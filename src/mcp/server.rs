//! The server: one request at a time, while stdin is still read, so a ping or a cancellation
//! is seen during a long tool call.
//!
//! Two eras are served. The newest revision (2026-07-28) is stateless: each request names its
//! protocol version and capabilities in `_meta`, and its results carry `resultType`. The legacy
//! revisions (2025-11-25, 2025-06-18) negotiate once, with `initialize`, and their results carry
//! no `resultType`. Both are answered by the same code.

use super::content;
use super::tools::{self, Outcome};
use super::wire::{self, Inbound, Parsed, RpcError, INVALID_PARAMS, METHOD_NOT_FOUND};
use crate::plan;
use serde_json::{json, Map, Value};
use std::collections::VecDeque;
use std::io::{self, BufReader, Read, Write};
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, TryRecvError};

/// The newest revision. Its requests carry the version in `_meta`.
pub const MODERN: &str = "2026-07-28";
/// Every revision this server answers, newest first.
pub const SUPPORTED: [&str; 3] = [MODERN, "2025-11-25", "2025-06-18"];
/// The revisions a legacy `initialize` can negotiate, newest first.
const LEGACY: [&str; 2] = ["2025-11-25", "2025-06-18"];
const VERSION_KEY: &str = "io.modelcontextprotocol/protocolVersion";
const CAPABILITIES_KEY: &str = "io.modelcontextprotocol/clientCapabilities";
const INSTRUCTIONS: &str = "stoop skips a command whose recorded inputs have not changed. Read the guide first (the guide tool or stoop://guide). Use explain before run: it reports what would run and never executes anything.";
const METHODS: [&str; 9] = [
    "initialize",
    "server/discover",
    "ping",
    "tools/list",
    "tools/call",
    "resources/list",
    "resources/read",
    "prompts/list",
    "prompts/get",
];

pub struct Config {
    pub root: PathBuf,
    pub allow_run: bool,
}

/// Which revision's rules a request is answered under.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Era {
    Modern,
    Legacy,
}

/// Messages in and out, and the ones held back while a tool call runs.
pub struct Io<W: Write> {
    out: W,
    inbox: Receiver<Inbound>,
    deferred: VecDeque<Inbound>,
    /// The first write failure. The server stops when it sees one.
    failed: Option<io::Error>,
}

impl<W: Write> Io<W> {
    fn send(&mut self, message: &Value) -> io::Result<()> {
        wire::write_message(&mut self.out, message)
    }

    /// The next message to handle, from the held-back queue first, else stdin. `None` at the end.
    fn next(&mut self) -> Option<Inbound> {
        self.deferred.pop_front().or_else(|| self.inbox.recv().ok())
    }

    /// Called while a tool call runs. Answers pings now, drops queued requests that were
    /// cancelled, holds everything else back. Returns true when `call` itself was cancelled,
    /// or when a write failed (the work stops, and `run` reports the failure).
    pub fn poll_cancelled(&mut self, call: &Value) -> bool {
        let mut cancelled = self.failed.is_some();
        loop {
            let item = match self.inbox.try_recv() {
                Ok(item) => item,
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    self.deferred.push_back(Inbound::Eof);
                    break;
                }
            };
            let parsed = match &item {
                Inbound::Line(bytes) => wire::parse(bytes),
                _ => {
                    self.deferred.push_back(item);
                    continue;
                }
            };
            match parsed {
                Parsed::Request { id, method, params } if method == "ping" => {
                    let answer = wire::result_response(id, shape(era_hint(&params), json!({})));
                    if let Err(e) = self.send(&answer) {
                        self.failed = Some(e);
                        cancelled = true;
                    }
                }
                Parsed::Notification { method, params } if method == "notifications/cancelled" => {
                    match params.get("requestId") {
                        Some(target) if target == call => cancelled = true,
                        Some(target) => self
                            .deferred
                            .retain(|queued| !is_request_with_id(queued, target)),
                        None => {}
                    }
                }
                _ => self.deferred.push_back(item),
            }
        }
        cancelled
    }
}

fn is_request_with_id(item: &Inbound, id: &Value) -> bool {
    match item {
        Inbound::Line(bytes) => {
            matches!(wire::parse(bytes), Parsed::Request { id: ref found, .. } if found == id)
        }
        _ => false,
    }
}

pub struct Server<W: Write> {
    cfg: Config,
    io: Io<W>,
    /// Set by `initialize`: the legacy revision this process negotiated.
    negotiated: Option<&'static str>,
}

/// Serve until stdin ends. Returns the exit status.
pub fn serve<R, W>(cfg: Config, input: R, output: W) -> i32
where
    R: Read + Send + 'static,
    W: Write,
{
    let (tx, rx) = channel();
    std::thread::spawn(move || wire::read_lines(BufReader::new(input), tx));
    let mut server = Server {
        cfg,
        io: Io {
            out: output,
            inbox: rx,
            deferred: VecDeque::new(),
            failed: None,
        },
        negotiated: None,
    };
    match server.run() {
        Ok(()) => 0,
        Err(e) => {
            eprintln!(
                "stoop mcp: cannot write to the client: {}",
                plan::output::escape(&e.to_string())
            );
            1
        }
    }
}

impl<W: Write> Server<W> {
    fn run(&mut self) -> io::Result<()> {
        while let Some(item) = self.io.next() {
            match item {
                Inbound::Eof => break,
                Inbound::TooLong => self.io.send(&wire::error_response(
                    Value::Null,
                    RpcError {
                        code: wire::INVALID_REQUEST,
                        message: format!(
                            "message is longer than {} bytes and was not read",
                            wire::MAX_LINE
                        ),
                        data: None,
                    },
                ))?,
                Inbound::Line(bytes) => self.line(&bytes)?,
            }
            if let Some(e) = self.io.failed.take() {
                return Err(e);
            }
        }
        Ok(())
    }

    fn line(&mut self, bytes: &[u8]) -> io::Result<()> {
        let answer = match wire::parse(bytes) {
            Parsed::Blank | Parsed::Reply | Parsed::Notification { .. } => None,
            Parsed::Invalid { id, code, message } => Some(wire::error_response(
                id,
                RpcError {
                    code,
                    message,
                    data: None,
                },
            )),
            Parsed::Request { id, method, params } => self.request(&id, &method, &params)?,
        };
        match answer {
            Some(answer) => self.io.send(&answer),
            None => Ok(()),
        }
    }

    /// Answer one request. `None` means no reply: the call was cancelled.
    fn request(&mut self, id: &Value, method: &str, params: &Value) -> io::Result<Option<Value>> {
        if !METHODS.contains(&method) {
            return Ok(Some(fail(
                id,
                RpcError {
                    code: METHOD_NOT_FOUND,
                    message: format!("method not found: {}", plan::output::escape(method)),
                    data: None,
                },
            )));
        }
        if method == "initialize" {
            return Ok(Some(respond(id, Era::Legacy, self.initialize(params))));
        }
        let bare_ok = matches!(method, "ping" | "server/discover");
        let era = match negotiate(params, bare_ok, self.negotiated.is_some()) {
            Ok(era) => era,
            Err(error) => return Ok(Some(fail(id, error))),
        };
        let body = match method {
            "ping" => Ok(json!({})),
            "server/discover" => Ok(discover()),
            "tools/list" => Ok(json!({"tools": tools::list(self.cfg.allow_run)})),
            "tools/call" => return self.call_tool(id, era, params),
            "resources/list" => Ok(content::resources_list()),
            "resources/read" => content::read_resource(&self.cfg.root, params, era == Era::Legacy),
            "prompts/list" => Ok(content::prompts_list()),
            "prompts/get" => content::get_prompt(params),
            _ => unreachable!("every method in METHODS is handled above"),
        };
        Ok(Some(respond(id, era, body)))
    }

    /// `initialize`: pick the revision for this process. An unknown or newest version is answered
    /// with the latest legacy one, which the client may accept or refuse.
    fn initialize(&mut self, params: &Value) -> Result<Value, RpcError> {
        let requested = params
            .get("protocolVersion")
            .and_then(Value::as_str)
            .ok_or_else(|| RpcError::invalid("initialize needs protocolVersion"))?;
        let version = LEGACY
            .iter()
            .copied()
            .find(|candidate| *candidate == requested)
            .unwrap_or(LEGACY[0]);
        self.negotiated = Some(version);
        Ok(json!({
            "protocolVersion": version,
            "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
            "serverInfo": server_info(),
            "instructions": INSTRUCTIONS
        }))
    }

    fn call_tool(&mut self, id: &Value, era: Era, params: &Value) -> io::Result<Option<Value>> {
        let Some(params) = params.as_object() else {
            return Ok(Some(fail(
                id,
                RpcError::invalid("tools/call params must be an object"),
            )));
        };
        let Some(name) = params.get("name").and_then(Value::as_str) else {
            return Ok(Some(fail(
                id,
                RpcError::invalid("tools/call needs a tool name"),
            )));
        };
        let arguments: Map<String, Value> = match params.get("arguments") {
            None | Some(Value::Null) => Map::new(),
            Some(Value::Object(map)) => map.clone(),
            Some(_) => {
                return Ok(Some(fail(
                    id,
                    RpcError::invalid("tools/call arguments must be an object"),
                )))
            }
        };
        match tools::call(
            &self.cfg.root,
            self.cfg.allow_run,
            &mut self.io,
            id,
            name,
            &arguments,
        ) {
            Ok(Outcome::Done(body)) => {
                if let Some(e) = self.io.failed.take() {
                    return Err(e);
                }
                Ok(Some(respond(id, era, Ok(body))))
            }
            Ok(Outcome::Cancelled) => match self.io.failed.take() {
                Some(e) => Err(e),
                None => Ok(None),
            },
            Err(error) => Ok(Some(fail(id, error))),
        }
    }
}

/// The era a request is answered under. A request names its revision in `_meta`. Without one,
/// it is served only if the process has negotiated a legacy revision, or if it is a bare probe
/// (`ping`, `server/discover`) that any client may send first.
fn negotiate(params: &Value, bare_ok: bool, initialized: bool) -> Result<Era, RpcError> {
    let meta = params.get("_meta");
    match meta.and_then(|m| m.get(VERSION_KEY)) {
        Some(Value::String(version)) => {
            if !SUPPORTED.contains(&version.as_str()) {
                return Err(RpcError {
                    code: wire::UNSUPPORTED_VERSION,
                    message: "Unsupported protocol version".into(),
                    data: Some(json!({"supported": SUPPORTED, "requested": version})),
                });
            }
            if version == MODERN {
                let has_capabilities = meta
                    .and_then(|m| m.get(CAPABILITIES_KEY))
                    .is_some_and(Value::is_object);
                if !has_capabilities {
                    return Err(RpcError::invalid(format!(
                        "every {MODERN} request carries {CAPABILITIES_KEY} in _meta"
                    )));
                }
                Ok(Era::Modern)
            } else {
                Ok(Era::Legacy)
            }
        }
        Some(_) => Err(RpcError::invalid(format!(
            "_meta {VERSION_KEY} must be a string"
        ))),
        None if bare_ok || initialized => Ok(Era::Legacy),
        None => Err(RpcError {
            code: INVALID_PARAMS,
            message: format!(
                "no protocol version: send initialize first, or put {VERSION_KEY} in _meta"
            ),
            data: Some(json!({"supported": SUPPORTED})),
        }),
    }
}

/// The era a bare ping's `_meta` names, for shaping its answer. Nothing is refused here.
fn era_hint(params: &Value) -> Era {
    match params
        .get("_meta")
        .and_then(|m| m.get(VERSION_KEY))
        .and_then(Value::as_str)
    {
        Some(MODERN) => Era::Modern,
        _ => Era::Legacy,
    }
}

fn server_info() -> Value {
    json!({"name": "stoop", "version": env!("CARGO_PKG_VERSION")})
}

fn discover() -> Value {
    json!({
        "supportedVersions": SUPPORTED,
        "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
        "_meta": {"io.modelcontextprotocol/serverInfo": server_info()},
        "instructions": INSTRUCTIONS
    })
}

/// A modern result says it is complete and names the server. A legacy result is unchanged.
fn shape(era: Era, mut body: Value) -> Value {
    if era == Era::Modern {
        if let Some(map) = body.as_object_mut() {
            map.entry("resultType").or_insert(json!("complete"));
            map.entry("_meta")
                .or_insert_with(|| json!({"io.modelcontextprotocol/serverInfo": server_info()}));
        }
    }
    body
}

fn respond(id: &Value, era: Era, body: Result<Value, RpcError>) -> Value {
    match body {
        Ok(body) => wire::result_response(id.clone(), shape(era, body)),
        Err(error) => fail(id, error),
    }
}

fn fail(id: &Value, error: RpcError) -> Value {
    wire::error_response(id.clone(), error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_modern_request_needs_capabilities() {
        let params = json!({"_meta": {VERSION_KEY: MODERN}});
        assert!(negotiate(&params, false, false).is_err());
        let params = json!({"_meta": {VERSION_KEY: MODERN, CAPABILITIES_KEY: {}}});
        assert_eq!(negotiate(&params, false, false).unwrap(), Era::Modern);
    }

    #[test]
    fn a_legacy_session_serves_requests_without_meta() {
        assert!(negotiate(&json!({}), false, false).is_err());
        assert_eq!(negotiate(&json!({}), false, true).unwrap(), Era::Legacy);
        assert_eq!(negotiate(&json!({}), true, false).unwrap(), Era::Legacy);
    }

    #[test]
    fn the_result_shape_follows_the_era() {
        assert_eq!(
            shape(Era::Legacy, json!({"a": 1}))["resultType"],
            Value::Null
        );
        let modern = shape(Era::Modern, json!({"a": 1}));
        assert_eq!(modern["resultType"], "complete");
        assert_eq!(
            modern["_meta"]["io.modelcontextprotocol/serverInfo"]["name"],
            "stoop"
        );
    }
}
