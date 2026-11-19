//! JSON-RPC 2.0 over stdio: line framing, parsing, and the response envelopes.
//!
//! Stdout carries protocol messages and nothing else. Lines are read on their own thread, so
//! the server keeps answering pings and cancellations while a tool runs.

use serde_json::{json, Value};
use std::io::{self, BufRead, Write};
use std::sync::mpsc::Sender;

/// The longest message read. A longer line is refused without being parsed.
pub const MAX_LINE: usize = 1024 * 1024;

pub const PARSE_ERROR: i64 = -32700;
pub const INVALID_REQUEST: i64 = -32600;
pub const METHOD_NOT_FOUND: i64 = -32601;
pub const INVALID_PARAMS: i64 = -32602;
/// The newest revision's code for a version the server does not serve.
pub const UNSUPPORTED_VERSION: i64 = -32022;
/// The legacy code for an unknown resource. The newest revision uses `INVALID_PARAMS`.
pub const LEGACY_RESOURCE_NOT_FOUND: i64 = -32002;

/// A protocol-level failure. It becomes a JSON-RPC error response.
#[derive(Debug)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
    pub data: Option<Value>,
}

impl RpcError {
    pub fn invalid(message: impl Into<String>) -> RpcError {
        RpcError {
            code: INVALID_PARAMS,
            message: message.into(),
            data: None,
        }
    }
}

/// What the reader thread hands the server.
pub enum Inbound {
    Line(Vec<u8>),
    TooLong,
    Eof,
}

/// Read stdin one line at a time until it ends, then send `Eof`.
pub fn read_lines<R: BufRead>(mut input: R, tx: Sender<Inbound>) {
    loop {
        match read_one(&mut input) {
            Ok(Some(item)) => {
                if tx.send(item).is_err() {
                    return;
                }
            }
            Ok(None) | Err(_) => {
                let _ = tx.send(Inbound::Eof);
                return;
            }
        }
    }
}

/// One line, without its terminator. A line over `MAX_LINE` is consumed to its end and
/// reported as `TooLong`, so the stream stays in step.
fn read_one<R: BufRead>(input: &mut R) -> io::Result<Option<Inbound>> {
    let mut line = Vec::new();
    let mut too_long = false;
    let mut seen_any = false;
    loop {
        let available = input.fill_buf()?;
        if available.is_empty() {
            if !seen_any {
                return Ok(None);
            }
            break;
        }
        seen_any = true;
        let (take, finished) = match available.iter().position(|&b| b == b'\n') {
            Some(at) => (at, true),
            None => (available.len(), false),
        };
        if !too_long {
            if line.len() + take > MAX_LINE {
                too_long = true;
                line = Vec::new();
            } else {
                line.extend_from_slice(&available[..take]);
            }
        }
        let used = if finished { take + 1 } else { take };
        input.consume(used);
        if finished {
            break;
        }
    }
    if too_long {
        return Ok(Some(Inbound::TooLong));
    }
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    Ok(Some(Inbound::Line(line)))
}

/// One line, classified.
pub enum Parsed {
    Request {
        id: Value,
        method: String,
        params: Value,
    },
    Notification {
        method: String,
        params: Value,
    },
    /// A reply to a request this server never sends. Nothing to do.
    Reply,
    /// Answer with this error. `id` echoes the request's id when it had a valid one.
    Invalid {
        id: Value,
        code: i64,
        message: String,
    },
    Blank,
}

/// A request id is a string or an integer. Null, fractions and everything else are refused.
pub fn valid_id(id: &Value) -> bool {
    id.is_string() || id.is_i64() || id.is_u64()
}

pub fn parse(line: &[u8]) -> Parsed {
    if line.iter().all(u8::is_ascii_whitespace) {
        return Parsed::Blank;
    }
    if std::str::from_utf8(line).is_err() {
        return invalid(Value::Null, PARSE_ERROR, "message is not valid UTF-8");
    }
    let value: Value = match serde_json::from_slice(line) {
        Ok(value) => value,
        Err(e) => return invalid(Value::Null, PARSE_ERROR, format!("parse error: {e}")),
    };
    let Value::Object(mut map) = value else {
        return invalid(
            Value::Null,
            INVALID_REQUEST,
            "not a JSON-RPC message (batches are not supported)",
        );
    };
    let id = map.remove("id");
    let echo = match &id {
        Some(id) if valid_id(id) => id.clone(),
        _ => Value::Null,
    };
    if map.remove("jsonrpc") != Some(json!("2.0")) {
        return invalid(echo, INVALID_REQUEST, "jsonrpc must be \"2.0\"");
    }
    let method = map.remove("method");
    let params = match map.remove("params") {
        None | Some(Value::Null) => json!({}),
        Some(params) => params,
    };
    match (method, id) {
        (Some(Value::String(method)), Some(id)) if valid_id(&id) => {
            Parsed::Request { id, method, params }
        }
        (Some(Value::String(_)), Some(_)) => invalid(
            Value::Null,
            INVALID_REQUEST,
            "request id must be a string or an integer",
        ),
        (Some(Value::String(method)), None) => Parsed::Notification { method, params },
        (Some(_), _) => invalid(echo, INVALID_REQUEST, "method must be a string"),
        (None, Some(_)) => Parsed::Reply,
        (None, None) => invalid(
            Value::Null,
            INVALID_REQUEST,
            "missing method (not a request or notification)",
        ),
    }
}

fn invalid(id: Value, code: i64, message: impl Into<String>) -> Parsed {
    Parsed::Invalid {
        id,
        code,
        message: message.into(),
    }
}

pub fn result_response(id: Value, body: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": body})
}

pub fn error_response(id: Value, error: RpcError) -> Value {
    let mut body = json!({"code": error.code, "message": error.message});
    if let Some(data) = error.data {
        body["data"] = data;
    }
    json!({"jsonrpc": "2.0", "id": id, "error": body})
}

/// One message, as a single line.
pub fn write_message<W: Write>(out: &mut W, message: &Value) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(message).map_err(io::Error::other)?;
    bytes.push(b'\n');
    out.write_all(&bytes)?;
    out.flush()
}

/// Text content for a structured result. It is the same JSON, with the sequences that GitHub
/// workflow commands act on written as JSON escapes, so the text cannot start one. The plan
/// command's JSON output does the same.
pub fn json_text(value: &Value) -> String {
    let json = serde_json::to_string(value).unwrap_or_else(|_| "null".into());
    let json = json
        .replace("##[", "#\\u0023[")
        .replace("::", "\\u003a\\u003a");
    json.chars()
        .map(|ch| {
            if is_bidi(ch) {
                format!("\\u{:04x}", ch as u32)
            } else {
                ch.to_string()
            }
        })
        .collect()
}

/// Bidirectional formatting characters reorder the text after them on screen.
fn is_bidi(ch: char) -> bool {
    matches!(
        ch,
        '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_text_never_contains_a_workflow_command_sequence() {
        let text = json_text(&json!({"a": "x\n::error::y##[add-mask]\u{202e}"}));
        assert!(!text.contains('\n') && !text.contains("::") && !text.contains("##["));
        let back: Value = serde_json::from_str(&text).expect("still JSON");
        assert_eq!(back["a"], "x\n::error::y##[add-mask]\u{202e}");
    }

    #[test]
    fn a_line_over_the_cap_is_reported_and_the_next_line_is_read() {
        let long = vec![b'a'; MAX_LINE + 10];
        let mut input = Vec::new();
        input.extend_from_slice(&long);
        input.extend_from_slice(b"\nnext\n");
        let mut reader = io::BufReader::new(&input[..]);
        assert!(matches!(
            read_one(&mut reader).unwrap(),
            Some(Inbound::TooLong)
        ));
        match read_one(&mut reader).unwrap() {
            Some(Inbound::Line(bytes)) => assert_eq!(bytes, b"next"),
            _ => panic!("the line after an oversized one is read"),
        }
    }
}
