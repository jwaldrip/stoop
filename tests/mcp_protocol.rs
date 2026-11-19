#![cfg(unix)]
//! The MCP wire protocol, end to end: the real `stoop mcp` binary, scripted over stdio.
//! Nothing here depends on tracing, so these run on every platform.

mod common;

use common::*;
use serde_json::{json, Value};
use std::fs;
use std::time::{Duration, Instant};

const PING_WAIT: Duration = Duration::from_secs(10);

fn tool_names(list: &Value) -> Vec<String> {
    list["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn initialize_echoes_a_supported_legacy_version() {
    let dir = temp_dir("proto-init-echo");
    let mut m = Mcp::spawn(&[], &dir);
    let r = m.call(
        json!(1),
        "initialize",
        json!({"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}),
    );
    let res = result(&r);
    assert_eq!(res["protocolVersion"], "2025-06-18");
    assert!(res["capabilities"]["tools"].is_object());
    assert!(res["capabilities"]["resources"].is_object());
    assert!(res["capabilities"]["prompts"].is_object());
    assert_eq!(res["serverInfo"]["name"], "stoop");
    assert!(res["serverInfo"]["version"].is_string());
    assert!(
        res.get("resultType").is_none(),
        "legacy results carry no resultType"
    );
    let (code, lines) = m.finish();
    assert_eq!(code, Some(0));
    assert_protocol_only(&lines);
}

#[test]
fn initialize_answers_the_latest_legacy_version_when_the_request_is_unsupported() {
    let dir = temp_dir("proto-init-unknown");
    let mut m = Mcp::spawn(&[], &dir);
    let r = m.call(
        json!(1),
        "initialize",
        json!({"protocolVersion": "1900-01-01", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}),
    );
    assert_eq!(result(&r)["protocolVersion"], "2025-11-25");
    m.finish();
}

#[test]
fn initialize_with_the_modern_version_is_answered_with_the_legacy_handshake_version() {
    // A handshake selects legacy semantics for this process; the modern version is per request.
    let dir = temp_dir("proto-init-modern");
    let mut m = Mcp::spawn(&[], &dir);
    let r = m.call(json!(1), "initialize", json!({"protocolVersion": MODERN, "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}));
    assert_eq!(result(&r)["protocolVersion"], "2025-11-25");
    m.finish();
}

#[test]
fn initialize_then_initialized_then_tools_list_needs_no_meta() {
    let dir = temp_dir("proto-legacy-session");
    let mut m = Mcp::spawn(&[], &dir);
    m.call(json!(1), "initialize", json!({"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}));
    m.notify("notifications/initialized", json!({}));
    let list = m.call(json!(2), "tools/list", json!({}));
    assert_eq!(
        tool_names(result(&list)),
        ["explain", "list_proofs", "plan", "forget", "guide"]
    );
    assert!(result(&list).get("resultType").is_none());
    m.finish();
}

#[test]
fn server_discover_answers_a_modern_probe_with_versions_and_identity() {
    let dir = temp_dir("proto-discover");
    let mut m = Mcp::spawn(&[], &dir);
    let r = m.call(json!("discover-1"), "server/discover", modern(json!({})));
    let res = result(&r);
    assert_eq!(res["resultType"], "complete");
    let versions: Vec<&str> = res["supportedVersions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(versions.contains(&MODERN), "{versions:?}");
    assert!(versions.contains(&"2025-11-25"), "{versions:?}");
    assert_eq!(
        res["_meta"]["io.modelcontextprotocol/serverInfo"]["name"],
        "stoop"
    );
    assert!(res["capabilities"]["tools"].is_object());
    assert!(res["instructions"].as_str().unwrap().contains("guide"));
    m.finish();
}

#[test]
fn server_discover_without_meta_still_answers_for_probes() {
    let dir = temp_dir("proto-discover-bare");
    let mut m = Mcp::spawn(&[], &dir);
    let r = m.call(json!(1), "server/discover", json!({}));
    assert!(result(&r)["supportedVersions"].is_array());
    m.finish();
}

#[test]
fn modern_requests_are_answered_statelessly_with_result_type_and_server_meta() {
    let dir = temp_dir("proto-modern-stateless");
    let mut m = Mcp::spawn(&[], &dir);
    // No initialize at all: each request names its own version.
    let list = m.call(json!(1), "tools/list", modern(json!({})));
    let res = result(&list);
    assert_eq!(res["resultType"], "complete");
    assert_eq!(
        tool_names(res),
        ["explain", "list_proofs", "plan", "forget", "guide"]
    );
    assert_eq!(
        res["_meta"]["io.modelcontextprotocol/serverInfo"]["name"],
        "stoop"
    );
    let ping = m.call(json!(2), "ping", modern(json!({})));
    assert_eq!(result(&ping)["resultType"], "complete");
    m.finish();
}

#[test]
fn an_unsupported_request_version_gets_unsupported_protocol_version_with_the_supported_list() {
    let dir = temp_dir("proto-unsupported");
    let mut m = Mcp::spawn(&[], &dir);
    let mut params = json!({});
    params["_meta"] = json!({
        "io.modelcontextprotocol/protocolVersion": "1900-01-01",
        "io.modelcontextprotocol/clientCapabilities": {}
    });
    let r = m.call(json!(1), "tools/list", params);
    assert_eq!(error_code(&r), -32022, "{r}");
    let data = &r["error"]["data"];
    assert_eq!(data["requested"], "1900-01-01");
    let supported: Vec<&str> = data["supported"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(supported.contains(&MODERN), "{supported:?}");
    m.finish();
}

#[test]
fn a_modern_request_without_client_capabilities_is_invalid_params() {
    let dir = temp_dir("proto-missing-caps");
    let mut m = Mcp::spawn(&[], &dir);
    let r = m.call(
        json!(1),
        "tools/list",
        json!({"_meta": {"io.modelcontextprotocol/protocolVersion": MODERN}}),
    );
    assert_eq!(error_code(&r), -32602, "{r}");
    m.finish();
}

#[test]
fn a_request_with_neither_meta_nor_a_handshake_is_invalid_params_that_names_the_fix() {
    let dir = temp_dir("proto-no-session");
    let mut m = Mcp::spawn(&[], &dir);
    let r = m.call(json!(1), "tools/list", json!({}));
    assert_eq!(error_code(&r), -32602, "{r}");
    let message = r["error"]["message"].as_str().unwrap();
    assert!(
        message.contains("initialize") && message.contains("protocolVersion"),
        "{message}"
    );
    assert!(r["error"]["data"]["supported"].is_array());
    m.finish();
}

#[test]
fn unknown_methods_are_method_not_found_in_every_era() {
    let dir = temp_dir("proto-method");
    let mut m = Mcp::spawn(&[], &dir);
    let bare = m.call(json!(1), "no/such/method", json!({}));
    assert_eq!(error_code(&bare), -32601);
    let modern_call = m.call(json!(2), "no/such/method", modern(json!({})));
    assert_eq!(error_code(&modern_call), -32601);
    // Methods this server does not offer (logging, subscriptions, completion) are not found.
    let logging = m.call(
        json!(3),
        "logging/setLevel",
        modern(json!({"level": "debug"})),
    );
    assert_eq!(error_code(&logging), -32601);
    m.finish();
}

#[test]
fn malformed_json_is_a_parse_error_with_a_null_id_and_the_server_keeps_going() {
    let dir = temp_dir("proto-parse");
    let mut m = Mcp::spawn(&[], &dir);
    m.send_raw(b"{not json");
    let r = m.next_message(PING_WAIT).expect("a parse error");
    assert_eq!(error_code(&r), -32700);
    assert!(r["id"].is_null());
    let ping = m.call(json!(1), "ping", json!({}));
    assert!(result(&ping).is_object());
    m.finish();
}

#[test]
fn invalid_utf8_is_a_parse_error() {
    let dir = temp_dir("proto-utf8");
    let mut m = Mcp::spawn(&[], &dir);
    m.send_raw(&[b'{', b'"', 0xff, b'"', b':', b'1', b'}']);
    let r = m.next_message(PING_WAIT).expect("a parse error");
    assert_eq!(error_code(&r), -32700);
    m.finish();
}

#[test]
fn json_rpc_batches_are_rejected_because_the_revision_removed_them() {
    let dir = temp_dir("proto-batch");
    let mut m = Mcp::spawn(&[], &dir);
    m.send_raw(br#"[{"jsonrpc":"2.0","id":1,"method":"ping"}]"#);
    let r = m.next_message(PING_WAIT).expect("an error");
    assert_eq!(error_code(&r), -32600);
    assert!(r["id"].is_null());
    m.finish();
}

#[test]
fn an_oversized_line_is_rejected_without_crashing() {
    let dir = temp_dir("proto-oversized");
    let mut m = Mcp::spawn(&[], &dir);
    // Valid JSON, a ping, but over the 1 MiB line limit: it must not be answered as a ping.
    let pad = "a".repeat(1_100_000);
    let line = format!(r#"{{"jsonrpc":"2.0","id":5,"method":"ping","params":{{"pad":"{pad}"}}}}"#);
    m.send_raw(line.as_bytes());
    let r = m
        .next_message(Duration::from_secs(30))
        .expect("an error for the oversized line");
    assert_eq!(error_code(&r), -32600, "{r}");
    assert!(r["id"].is_null());
    let ping = m.call(json!(6), "ping", json!({}));
    assert!(result(&ping).is_object());
    m.finish();
}

#[test]
fn request_ids_are_echoed_as_sent_and_invalid_ids_are_rejected() {
    let dir = temp_dir("proto-ids");
    let mut m = Mcp::spawn(&[], &dir);
    let number = m.call(json!(7), "ping", json!({}));
    assert_eq!(number["id"], json!(7));
    let string = m.call(json!("seven"), "ping", json!({}));
    assert_eq!(string["id"], json!("seven"));
    m.send_raw(br#"{"jsonrpc":"2.0","id":null,"method":"ping"}"#);
    let null_id = m.next_message(PING_WAIT).expect("an error for a null id");
    assert_eq!(error_code(&null_id), -32600);
    m.send_raw(br#"{"jsonrpc":"2.0","id":1.5,"method":"ping"}"#);
    let float_id = m
        .next_message(PING_WAIT)
        .expect("an error for a fractional id");
    assert_eq!(error_code(&float_id), -32600);
    assert!(float_id["id"].is_null());
    m.finish();
}

#[test]
fn error_responses_echo_the_request_id() {
    let dir = temp_dir("proto-error-id");
    let mut m = Mcp::spawn(&[], &dir);
    let r = m.call(json!("unknown-1"), "no/such/method", json!({}));
    assert_eq!(r["id"], json!("unknown-1"));
    assert_eq!(error_code(&r), -32601);
    m.finish();
}

#[test]
fn notifications_never_get_a_response() {
    let dir = temp_dir("proto-notify");
    let mut m = Mcp::spawn(&[], &dir);
    m.notify("notifications/initialized", json!({}));
    m.notify(
        "notifications/cancelled",
        json!({"requestId": 404, "reason": "unknown"}),
    );
    m.notify("notifications/made-up", json!({"x": 1}));
    let ping = m.call(json!(1), "ping", json!({}));
    assert!(result(&ping).is_object());
    // Nothing else was written: the first and only line is the ping's response.
    assert_eq!(m.seen.len(), 1, "notifications were answered: {:?}", m.seen);
    m.finish();
}

#[test]
fn stdin_end_of_file_exits_cleanly_with_status_zero() {
    let dir = temp_dir("proto-eof");
    let m = Mcp::spawn(&[], &dir);
    let (code, lines) = m.finish();
    assert_eq!(code, Some(0));
    assert!(lines.is_empty());
}

#[test]
fn every_stdout_line_is_a_protocol_message() {
    let dir = temp_dir("proto-clean");
    let mut m = Mcp::spawn(&["--allow-run"], &dir);
    m.call(json!(1), "initialize", json!({"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}));
    m.notify("notifications/initialized", json!({}));
    m.call(json!(2), "tools/list", json!({}));
    m.call(json!(3), "resources/list", json!({}));
    m.call(json!(4), "prompts/list", json!({}));
    m.call(
        json!(5),
        "tools/call",
        tool_call("explain", json!({"argv": ["true"]})),
    );
    let (code, lines) = m.finish();
    assert_eq!(code, Some(0));
    let messages = assert_protocol_only(&lines);
    assert!(messages.len() >= 5);
}

#[test]
fn a_ping_is_answered_while_a_run_is_in_flight_and_cancel_stops_it() {
    let dir = temp_dir("proto-cancel");
    let mut m = Mcp::spawn(&["--allow-run"], &dir);
    let started = Instant::now();
    m.send(&json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": modern(tool_call("run", json!({"argv": ["sleep", "30"], "timeout_s": 60})))
    }));
    std::thread::sleep(Duration::from_millis(300));
    m.send(&json!({"jsonrpc": "2.0", "id": 3, "method": "ping"}));
    let pong = m
        .next_message(PING_WAIT)
        .expect("a ping answer during the run");
    assert_eq!(pong["id"], json!(3), "{pong}");
    m.notify(
        "notifications/cancelled",
        json!({"requestId": 2, "reason": "test"}),
    );
    let after = m.call(json!(4), "ping", json!({}));
    assert_eq!(after["id"], json!(4));
    let (code, lines) = m.finish();
    assert_eq!(code, Some(0));
    assert!(
        started.elapsed() < Duration::from_secs(25),
        "the cancelled sleep kept running"
    );
    let messages = assert_protocol_only(&lines);
    assert!(
        !messages.iter().any(|m| m["id"] == json!(2)),
        "a cancelled request got a response: {lines:?}"
    );
}

#[test]
fn child_output_is_captured_and_never_forwarded_to_the_protocol_stream() {
    let dir = temp_dir("proto-garbage");
    let mut m = Mcp::spawn(&["--allow-run"], &dir);
    let script = r#"echo GARBAGE; printf '{"jsonrpc":"2.0","id":99,"result":{}}\n'"#;
    let r = m.call(
        json!(2),
        "tools/call",
        modern(tool_call("run", json!({"argv": ["sh", "-c", script]}))),
    );
    let sc = &result(&r)["structuredContent"];
    assert_eq!(sc["exit_code"], 0);
    let stdout = sc["stdout"]["text"].as_str().unwrap();
    assert!(
        stdout.contains("GARBAGE") && stdout.contains("\"id\":99"),
        "{stdout}"
    );
    let (code, lines) = m.finish();
    assert_eq!(code, Some(0));
    assert!(
        !lines.iter().any(|l| l == "GARBAGE"),
        "child output reached stdout: {lines:?}"
    );
    let messages = assert_protocol_only(&lines);
    assert!(!messages.iter().any(|m| m["id"] == json!(99)));
}

#[test]
fn unknown_resource_uri_uses_the_legacy_code_in_a_legacy_session_and_invalid_params_otherwise() {
    let dir = temp_dir("proto-resource-code");
    let mut m = Mcp::spawn(&[], &dir);
    m.call(json!(1), "initialize", json!({"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}));
    let legacy = m.call(json!(2), "resources/read", json!({"uri": "stoop://nope"}));
    assert_eq!(error_code(&legacy), -32002, "{legacy}");
    let modern_read = m.call(
        json!(3),
        "resources/read",
        modern(json!({"uri": "stoop://nope"})),
    );
    assert_eq!(error_code(&modern_read), -32602, "{modern_read}");
    m.finish();
}

#[test]
fn resources_list_and_read_serve_the_guide_the_docs_index_and_the_proofs() {
    let dir = temp_dir("proto-resources");
    let mut m = Mcp::spawn(&[], &dir);
    let list = m.call(json!(1), "resources/list", modern(json!({})));
    let uris: Vec<&str> = result(&list)["resources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["uri"].as_str().unwrap())
        .collect();
    for uri in ["stoop://guide", "stoop://proofs", "stoop://docs/index"] {
        assert!(uris.contains(&uri), "{uris:?}");
    }
    let guide = m.call(
        json!(2),
        "resources/read",
        modern(json!({"uri": "stoop://guide"})),
    );
    let text = result(&guide)["contents"][0]["text"].as_str().unwrap();
    assert!(text.starts_with('#'), "{}", &text[..text.len().min(80)]);
    assert_eq!(result(&guide)["contents"][0]["mimeType"], "text/markdown");
    let docs = m.call(
        json!(3),
        "resources/read",
        modern(json!({"uri": "stoop://docs/index"})),
    );
    assert!(result(&docs)["contents"][0]["text"]
        .as_str()
        .unwrap()
        .contains("https://stoop.build/docs/"));
    let proofs = m.call(
        json!(4),
        "resources/read",
        modern(json!({"uri": "stoop://proofs"})),
    );
    assert!(result(&proofs)["contents"][0]["text"]
        .as_str()
        .unwrap()
        .contains("\"proofs\""));
    m.finish();
}

#[test]
fn prompts_list_and_get_return_the_two_guided_prompts() {
    let dir = temp_dir("proto-prompts");
    let mut m = Mcp::spawn(&[], &dir);
    let list = m.call(json!(1), "prompts/list", modern(json!({})));
    let names: Vec<&str> = result(&list)["prompts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["wire-stoop-into-ci", "why-did-this-run"]);
    let ci = m.call(
        json!(2),
        "prompts/get",
        modern(json!({"name": "wire-stoop-into-ci"})),
    );
    assert_eq!(result(&ci)["messages"][0]["role"], "user");
    assert!(result(&ci)["messages"][0]["content"]["text"]
        .as_str()
        .unwrap()
        .contains("stoop sh"));
    let why = m.call(
        json!(3),
        "prompts/get",
        modern(json!({"name": "why-did-this-run", "arguments": {"key": "sh-abc123"}})),
    );
    assert!(result(&why)["messages"][0]["content"]["text"]
        .as_str()
        .unwrap()
        .contains("sh-abc123"));
    let unknown = m.call(json!(4), "prompts/get", modern(json!({"name": "nope"})));
    assert_eq!(error_code(&unknown), -32602);
    let bad_arg = m.call(
        json!(5),
        "prompts/get",
        modern(json!({"name": "why-did-this-run", "arguments": {"key": 3}})),
    );
    assert_eq!(error_code(&bad_arg), -32602);
    m.finish();
}

#[test]
fn run_is_not_listed_without_allow_run_and_a_direct_call_is_an_error() {
    let dir = temp_dir("proto-run-gate");
    let mut m = Mcp::spawn(&[], &dir);
    let list = m.call(json!(1), "tools/list", modern(json!({})));
    assert!(!tool_names(result(&list)).contains(&"run".to_string()));
    let direct = m.call(
        json!(2),
        "tools/call",
        modern(tool_call("run", json!({"argv": ["true"]}))),
    );
    assert_eq!(error_code(&direct), -32602, "{direct}");
    let (_, lines) = m.finish();
    assert!(!lines.is_empty());
}

#[test]
fn run_is_listed_with_allow_run_and_is_last() {
    let dir = temp_dir("proto-run-listed");
    let mut m = Mcp::spawn(&["--allow-run"], &dir);
    let list = m.call(json!(1), "tools/list", modern(json!({})));
    assert_eq!(
        tool_names(result(&list)),
        ["explain", "list_proofs", "plan", "forget", "guide", "run"]
    );
    m.finish();
}

#[test]
fn an_unknown_tool_name_is_invalid_params() {
    let dir = temp_dir("proto-unknown-tool");
    let mut m = Mcp::spawn(&[], &dir);
    let r = m.call(
        json!(1),
        "tools/call",
        modern(tool_call("no_such_tool", json!({}))),
    );
    assert_eq!(error_code(&r), -32602);
    assert!(r["error"]["message"]
        .as_str()
        .unwrap()
        .contains("no_such_tool"));
    m.finish();
}

#[test]
fn tool_arguments_that_are_not_an_object_are_invalid_params() {
    let dir = temp_dir("proto-args-type");
    let mut m = Mcp::spawn(&[], &dir);
    let r = m.call(
        json!(1),
        "tools/call",
        modern(json!({"name": "guide", "arguments": "topic"})),
    );
    assert_eq!(error_code(&r), -32602, "{r}");
    m.finish();
}

#[test]
fn tool_arguments_that_violate_the_schema_are_tool_errors_not_protocol_errors() {
    let dir = temp_dir("proto-schema-error");
    let mut m = Mcp::spawn(&[], &dir);
    let r = m.call(
        json!(1),
        "tools/call",
        modern(tool_call("explain", json!({}))),
    );
    assert_eq!(result(&r)["isError"], true, "{r}");
    assert!(text_of(result(&r)).contains("argv"));
    let extra = m.call(
        json!(2),
        "tools/call",
        modern(tool_call("guide", json!({"topic": 5}))),
    );
    assert_eq!(result(&extra)["isError"], true, "{extra}");
    m.finish();
}

#[test]
fn hostile_repository_text_stays_inert_in_text_content() {
    // A directory whose name carries workflow-command forms. explain echoes the directory it
    // decided in; the text content must not carry those forms, while the structured data keeps them.
    let dir = temp_dir("proto-hostile");
    let hostile = "sub\n::error::x##[add-mask]";
    fs::create_dir_all(dir.join(hostile)).unwrap();
    git(&dir, &["init", "-q"]);
    let mut m = Mcp::spawn(&[], &dir);
    let r = m.call(
        json!(1),
        "tools/call",
        modern(tool_call(
            "explain",
            json!({"argv": ["true"], "cwd": hostile}),
        )),
    );
    let res = result(&r);
    let text = text_of(res);
    assert!(!text.contains('\n'), "a raw newline reached text content");
    assert!(
        !text.contains("::"),
        "a workflow-command separator reached text content: {text}"
    );
    assert!(
        !text.contains("##["),
        "a workflow-command prefix reached text content: {text}"
    );
    // The data is still the data: the directory name is in the structured lines.
    let lines = res["structuredContent"]["lines"].to_string();
    assert!(lines.contains("error"), "{lines}");
    m.finish();
}

#[test]
fn a_cwd_outside_the_project_root_is_a_tool_error() {
    let dir = temp_dir("proto-escape");
    let mut m = Mcp::spawn(&[], &dir);
    let r = m.call(
        json!(1),
        "tools/call",
        modern(tool_call(
            "explain",
            json!({"argv": ["true"], "cwd": "../.."}),
        )),
    );
    assert_eq!(result(&r)["isError"], true, "{r}");
    assert!(
        text_of(result(&r)).contains("outside"),
        "{}",
        text_of(result(&r))
    );
    m.finish();
}

#[test]
fn ping_returns_an_empty_result_in_both_eras() {
    let dir = temp_dir("proto-ping");
    let mut m = Mcp::spawn(&[], &dir);
    let bare = m.call(json!(1), "ping", json!({}));
    assert_eq!(result(&bare), &json!({}));
    let modern_ping = m.call(json!(2), "ping", modern(json!({})));
    let modern_result = result(&modern_ping);
    assert_eq!(modern_result["resultType"], "complete");
    assert_eq!(
        modern_result["_meta"]["io.modelcontextprotocol/serverInfo"]["name"],
        "stoop"
    );
    m.finish();
}

#[test]
fn a_hostile_argument_echoed_by_run_stays_inert_in_text_content() {
    // The command prints its argument. The argument carries workflow-command forms: the text
    // content must not carry them, while the structured output keeps the exact bytes.
    let dir = temp_dir("proto-hostile-argv");
    let mut m = Mcp::spawn(&["--allow-run"], &dir);
    let hostile = "x\n::error::pwned ##[add-mask]";
    let r = m.call(
        json!(2),
        "tools/call",
        modern(tool_call(
            "run",
            json!({"argv": ["sh", "-c", "printf '%s\\n' \"$1\"", "sh", hostile]}),
        )),
    );
    let res = result(&r);
    let text = text_of(res);
    assert!(!text.contains('\n'), "a raw newline reached text content");
    assert!(!text.contains("::error"), "{text}");
    assert!(!text.contains("##["), "{text}");
    let out = res["structuredContent"]["stdout"]["text"].as_str().unwrap();
    assert!(out.contains("::error::pwned ##[add-mask]"), "{out}");
    m.finish();
}
