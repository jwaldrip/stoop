#!/usr/bin/env python3
"""An independent MCP client for `stoop mcp`, using only the standard library.

It shares no code with the Rust test harness, so it checks the server the way another client
would: the newest revision (per-request _meta), the legacy handshake, and the framing rules.

Usage: python3 tests/mcp_client.py path/to/stoop [workdir]
Exits 0 when every check passes.
"""

import json
import os
import subprocess
import sys
import tempfile

MODERN = "2026-07-28"
EXPECTED_TOOLS = ["explain", "list_proofs", "plan", "forget", "guide"]


def meta():
    return {
        "io.modelcontextprotocol/protocolVersion": MODERN,
        "io.modelcontextprotocol/clientInfo": {"name": "mcp_client.py", "version": "1"},
        "io.modelcontextprotocol/clientCapabilities": {},
    }


class Session:
    def __init__(self, binary, cwd, args=()):
        self.proc = subprocess.Popen(
            [binary, "mcp", *args],
            cwd=cwd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.lines = []  # every stdout line, verbatim
        self.pending = []  # messages read while waiting for another reply

    def send(self, message):
        self.proc.stdin.write((json.dumps(message) + "\n").encode("utf-8"))
        self.proc.stdin.flush()

    def send_raw(self, text):
        self.proc.stdin.write(text.encode("utf-8") + b"\n")
        self.proc.stdin.flush()

    def read(self):
        raw = self.proc.stdout.readline()
        if not raw:
            return None
        line = raw.decode("utf-8").rstrip("\n")
        self.lines.append(line)
        return json.loads(line)  # every stdout line must be one JSON message

    def call(self, request_id, method, params):
        self.send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
        while True:
            message = self.read()
            if message is None:
                raise AssertionError(f"server closed before answering {request_id!r}")
            if message.get("id") == request_id and ("result" in message or "error" in message):
                return message
            self.pending.append(message)

    def finish(self):
        self.proc.stdin.close()
        for raw in self.proc.stdout.read().decode("utf-8").splitlines():
            self.lines.append(raw)
            self.pending.append(json.loads(raw))
        return self.proc.wait(timeout=120)


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def tool_names(result):
    return [tool["name"] for tool in result["tools"]]


def modern_checks(binary, cwd):
    s = Session(binary, cwd)
    discover = s.call(1, "server/discover", {"_meta": meta()})
    check(discover["result"]["resultType"] == "complete", f"discover: {discover}")
    check(MODERN in discover["result"]["supportedVersions"], f"discover versions: {discover}")

    listed = s.call(2, "tools/list", {"_meta": meta()})
    check(tool_names(listed["result"]) == EXPECTED_TOOLS, f"tools/list: {listed}")

    unsupported = s.call(3, "tools/list", {"_meta": {**meta(), "io.modelcontextprotocol/protocolVersion": "1900-01-01"}})
    check(unsupported["error"]["code"] == -32022, f"unsupported version: {unsupported}")
    check(MODERN in unsupported["error"]["data"]["supported"], f"supported list: {unsupported}")

    guide = s.call(4, "tools/call", {"name": "guide", "arguments": {"topic": "reading-a-decision"}, "_meta": meta()})
    sections = guide["result"]["structuredContent"]["sections"]
    check(len(sections) == 1 and sections[0]["id"] == "reading-a-decision", f"guide topic: {guide}")
    check(guide["result"]["isError"] is False, f"guide is an error: {guide}")

    explain = s.call(5, "tools/call", {"name": "explain", "arguments": {"argv": ["true"]}, "_meta": meta()})
    check(explain["result"]["structuredContent"]["decision"] in ("run", "skip"), f"explain: {explain}")
    check(explain["result"]["content"][0]["type"] == "text", f"explain text mirror: {explain}")

    refused = s.call(6, "tools/call", {"name": "run", "arguments": {"argv": ["true"]}, "_meta": meta()})
    check(refused["error"]["code"] == -32602, f"run without --allow-run: {refused}")

    # Garbage the server must survive, and a notification it must not answer.
    s.send_raw("{not json")
    parse = s.read()
    check(parse["error"]["code"] == -32700 and parse["id"] is None, f"parse error: {parse}")
    s.send_raw('[{"jsonrpc":"2.0","id":1,"method":"ping"}]')
    batch = s.read()
    check(batch["error"]["code"] == -32600, f"batch: {batch}")
    s.send({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 99}})
    ping = s.call(7, "ping", {})
    check(ping["id"] == 7 and "result" in ping, f"ping: {ping}")
    check(not s.pending, f"unexpected messages: {s.pending}")

    code = s.finish()
    check(code == 0, f"exit status after end of input: {code}")
    for line in s.lines:
        json.loads(line)


def legacy_checks(binary, cwd):
    s = Session(binary, cwd)
    init = s.call(1, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "mcp_client.py", "version": "1"}})
    check(init["result"]["protocolVersion"] == "2025-06-18", f"initialize: {init}")
    check("resultType" not in init["result"], f"legacy result carries resultType: {init}")
    s.send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    listed = s.call(2, "tools/list", {})
    check(tool_names(listed["result"]) == EXPECTED_TOOLS, f"legacy tools/list: {listed}")

    missing = s.call(3, "resources/read", {"uri": "stoop://nope"})
    check(missing["error"]["code"] == -32002, f"legacy unknown resource: {missing}")

    proofs = s.call(4, "resources/read", {"uri": "stoop://proofs"})
    check(json.loads(proofs["result"]["contents"][0]["text"])["proofs"] == [], f"proofs: {proofs}")

    check(s.finish() == 0, "legacy session exit status")


def unknown_version_checks(binary, cwd):
    s = Session(binary, cwd)
    init = s.call(1, "initialize", {"protocolVersion": "1900-01-01", "capabilities": {}, "clientInfo": {"name": "mcp_client.py", "version": "1"}})
    check(init["result"]["protocolVersion"] == "2025-11-25", f"unknown version answer: {init}")
    check(s.finish() == 0, "unknown-version session exit status")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    binary = os.path.abspath(sys.argv[1])
    workdir = sys.argv[2] if len(sys.argv) > 2 else tempfile.mkdtemp(prefix="stoop-mcp-client-")
    modern_checks(binary, workdir)
    legacy_checks(binary, workdir)
    unknown_version_checks(binary, workdir)
    print("mcp client checks passed")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"mcp client check failed: {failure}", file=sys.stderr)
        sys.exit(1)
