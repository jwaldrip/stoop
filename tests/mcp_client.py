#!/usr/bin/env python3
"""An independent MCP client for `stoop mcp`, using only the standard library.

It shares no code with the Rust test harness, so it checks the server the way another client
would: the newest revision (per-request _meta), the legacy handshake, and the framing rules.
Every read has a deadline, so a server that stops answering fails the check instead of hanging.

Usage: python3 tests/mcp_client.py path/to/stoop [workdir]
Exits 0 when every check passes.
"""

import json
import os
import select
import subprocess
import sys
import tempfile
import time

MODERN = "2026-07-28"
EXPECTED_TOOLS = ["explain", "list_proofs", "plan", "forget", "guide"]
READ_TIMEOUT = 20  # seconds to wait for each message from the server


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
        self.fd = self.proc.stdout.fileno()
        self.buffer = b""
        self.lines = []  # every stdout line, verbatim
        self.pending = []  # messages read while waiting for another reply

    def send(self, message):
        self.proc.stdin.write((json.dumps(message) + "\n").encode("utf-8"))
        self.proc.stdin.flush()

    def send_raw(self, text):
        self.proc.stdin.write(text.encode("utf-8") + b"\n")
        self.proc.stdin.flush()

    def _next_line(self, timeout):
        """One complete stdout line, or None at end of output. Fails after `timeout` seconds."""
        deadline = time.monotonic() + timeout
        while b"\n" not in self.buffer:
            left = deadline - time.monotonic()
            if left <= 0:
                raise AssertionError(f"no message from stoop mcp within {timeout} s")
            ready, _, _ = select.select([self.fd], [], [], left)
            if not ready:
                raise AssertionError(f"no message from stoop mcp within {timeout} s")
            chunk = os.read(self.fd, 65536)
            if not chunk:
                if self.buffer:
                    line, self.buffer = self.buffer, b""
                    return line.decode("utf-8")
                return None
            self.buffer += chunk
        line, _, self.buffer = self.buffer.partition(b"\n")
        return line.decode("utf-8")

    def read(self, timeout=READ_TIMEOUT):
        raw = self._next_line(timeout)
        if raw is None:
            return None
        self.lines.append(raw)
        return json.loads(raw)  # every stdout line must be one JSON message

    def call(self, request_id, method, params):
        self.send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
        while True:
            message = self.read()
            if message is None:
                raise AssertionError(f"server closed before answering {request_id!r}")
            if message.get("id") == request_id and ("result" in message or "error" in message):
                return message
            self.pending.append(message)

    def finish(self, timeout=60):
        self.proc.stdin.close()
        while True:
            message = self.read(timeout)
            if message is None:
                break
            self.pending.append(message)
        return self.proc.wait(timeout=timeout)


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

    bad_params = s.call(3, "tools/list", "hello")
    check(bad_params["error"]["code"] == -32602, f"non-object params: {bad_params}")

    unsupported = s.call(
        4, "tools/list", {"_meta": {**meta(), "io.modelcontextprotocol/protocolVersion": "1900-01-01"}}
    )
    check(unsupported["error"]["code"] == -32022, f"unsupported version: {unsupported}")
    check(MODERN in unsupported["error"]["data"]["supported"], f"supported list: {unsupported}")

    guide = s.call(
        5, "tools/call", {"name": "guide", "arguments": {"topic": "reading-a-decision"}, "_meta": meta()}
    )
    sections = guide["result"]["structuredContent"]["sections"]
    check(len(sections) == 1 and sections[0]["id"] == "reading-a-decision", f"guide topic: {guide}")
    check(guide["result"]["isError"] is False, f"guide is an error: {guide}")

    explain = s.call(6, "tools/call", {"name": "explain", "arguments": {"argv": ["true"]}, "_meta": meta()})
    check(explain["result"]["structuredContent"]["decision"] in ("run", "skip"), f"explain: {explain}")
    check(explain["result"]["content"][0]["type"] == "text", f"explain text mirror: {explain}")

    refused = s.call(7, "tools/call", {"name": "run", "arguments": {"argv": ["true"]}, "_meta": meta()})
    check(refused["error"]["code"] == -32602, f"run without --allow-run: {refused}")

    # Garbage the server must survive, and a notification it must not answer.
    s.send_raw("{not json")
    parse = s.read()
    check(parse["error"]["code"] == -32700 and parse["id"] is None, f"parse error: {parse}")
    s.send_raw('[{"jsonrpc":"2.0","id":1,"method":"ping"}]')
    batch = s.read()
    check(batch["error"]["code"] == -32600, f"batch: {batch}")
    s.send({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 99}})
    ping = s.call(8, "ping", {})
    check(ping["id"] == 8 and "result" in ping, f"ping: {ping}")
    check(not s.pending, f"unexpected messages: {s.pending}")

    code = s.finish()
    check(code == 0, f"exit status after end of input: {code}")
    for line in s.lines:
        json.loads(line)


def legacy_checks(binary, cwd):
    s = Session(binary, cwd)
    init = s.call(
        1,
        "initialize",
        {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "mcp_client.py", "version": "1"}},
    )
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
    init = s.call(
        1,
        "initialize",
        {"protocolVersion": "1900-01-01", "capabilities": {}, "clientInfo": {"name": "mcp_client.py", "version": "1"}},
    )
    check(init["result"]["protocolVersion"] == "2025-11-25", f"unknown version answer: {init}")
    check(s.finish() == 0, "unknown-version session exit status")


def silence_checks(binary, cwd):
    """A server that stops answering must fail the check within the read timeout."""
    s = Session(binary, cwd)
    s.call(1, "ping", {})
    s.send({"jsonrpc": "2.0", "id": 2, "method": "ping", "params": {}})
    s.proc.stdin.close()
    answered = s.read(READ_TIMEOUT)
    check(answered is not None and answered.get("id") == 2, f"ping after close: {answered}")
    check(s.proc.wait(timeout=READ_TIMEOUT) == 0, "exit after a closed input")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    binary = os.path.abspath(sys.argv[1])
    workdir = sys.argv[2] if len(sys.argv) > 2 else tempfile.mkdtemp(prefix="stoop-mcp-client-")
    modern_checks(binary, workdir)
    legacy_checks(binary, workdir)
    unknown_version_checks(binary, workdir)
    silence_checks(binary, workdir)
    print("mcp client checks passed")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as failure:
        print(f"mcp client check failed: {failure}", file=sys.stderr)
        sys.exit(1)
