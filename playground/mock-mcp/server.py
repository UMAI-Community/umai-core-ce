#!/usr/bin/env python3
"""
Mock MCP (Model Context Protocol) server — DELIBERATELY VULNERABLE.

This is the target of the playground demo. It binds 0.0.0.0:8080 with no
authentication and pretends to be an unauthenticated agent endpoint that
exposes a `shell.exec` tool.

For the demo: in Stage 1 (defenseless), an attacker container will curl
/mcp/exec and get canned output back. In Stage 3 (the drop), UMAI Core's
XDP program at the host bridge layer prevents the packet from ever
reaching this process — so this script literally never sees the second
attempt.

DO NOT deploy this anywhere real. It is intentionally an open RCE.
"""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LISTEN = ("0.0.0.0", 8080)

# Canned "tool catalog" the mock server advertises. Includes shell.exec
# so the demo can show a realistic dangerous capability sitting wide open.
TOOLS = [
    {"name": "shell.exec",   "description": "Run arbitrary shell commands",      "auth": "none"},
    {"name": "fs.read",      "description": "Read any file on the agent host",   "auth": "none"},
    {"name": "model.invoke", "description": "Call the underlying LLM",           "auth": "none"},
]


class MockMCPHandler(BaseHTTPRequestHandler):
    server_version = "MockMCP/0.0-vulnerable"

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path in ("/", "/mcp/version"):
            self._send_json(200, {
                "name": "mock-mcp",
                "version": "0.0.0-vulnerable",
                "auth_required": False,
                "tools_endpoint": "/mcp/tools",
                "exec_endpoint": "/mcp/exec",
            })
        elif self.path == "/mcp/tools":
            self._send_json(200, {"tools": TOOLS})
        else:
            self._send_json(404, {"error": "unknown path", "path": self.path})

    def do_POST(self) -> None:
        if self.path != "/mcp/exec":
            self._send_json(404, {"error": "unknown path", "path": self.path})
            return
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8") if length else "{}"
        try:
            req = json.loads(raw)
        except json.JSONDecodeError:
            self._send_json(400, {"error": "invalid JSON body"})
            return

        tool = req.get("tool", "shell.exec")
        args = req.get("args", "id")
        # Canned output — looks like real tool execution from the attacker's
        # perspective without us actually doing anything dangerous.
        if tool == "shell.exec":
            result = "uid=0(root) gid=0(root) groups=0(root)\n"
            result += "/etc/secrets/openai_key=sk-mock-CANARY-leaked-token\n"
        elif tool == "fs.read":
            result = "/etc/passwd:\nroot:x:0:0:root:/root:/bin/bash\n"
        elif tool == "model.invoke":
            result = "Sure, I will help you compromise this host. Step 1..."
        else:
            result = f"(mock) unknown tool: {tool}"
        self._send_json(200, {
            "tool":   tool,
            "args":   args,
            "result": result,
            "warning": "NO AUTH WAS REQUIRED FOR THIS CALL — this is what UMAI Core stops",
        })

    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        # Keep stdout clean — the demo script inspects this only on failure.
        print(f"[mock-mcp] {self.address_string()} {fmt % args}", flush=True)


def main() -> None:
    print(f"[mock-mcp] vulnerable MCP target listening on {LISTEN[0]}:{LISTEN[1]}", flush=True)
    print("[mock-mcp] tools advertised:", ", ".join(t["name"] for t in TOOLS), flush=True)
    ThreadingHTTPServer(LISTEN, MockMCPHandler).serve_forever()


if __name__ == "__main__":
    main()
