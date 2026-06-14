"""ENVDOCTOR MCP server — exposes lint() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
import json
from envdoctor.core import lint_file


def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-envdoctor[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-envdoctor[mcp]'")
        return 1
    app = FastMCP("envdoctor")

    @app.tool()
    def envdoctor_scan(target: str) -> str:
        """.env validator, secret-presence checker. Returns JSON findings."""
        return json.dumps(lint_file(target).to_dict(), indent=2)

    app.run()
    return 0
