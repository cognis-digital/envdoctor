"""ENVDOCTOR MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from envdoctor.core import scan, to_json

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
        """.env validator, secret-presence and config-drift checker. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
