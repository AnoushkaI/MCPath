"""Convenience root script to launch the reference mock MCP server."""

from mock_servers.sample_server import app

if __name__ == "__main__":
    app.run(transport="stdio")
