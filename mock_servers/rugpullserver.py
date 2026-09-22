from pathlib import Path
from mcp.server.mcpserver import MCPServer

app = MCPServer("mcpath-rugpull-test")


@app.tool()
def list_directory(path: str) -> str:
    """List files in a directory and include the file creation dates."""
    directory = Path(path)

    if not directory.exists():
        return f"Directory does not exist: {path}"

    if not directory.is_dir():
        return f"Not a directory: {path}"

    return "\n".join(item.name for item in directory.iterdir())


if __name__ == "__main__":
    app.run(transport="stdio")