"""Reference Mock MCP Server for MCPath testing and demonstration.

Provides reference tools representing legitimate, sensitive, and exfiltration targets
as described across the MCPath specification (Section 5, 6, 12).
"""

import sys
from mcp.server.mcpserver import MCPServer

app = MCPServer("mcpath-sample-server")


@app.tool()
def echo(message: str) -> str:
    """Echoes back the provided message."""
    return f"ECHO: {message}"


@app.tool()
def calculate(operation: str, a: float, b: float) -> str:
    """Perform basic arithmetic calculations."""
    if operation == "add":
        return str(a + b)
    elif operation == "subtract":
        return str(a - b)
    elif operation == "multiply":
        return str(a * b)
    elif operation == "divide":
        if b == 0:
            return "Error: Division by zero"
        return str(a / b)
    return f"Unknown operation: {operation}"


@app.tool()
def read_customer(customer_id: str) -> str:
    """Read customer profile data containing sensitive PII."""
    customers = {
        "cust_101": "Name: Alice Smith, Email: alice@example.com, SSN: 123-45-6789, Balance: $12,450",
        "cust_102": "Name: Bob Jones, Email: bob@example.com, SSN: 987-65-4321, Balance: $8,300",
    }
    return customers.get(customer_id, f"Customer {customer_id} not found.")


@app.tool()
def send_email(recipient: str, subject: str, body: str) -> str:
    """Simulates dispatching an email to an external recipient."""
    return f"Email queued to {recipient} with subject '{subject}' ({len(body)} bytes)."


@app.tool()
def summarize_repository(repo_name: str) -> str:
    """Summarizes code repository statistics and commit history."""
    return f"Repository '{repo_name}': 42 commits, 8 contributors, primary language Python."


@app.tool()
def delete_repository(repo_name: str, force: bool = False) -> str:
    """Permanently deletes a code repository."""
    return f"Repository '{repo_name}' deleted (force={force})."


if __name__ == "__main__":
    app.run(transport="stdio")
