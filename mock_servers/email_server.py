"""Safe Mock Email MCP Server for MCPath external-action capability modeling.

Exposes a realistic send_email tool without making any network requests or
sending real emails. All actions are simulated, safely validated, and logged locally.
"""

import logging
import sys
from mcp.server.mcpserver import MCPServer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("mcpath.mock_servers.email_server")

app = MCPServer("mcpath-mock-email-server")


@app.tool()
def send_email(recipient: str, subject: str, body: str) -> str:
    """Simulates sending an email to an external recipient safely without making any real network requests.

    Args:
        recipient: The destination email address (e.g. user@example.com).
        subject: The subject line of the email.
        body: The plain text message body.

    Returns:
        A deterministic confirmation string confirming the simulated email queueing.
    """
    if not recipient or not recipient.strip():
        return "Error: Recipient address cannot be empty."

    # Completely simulated - zero external network requests, zero socket connections
    logger.info(
        "SIMULATED EMAIL DISPATCH: recipient=%s, subject=%s, body_length=%d bytes",
        recipient.strip(),
        subject.strip(),
        len(body or ""),
    )

    return (
        f"[MOCK EMAIL QUEUED] To: {recipient.strip()} | "
        f"Subject: '{subject.strip()}' | "
        f"Body Length: {len(body or '')} chars | "
        f"Status: SIMULATED (no external network request made)"
    )


if __name__ == "__main__":
    app.run(transport="stdio")
