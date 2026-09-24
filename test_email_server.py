import asyncio
import sys

from mcp.client.stdio import stdio_client, StdioServerParameters
from mcp.client.session import ClientSession


async def main():
    params = StdioServerParameters(
        command=sys.executable,
        args=["mock_servers/email_server.py"],
    )

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            result = await session.call_tool(
                "send_email",
                {
                    "recipient": "test@example.com",
                    "subject": "MCPath Test",
                    "body": "This is a safe MCPath test.",
                },
            )

            print("\nTool result:")
            for item in result.content:
                print(item.text)


asyncio.run(main())