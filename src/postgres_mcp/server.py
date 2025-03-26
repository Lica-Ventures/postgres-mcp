import asyncio
import os
import sys
from urllib.parse import urlparse

import psycopg2
from psycopg2.extras import RealDictCursor
from mcp.server.models import InitializationOptions
import mcp.types as types
from mcp.server import NotificationOptions, Server
from pydantic import AnyUrl
import mcp.server.stdio

server = Server("postgres-mcp")

# Global connection pool
conn = None
SCHEMA_PATH = "schema"

def get_connection():
    global conn
    if not conn:
        raise ValueError("Database connection not initialized")
    return conn

@server.list_resources()
async def handle_list_resources() -> list[types.Resource]:
    """List available database tables as resources."""
    try:
        with get_connection().cursor() as cursor:
            cursor.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'"
            )
            tables = cursor.fetchall()

            base_url = urlparse(os.environ.get("DATABASE_URL", ""))
            base_url = base_url._replace(scheme="postgres", password="")
            base_url = base_url.geturl()

            return [
                types.Resource(
                    uri=AnyUrl(f"{base_url}/{table[0]}/{SCHEMA_PATH}"),
                    name=f'"{table[0]}" database schema',
                    description=f"Schema for table {table[0]}",
                    mimeType="application/json",
                )
                for table in tables
            ]
    except Exception as e:
        print(f"Error listing resources: {e}", file=sys.stderr)
        return []

@server.read_resource()
async def handle_read_resource(uri: AnyUrl) -> str:
    """Read schema information for a specific table."""
    if uri.scheme != "postgres":
        raise ValueError(f"Unsupported URI scheme: {uri.scheme}")

    path_parts = uri.path.strip("/").split("/")
    if len(path_parts) != 2 or path_parts[1] != SCHEMA_PATH:
        raise ValueError("Invalid resource URI")

    table_name = path_parts[0]

    try:
        with get_connection().cursor() as cursor:
            cursor.execute(
                """
                SELECT column_name, data_type
                FROM information_schema.columns
                WHERE table_name = %s
                """,
                [table_name]
            )
            columns = cursor.fetchall()
            return str([{"column_name": col[0], "data_type": col[1]} for col in columns])
    except Exception as e:
        print(f"Error reading resource: {e}", file=sys.stderr)
        raise

@server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    """List available database tools."""
    return [
        types.Tool(
            name="query",
            description="Run a read-only SQL query",
            inputSchema={
                "type": "object",
                "properties": {
                    "sql": {"type": "string"},
                },
                "required": ["sql"],
            },
        )
    ]

@server.call_tool()
async def handle_call_tool(
    name: str, arguments: dict | None
) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    """Handle tool execution requests."""
    if name != "query":
        raise ValueError(f"Unknown tool: {name}")

    if not arguments or "sql" not in arguments:
        raise ValueError("Missing SQL query")

    sql = arguments["sql"]

    try:
        with get_connection().cursor(cursor_factory=RealDictCursor) as cursor:
            # Start read-only transaction
            cursor.execute("BEGIN TRANSACTION READ ONLY")
            try:
                cursor.execute(sql)
                rows = cursor.fetchall()
                return [
                    types.TextContent(
                        type="text",
                        text=str(list(rows))
                    )
                ]
            finally:
                cursor.execute("ROLLBACK")
    except Exception as e:
        print(f"Error executing query: {e}", file=sys.stderr)
        raise

async def main():
    # Get database URL from command line
    if len(sys.argv) != 2:
        print("Please provide a database URL as a command-line argument", file=sys.stderr)
        sys.exit(1)

    database_url = sys.argv[1]

    # Initialize global connection
    global conn
    try:
        conn = psycopg2.connect(database_url)
    except Exception as e:
        print(f"Error connecting to database: {e}", file=sys.stderr)
        sys.exit(1)

    # Run the server using stdin/stdout streams
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        try:
            await server.run(
                read_stream,
                write_stream,
                InitializationOptions(
                    server_name="postgres-mcp",
                    server_version="0.1.0",
                    capabilities=server.get_capabilities(
                        notification_options=NotificationOptions(),
                        experimental_capabilities={},
                    ),
                ),
            )
        finally:
            if conn:
                conn.close()

if __name__ == "__main__":
    asyncio.run(main())