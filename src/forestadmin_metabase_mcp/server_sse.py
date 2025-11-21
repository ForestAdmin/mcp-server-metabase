"""MCP SSE server for Dust.tt using official MCP SDK."""

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request, HTTPException, Security, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from mcp.server import Server
from mcp.server.sse import SseServerTransport
import mcp.types as types

from .metabase_client import MetabaseClient
from .tools import TOOL_DEFINITIONS, execute_tool

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Security
security = HTTPBearer(auto_error=False)

# Global Metabase client
metabase_client: MetabaseClient | None = None


async def verify_mcp_token(
    credentials: HTTPAuthorizationCredentials | None = Security(security)
) -> str:
    """
    Verify MCP authentication token from Authorization header.

    Args:
        credentials: HTTP Bearer token credentials

    Returns:
        The validated token string

    Raises:
        HTTPException: If authentication fails
    """
    expected_token = os.getenv("MCP_AUTH_TOKEN")

    # Check if MCP_AUTH_TOKEN is configured
    if not expected_token:
        logger.error("MCP_AUTH_TOKEN not configured in environment")
        raise HTTPException(
            status_code=500,
            detail="Server authentication not configured"
        )

    # Check if credentials were provided
    if not credentials:
        logger.warning("Authentication attempt without credentials")
        raise HTTPException(
            status_code=401,
            detail="Missing authentication token. Please provide Bearer token in Authorization header."
        )

    # Verify token matches
    if credentials.credentials != expected_token:
        logger.warning(f"Invalid authentication attempt from token: {credentials.credentials[:10]}...")
        raise HTTPException(
            status_code=403,
            detail="Invalid authentication token"
        )

    logger.debug("Authentication successful")
    return credentials.credentials


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle manager for FastAPI app."""
    global metabase_client

    # Startup
    base_url = os.getenv("METABASE_URL")
    api_key = os.getenv("METABASE_API_KEY")
    username = os.getenv("METABASE_USERNAME")
    password = os.getenv("METABASE_PASSWORD")

    logger.info("Starting Forest Admin Metabase MCP Server (SSE)")
    logger.info(f"Metabase URL: {base_url if base_url else 'Not configured'}")
    logger.info(f"Authentication: {'API Key' if api_key else 'Username/Password' if username and password else 'Not configured'}")

    try:
        metabase_client = MetabaseClient(
            base_url=base_url,
            api_key=api_key,
            username=username,
            password=password
        )
        logger.info("Metabase client initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize Metabase client: {e}")
        raise

    yield

    # Shutdown
    logger.info("Shutting down MCP server")
    if metabase_client:
        metabase_client.close()


# Initialize FastAPI app
app = FastAPI(
    title="Forest Admin Metabase MCP Server",
    description="MCP server for Metabase with SSE transport for Dust.tt",
    version="0.1.0",
    lifespan=lifespan,
)

# Initialize MCP server
mcp_server = Server("forestadmin-metabase-mcp")


@mcp_server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    """List available MCP tools for Metabase interactions."""
    return TOOL_DEFINITIONS


@mcp_server.call_tool()
async def handle_call_tool(
    name: str, arguments: dict[str, Any] | None
) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    """Handle tool execution requests."""
    if metabase_client is None:
        raise RuntimeError("Metabase client not initialized")

    try:
        result = await execute_tool(metabase_client, name, arguments or {})
        return [types.TextContent(type="text", text=result)]
    except Exception as e:
        logger.error(f"Tool execution failed: {name}, error: {e}")
        raise


@app.get("/")
async def root(request: Request, credentials: HTTPAuthorizationCredentials | None = Security(security)):
    """MCP endpoint - handle both health check and SSE connections."""
    # Check if client wants SSE (MCP protocol)
    accept = request.headers.get("accept", "")
    if "text/event-stream" in accept:
        # SSE connections require authentication
        await verify_mcp_token(credentials)
        # Return SSE stream for MCP
        from sse_starlette.sse import EventSourceResponse

        async def event_generator():
            """Generate SSE events from MCP server."""
            try:
                # Send initial connection message
                yield {
                    "event": "message",
                    "data": '{"jsonrpc":"2.0","method":"initialized","params":{}}'
                }

                # Keep connection alive
                while True:
                    await asyncio.sleep(30)
                    # Send heartbeat/ping
                    yield {
                        "event": "ping",
                        "data": ""
                    }
            except asyncio.CancelledError:
                logger.info("SSE connection closed")

        return EventSourceResponse(
            event_generator(),
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no"
            }
        )
    else:
        # Regular health check
        return {
            "name": "forestadmin-metabase-mcp",
            "version": "0.1.0",
            "status": "healthy",
            "protocol": "MCP over SSE",
            "compatible_with": ["Dust.tt", "Claude Desktop", "Cursor IDE"],
            "mcp_endpoint": "/",
            "tools_count": len(TOOL_DEFINITIONS)
        }


@app.post("/")
async def root_post(request: Request, token: str = Depends(verify_mcp_token)):
    """Handle JSON-RPC requests via POST to root endpoint (Dust.tt compatibility)."""
    try:
        body = await request.json()
        method = body.get("method", "")
        params = body.get("params", {})

        logger.info(f"Received JSON-RPC request at /: {method}")

        # Handle initialize request
        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": body.get("id"),
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {}
                    },
                    "serverInfo": {
                        "name": "forestadmin-metabase-mcp",
                        "version": "0.1.0"
                    }
                }
            }

        # Handle tools/list request
        elif method == "tools/list":
            tools_list = []
            for tool in TOOL_DEFINITIONS:
                tools_list.append({
                    "name": tool.name,
                    "description": tool.description,
                    "inputSchema": tool.inputSchema
                })

            return {
                "jsonrpc": "2.0",
                "id": body.get("id"),
                "result": {
                    "tools": tools_list
                }
            }

        # Handle tools/call request
        elif method == "tools/call":
            tool_name = params.get("name")
            tool_arguments = params.get("arguments", {})

            if metabase_client is None:
                raise RuntimeError("Metabase client not initialized")

            result = await execute_tool(metabase_client, tool_name, tool_arguments)

            return {
                "jsonrpc": "2.0",
                "id": body.get("id"),
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": result
                        }
                    ]
                }
            }

        else:
            return {
                "jsonrpc": "2.0",
                "id": body.get("id"),
                "error": {
                    "code": -32601,
                    "message": f"Method not found: {method}"
                }
            }

    except Exception as e:
        logger.error(f"Error handling POST request at /: {e}", exc_info=True)
        return {
            "jsonrpc": "2.0",
            "id": body.get("id") if 'body' in locals() else None,
            "error": {
                "code": -32603,
                "message": str(e)
            }
        }


@app.get("/health")
async def health_check():
    """Detailed health check."""
    is_healthy = metabase_client is not None
    return {
        "status": "healthy" if is_healthy else "unhealthy",
        "metabase_client": "initialized" if is_healthy else "not initialized",
        "metabase_url": metabase_client.base_url if is_healthy and metabase_client else None
    }


# Add SSE endpoint using MCP SDK
from starlette.requests import Request
from starlette.responses import Response

sse = SseServerTransport("/sse")


@app.get("/sse")
async def handle_sse_get(request: Request, token: str = Depends(verify_mcp_token)):
    """Handle SSE connections for MCP protocol (GET requests)."""
    from sse_starlette.sse import EventSourceResponse

    async def event_generator():
        """Generate SSE events from MCP server."""
        try:
            # Send initial connection message
            yield {
                "event": "message",
                "data": '{"jsonrpc":"2.0","method":"initialized","params":{}}'
            }

            # Keep connection alive
            while True:
                await asyncio.sleep(30)
                # Send heartbeat/ping
                yield {
                    "event": "ping",
                    "data": ""
                }
        except asyncio.CancelledError:
            logger.info("SSE connection closed")

    return EventSourceResponse(
        event_generator(),
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no"
        }
    )


@app.post("/sse")
async def handle_sse_post(request: Request, token: str = Depends(verify_mcp_token)):
    """Handle JSON-RPC requests via POST to SSE endpoint."""
    try:
        body = await request.json()
        method = body.get("method", "")
        params = body.get("params", {})

        logger.info(f"Received JSON-RPC request: {method}")

        # Handle initialize request
        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": body.get("id"),
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {}
                    },
                    "serverInfo": {
                        "name": "forestadmin-metabase-mcp",
                        "version": "0.1.0"
                    }
                }
            }

        # Handle tools/list request
        elif method == "tools/list":
            tools_list = []
            for tool in TOOL_DEFINITIONS:
                tools_list.append({
                    "name": tool.name,
                    "description": tool.description,
                    "inputSchema": tool.inputSchema
                })

            return {
                "jsonrpc": "2.0",
                "id": body.get("id"),
                "result": {
                    "tools": tools_list
                }
            }

        # Handle tools/call request
        elif method == "tools/call":
            tool_name = params.get("name")
            tool_arguments = params.get("arguments", {})

            if metabase_client is None:
                raise RuntimeError("Metabase client not initialized")

            result = await execute_tool(metabase_client, tool_name, tool_arguments)

            return {
                "jsonrpc": "2.0",
                "id": body.get("id"),
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": result
                        }
                    ]
                }
            }

        else:
            return {
                "jsonrpc": "2.0",
                "id": body.get("id"),
                "error": {
                    "code": -32601,
                    "message": f"Method not found: {method}"
                }
            }

    except Exception as e:
        logger.error(f"Error handling POST request: {e}", exc_info=True)
        return {
            "jsonrpc": "2.0",
            "id": body.get("id") if 'body' in locals() else None,
            "error": {
                "code": -32603,
                "message": str(e)
            }
        }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
