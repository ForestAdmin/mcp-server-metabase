"""MCP SSE server for Dust.tt using official MCP SDK."""

import asyncio
import hashlib
import logging
import os
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request, HTTPException, Security, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import Response
from mcp.server import Server
from mcp.server.sse import SseServerTransport
import mcp.types as types
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from starlette.middleware.base import BaseHTTPMiddleware

from .metabase_client import MetabaseClient
from .tools import TOOL_DEFINITIONS, execute_tool

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Security
security = HTTPBearer(auto_error=False)

# Rate limiter
limiter = Limiter(key_func=get_remote_address)

# Global Metabase clients (connection-based)
metabase_clients: dict[str, MetabaseClient] = {}


# Middleware for request size limits
class LimitUploadSize(BaseHTTPMiddleware):
    """Middleware to limit request body size and prevent memory exhaustion attacks."""

    def __init__(self, app, max_upload_size: int = 1_000_000):
        super().__init__(app)
        self.max_upload_size = max_upload_size

    async def dispatch(self, request: Request, call_next):
        if request.method in ["POST", "PUT", "PATCH"]:
            if "content-length" in request.headers:
                content_length = int(request.headers["content-length"])
                if content_length > self.max_upload_size:
                    logger.warning(
                        f"Request rejected: payload size {content_length} exceeds limit {self.max_upload_size}"
                    )
                    return Response(
                        content='{"detail":"Request payload too large. Maximum size is 1MB."}',
                        status_code=413,
                        media_type="application/json"
                    )
        return await call_next(request)


def hash_token(token: str) -> str:
    """Hash a token for secure logging without exposing the actual token."""
    return hashlib.sha256(token.encode()).hexdigest()[:16]


def get_metabase_connection(request: Request) -> str:
    """
    Get Metabase connection name from X-Metabase-Connection header.

    Args:
        request: FastAPI request object

    Returns:
        Connection name from header

    Raises:
        HTTPException: If header is missing or connection doesn't exist
    """
    connection = request.headers.get("X-Metabase-Connection")

    if not connection:
        client_ip = request.client.host if request.client else "unknown"
        logger.warning(f"Request without X-Metabase-Connection header from IP: {client_ip}")
        raise HTTPException(
            status_code=400,
            detail="Missing X-Metabase-Connection header. Please specify connection name (e.g., 'mcp-server-metabase-admin' or 'mcp-server-metabase-revenue')."
        )

    if connection not in metabase_clients:
        client_ip = request.client.host if request.client else "unknown"
        available_connections = list(metabase_clients.keys())
        logger.warning(
            f"Invalid connection '{connection}' requested from IP: {client_ip}. "
            f"Available: {available_connections}"
        )
        raise HTTPException(
            status_code=400,
            detail=f"Invalid connection name: '{connection}'. Available connections: {', '.join(available_connections)}"
        )

    logger.debug(f"Using Metabase connection: {connection}")
    return connection


async def verify_mcp_token(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Security(security)
) -> str:
    """
    Verify MCP authentication token from Authorization header.

    Args:
        request: FastAPI request object for IP logging
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
        client_ip = request.client.host if request.client else "unknown"
        logger.warning(f"Authentication attempt without credentials from IP: {client_ip}")
        raise HTTPException(
            status_code=401,
            detail="Missing authentication token. Please provide Bearer token in Authorization header."
        )

    # Verify token matches
    if credentials.credentials != expected_token:
        client_ip = request.client.host if request.client else "unknown"
        token_hash = hash_token(credentials.credentials)
        logger.warning(
            f"Invalid authentication attempt from IP: {client_ip}, "
            f"token hash: {token_hash}"
        )
        raise HTTPException(
            status_code=403,
            detail="Invalid authentication token"
        )

    logger.debug("Authentication successful")
    return credentials.credentials


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle manager for FastAPI app."""
    global metabase_clients

    # Startup
    base_url = os.getenv("METABASE_URL")

    logger.info("Starting Forest Admin Metabase MCP Server (SSE) with multi-connection support")
    logger.info(f"Metabase URL: {base_url if base_url else 'Not configured'}")

    # Initialize multiple Metabase connections
    connections = {
        "mcp-server-metabase-admin": os.getenv("METABASE_API_KEY_ADMIN"),
        "mcp-server-metabase-revenue": os.getenv("METABASE_API_KEY_REVENUE")
    }

    for connection_name, api_key in connections.items():
        if api_key:
            try:
                metabase_clients[connection_name] = MetabaseClient(
                    base_url=base_url,
                    api_key=api_key
                )
                logger.info(f"✓ Metabase connection '{connection_name}' initialized successfully")
            except Exception as e:
                logger.error(f"✗ Failed to initialize connection '{connection_name}': {e}")
                raise
        else:
            logger.warning(f"⚠ Connection '{connection_name}' not configured (missing API key)")

    if not metabase_clients:
        logger.error("No Metabase connections configured! At least one connection is required.")
        raise ValueError("No Metabase connections configured")

    logger.info(f"Total active connections: {len(metabase_clients)}")
    logger.info(f"Available connections: {', '.join(metabase_clients.keys())}")

    yield

    # Shutdown
    logger.info("Shutting down MCP server")
    for connection_name, client in metabase_clients.items():
        logger.info(f"Closing connection: {connection_name}")
        client.close()
    metabase_clients.clear()


# Initialize FastAPI app
app = FastAPI(
    title="Forest Admin Metabase MCP Server",
    description="MCP server for Metabase with SSE transport for Dust.tt",
    version="0.1.0",
    lifespan=lifespan,
    docs_url=None,        # Disable Swagger UI for security
    redoc_url=None,       # Disable ReDoc for security
    openapi_url=None,     # Disable OpenAPI JSON endpoint for security
)

# Configure rate limiter
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Add security middlewares
app.add_middleware(LimitUploadSize, max_upload_size=1_000_000)  # 1MB limit


# Security headers middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Add security headers to all responses."""
    response = await call_next(request)

    # Security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'none'"

    # HSTS for HTTPS connections (Heroku handles this but we can add it)
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    return response


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
@limiter.limit("30/minute")  # Rate limit SSE connections
async def root(request: Request, credentials: HTTPAuthorizationCredentials | None = Security(security)):
    """MCP endpoint - handle both health check and SSE connections."""
    # Check if client wants SSE (MCP protocol)
    accept = request.headers.get("accept", "")
    if "text/event-stream" in accept:
        # SSE connections require authentication
        await verify_mcp_token(request, credentials)
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
@limiter.limit("20/minute")  # Rate limit API calls
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
            # Get connection from header (REQUIRED for tool calls)
            connection_name = get_metabase_connection(request)
            metabase_client = metabase_clients[connection_name]

            tool_name = params.get("name")
            tool_arguments = params.get("arguments", {})

            logger.info(f"Executing tool '{tool_name}' on connection '{connection_name}'")
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

    except HTTPException as he:
        # Re-raise HTTP exceptions (like missing header)
        raise he
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
    is_healthy = len(metabase_clients) > 0
    connections_status = {
        name: "initialized" for name in metabase_clients.keys()
    }
    return {
        "status": "healthy" if is_healthy else "unhealthy",
        "connections": connections_status,
        "connection_count": len(metabase_clients),
        "metabase_url": list(metabase_clients.values())[0].base_url if metabase_clients else None
    }


# Add SSE endpoint using MCP SDK
from starlette.requests import Request
from starlette.responses import Response

sse = SseServerTransport("/sse")


@app.get("/sse")
@limiter.limit("30/minute")  # Rate limit SSE connections
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
@limiter.limit("20/minute")  # Rate limit API calls
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
            # Get connection from header (REQUIRED for tool calls)
            connection_name = get_metabase_connection(request)
            metabase_client = metabase_clients[connection_name]

            tool_name = params.get("name")
            tool_arguments = params.get("arguments", {})

            logger.info(f"Executing tool '{tool_name}' on connection '{connection_name}'")
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

    except HTTPException as he:
        # Re-raise HTTP exceptions (like missing header)
        raise he
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
