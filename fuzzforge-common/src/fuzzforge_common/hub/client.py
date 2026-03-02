"""MCP client for communicating with hub servers.

This module provides a generic MCP client that can connect to any MCP server
via stdio (docker/command) or SSE transport. It handles:
- Starting containers/processes for stdio transport
- Connecting to SSE endpoints
- Discovering tools via list_tools()
- Executing tools via call_tool()

"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any, cast

from fuzzforge_common.hub.models import (
    HubServer,
    HubServerConfig,
    HubServerType,
    HubTool,
)

if TYPE_CHECKING:
    from asyncio.subprocess import Process
    from collections.abc import AsyncGenerator

    from structlog.stdlib import BoundLogger


def get_logger() -> BoundLogger:
    """Get structlog logger instance.

    :returns: Configured structlog logger.

    """
    from structlog import get_logger  # noqa: PLC0415

    return cast("BoundLogger", get_logger())


class HubClientError(Exception):
    """Error in hub client operations."""


class HubClient:
    """Client for communicating with MCP hub servers.

    Supports stdio (via docker/command) and SSE transports.
    Uses the MCP protocol for tool discovery and execution.

    """

    #: Default timeout for operations.
    DEFAULT_TIMEOUT: int = 30

    def __init__(self, timeout: int = DEFAULT_TIMEOUT) -> None:
        """Initialize the hub client.

        :param timeout: Default timeout for operations in seconds.

        """
        self._timeout = timeout

    async def discover_tools(self, server: HubServer) -> list[HubTool]:
        """Discover tools from a hub server.

        Connects to the server, calls list_tools(), and returns
        parsed HubTool instances.

        :param server: Hub server to discover tools from.
        :returns: List of discovered tools.
        :raises HubClientError: If discovery fails.

        """
        logger = get_logger()
        config = server.config

        logger.info("Discovering tools", server=config.name, type=config.type.value)

        try:
            async with self._connect(config) as (reader, writer):
                # Initialize MCP session
                await self._initialize_session(reader, writer, config.name)

                # List tools
                tools_data = await self._call_method(
                    reader,
                    writer,
                    "tools/list",
                    {},
                )

                # Parse tools
                tools = []
                for tool_data in tools_data.get("tools", []):
                    tool = HubTool.from_mcp_tool(
                        server_name=config.name,
                        name=tool_data["name"],
                        description=tool_data.get("description"),
                        input_schema=tool_data.get("inputSchema", {}),
                    )
                    tools.append(tool)

                logger.info(
                    "Discovered tools",
                    server=config.name,
                    count=len(tools),
                )
                return tools

        except Exception as e:
            logger.error(
                "Tool discovery failed",
                server=config.name,
                error=str(e),
            )
            raise HubClientError(f"Discovery failed for {config.name}: {e}") from e

    async def execute_tool(
        self,
        server: HubServer,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        timeout: int | None = None,
    ) -> dict[str, Any]:
        """Execute a tool on a hub server.

        :param server: Hub server to execute on.
        :param tool_name: Name of the tool to execute.
        :param arguments: Tool arguments.
        :param timeout: Execution timeout (uses default if None).
        :returns: Tool execution result.
        :raises HubClientError: If execution fails.

        """
        logger = get_logger()
        config = server.config
        exec_timeout = timeout or self._timeout

        logger.info(
            "Executing hub tool",
            server=config.name,
            tool=tool_name,
            timeout=exec_timeout,
        )

        try:
            async with self._connect(config) as (reader, writer):
                # Initialize MCP session
                await self._initialize_session(reader, writer, config.name)

                # Call tool
                result = await asyncio.wait_for(
                    self._call_method(
                        reader,
                        writer,
                        "tools/call",
                        {"name": tool_name, "arguments": arguments},
                    ),
                    timeout=exec_timeout,
                )

                logger.info(
                    "Tool execution completed",
                    server=config.name,
                    tool=tool_name,
                )
                return result

        except asyncio.TimeoutError as e:
            logger.error(
                "Tool execution timed out",
                server=config.name,
                tool=tool_name,
                timeout=exec_timeout,
            )
            raise HubClientError(
                f"Execution timed out for {config.name}:{tool_name}"
            ) from e

        except Exception as e:
            logger.error(
                "Tool execution failed",
                server=config.name,
                tool=tool_name,
                error=str(e),
            )
            raise HubClientError(
                f"Execution failed for {config.name}:{tool_name}: {e}"
            ) from e

    @asynccontextmanager
    async def _connect(
        self,
        config: HubServerConfig,
    ) -> AsyncGenerator[tuple[asyncio.StreamReader, asyncio.StreamWriter], None]:
        """Connect to an MCP server.

        :param config: Server configuration.
        :yields: Tuple of (reader, writer) for communication.

        """
        if config.type == HubServerType.DOCKER:
            async with self._connect_docker(config) as streams:
                yield streams
        elif config.type == HubServerType.COMMAND:
            async with self._connect_command(config) as streams:
                yield streams
        elif config.type == HubServerType.SSE:
            async with self._connect_sse(config) as streams:
                yield streams
        else:
            msg = f"Unsupported server type: {config.type}"
            raise HubClientError(msg)

    @asynccontextmanager
    async def _connect_docker(
        self,
        config: HubServerConfig,
    ) -> AsyncGenerator[tuple[asyncio.StreamReader, asyncio.StreamWriter], None]:
        """Connect to a Docker-based MCP server.

        :param config: Server configuration with image name.
        :yields: Tuple of (reader, writer) for stdio communication.

        """
        if not config.image:
            msg = f"Docker image not specified for server '{config.name}'"
            raise HubClientError(msg)

        # Build docker command
        cmd = ["docker", "run", "-i", "--rm"]

        # Add capabilities
        for cap in config.capabilities:
            cmd.extend(["--cap-add", cap])

        # Add volumes
        for volume in config.volumes:
            cmd.extend(["-v", os.path.expandvars(os.path.expanduser(volume))])

        # Add environment variables
        for key, value in config.environment.items():
            cmd.extend(["-e", f"{key}={value}"])

        cmd.append(config.image)

        process: Process = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            limit=4 * 1024 * 1024,  # 4 MB — default 64 KB breaks large YARA/capa results
        )

        try:
            if process.stdin is None or process.stdout is None:
                msg = "Failed to get process streams"
                raise HubClientError(msg)

            # Create asyncio streams from process pipes
            reader = process.stdout
            writer = process.stdin

            yield reader, writer  # type: ignore[misc]

        finally:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=5)
            except asyncio.TimeoutError:
                process.kill()

    @asynccontextmanager
    async def _connect_command(
        self,
        config: HubServerConfig,
    ) -> AsyncGenerator[tuple[asyncio.StreamReader, asyncio.StreamWriter], None]:
        """Connect to a command-based MCP server.

        :param config: Server configuration with command.
        :yields: Tuple of (reader, writer) for stdio communication.

        """
        if not config.command:
            msg = f"Command not specified for server '{config.name}'"
            raise HubClientError(msg)

        # Set up environment
        env = dict(config.environment) if config.environment else None

        process: Process = await asyncio.create_subprocess_exec(
            *config.command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            limit=4 * 1024 * 1024,  # 4 MB — default 64 KB breaks large tool results
        )

        try:
            if process.stdin is None or process.stdout is None:
                msg = "Failed to get process streams"
                raise HubClientError(msg)

            reader = process.stdout
            writer = process.stdin

            yield reader, writer  # type: ignore[misc]

        finally:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=5)
            except asyncio.TimeoutError:
                process.kill()

    @asynccontextmanager
    async def _connect_sse(
        self,
        config: HubServerConfig,
    ) -> AsyncGenerator[tuple[asyncio.StreamReader, asyncio.StreamWriter], None]:
        """Connect to an SSE-based MCP server.

        :param config: Server configuration with URL.
        :yields: Tuple of (reader, writer) for SSE communication.

        """
        # SSE support requires additional dependencies
        # For now, raise not implemented
        msg = "SSE transport not yet implemented"
        raise NotImplementedError(msg)

    async def _initialize_session(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        server_name: str,
    ) -> dict[str, Any]:
        """Initialize MCP session with the server.

        :param reader: Stream reader.
        :param writer: Stream writer.
        :param server_name: Server name for logging.
        :returns: Server capabilities.

        """
        # Send initialize request
        result = await self._call_method(
            reader,
            writer,
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "fuzzforge-hub",
                    "version": "0.1.0",
                },
            },
        )

        # Send initialized notification
        await self._send_notification(reader, writer, "notifications/initialized", {})

        return result

    async def _call_method(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        method: str,
        params: dict[str, Any],
    ) -> dict[str, Any]:
        """Call an MCP method.

        :param reader: Stream reader.
        :param writer: Stream writer.
        :param method: Method name.
        :param params: Method parameters.
        :returns: Method result.

        """
        # Create JSON-RPC request
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        }

        # Send request
        request_line = json.dumps(request) + "\n"
        writer.write(request_line.encode())
        await writer.drain()

        # Read response
        response_line = await asyncio.wait_for(
            reader.readline(),
            timeout=self._timeout,
        )

        if not response_line:
            msg = "Empty response from server"
            raise HubClientError(msg)

        response = json.loads(response_line.decode())

        if "error" in response:
            error = response["error"]
            msg = f"MCP error: {error.get('message', 'Unknown error')}"
            raise HubClientError(msg)

        return response.get("result", {})

    async def _send_notification(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        method: str,
        params: dict[str, Any],
    ) -> None:
        """Send an MCP notification (no response expected).

        :param reader: Stream reader (unused but kept for consistency).
        :param writer: Stream writer.
        :param method: Notification method name.
        :param params: Notification parameters.

        """
        # Create JSON-RPC notification (no id)
        notification = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        }

        notification_line = json.dumps(notification) + "\n"
        writer.write(notification_line.encode())
        await writer.drain()
