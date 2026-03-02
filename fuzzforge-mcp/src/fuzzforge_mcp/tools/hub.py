"""MCP Hub tools for FuzzForge MCP server.

This module provides tools for interacting with external MCP servers
through the FuzzForge hub. AI agents can:
- List available hub servers and their tools
- Discover tools from hub servers
- Execute hub tools

"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError

from fuzzforge_common.hub import HubExecutor, HubServerConfig, HubServerType
from fuzzforge_mcp.dependencies import get_settings

mcp: FastMCP = FastMCP()

# Global hub executor instance (lazy initialization)
_hub_executor: HubExecutor | None = None


def _get_hub_executor() -> HubExecutor:
    """Get or create the hub executor instance.

    :returns: Hub executor instance.
    :raises ToolError: If hub is disabled.

    """
    global _hub_executor

    settings = get_settings()

    if not settings.hub.enabled:
        msg = "MCP Hub is disabled. Enable it via FUZZFORGE_HUB__ENABLED=true"
        raise ToolError(msg)

    if _hub_executor is None:
        config_path = settings.hub.config_path
        _hub_executor = HubExecutor(
            config_path=config_path,
            timeout=settings.hub.timeout,
        )

    return _hub_executor


@mcp.tool
async def list_hub_servers() -> dict[str, Any]:
    """List all registered MCP hub servers.

    Returns information about configured hub servers, including
    their connection type, status, and discovered tool count.

    :return: Dictionary with list of hub servers.

    """
    try:
        executor = _get_hub_executor()
        servers = executor.list_servers()

        return {
            "servers": servers,
            "count": len(servers),
            "enabled_count": len([s for s in servers if s["enabled"]]),
        }

    except Exception as e:
        if isinstance(e, ToolError):
            raise
        msg = f"Failed to list hub servers: {e}"
        raise ToolError(msg) from e


@mcp.tool
async def discover_hub_tools(server_name: str | None = None) -> dict[str, Any]:
    """Discover tools from hub servers.

    Connects to hub servers and retrieves their available tools.
    If server_name is provided, only discovers from that server.
    Otherwise discovers from all enabled servers.

    :param server_name: Optional specific server to discover from.
    :return: Dictionary with discovered tools.

    """
    try:
        executor = _get_hub_executor()

        if server_name:
            tools = await executor.discover_server_tools(server_name)
            return {
                "server": server_name,
                "tools": [
                    {
                        "identifier": t.identifier,
                        "name": t.name,
                        "description": t.description,
                        "parameters": [p.model_dump() for p in t.parameters],
                    }
                    for t in tools
                ],
                "count": len(tools),
            }
        else:
            results = await executor.discover_all_tools()
            all_tools = []
            for server, tools in results.items():
                for tool in tools:
                    all_tools.append({
                        "identifier": tool.identifier,
                        "name": tool.name,
                        "server": server,
                        "description": tool.description,
                        "parameters": [p.model_dump() for p in tool.parameters],
                    })

            return {
                "servers_discovered": len(results),
                "tools": all_tools,
                "count": len(all_tools),
            }

    except Exception as e:
        if isinstance(e, ToolError):
            raise
        msg = f"Failed to discover hub tools: {e}"
        raise ToolError(msg) from e


@mcp.tool
async def list_hub_tools() -> dict[str, Any]:
    """List all discovered hub tools.

    Returns tools that have been previously discovered from hub servers.
    Run discover_hub_tools first if no tools are listed.

    :return: Dictionary with list of discovered tools.

    """
    try:
        executor = _get_hub_executor()
        tools = executor.list_tools()

        return {
            "tools": tools,
            "count": len(tools),
        }

    except Exception as e:
        if isinstance(e, ToolError):
            raise
        msg = f"Failed to list hub tools: {e}"
        raise ToolError(msg) from e


@mcp.tool
async def execute_hub_tool(
    identifier: str,
    arguments: dict[str, Any] | None = None,
    timeout: int | None = None,
) -> dict[str, Any]:
    """Execute a tool from a hub server.

    :param identifier: Tool identifier (format: hub:server:tool or server:tool).
    :param arguments: Tool arguments matching the tool's input schema.
    :param timeout: Optional execution timeout in seconds.
    :return: Tool execution result.

    Example identifiers:
    - "hub:nmap:nmap_scan"
    - "nmap:nmap_scan"
    - "hub:nuclei:nuclei_scan"

    """
    try:
        executor = _get_hub_executor()

        result = await executor.execute_tool(
            identifier=identifier,
            arguments=arguments or {},
            timeout=timeout,
        )

        return result.to_dict()

    except Exception as e:
        if isinstance(e, ToolError):
            raise
        msg = f"Hub tool execution failed: {e}"
        raise ToolError(msg) from e


@mcp.tool
async def get_hub_tool_schema(identifier: str) -> dict[str, Any]:
    """Get the input schema for a hub tool.

    Returns the JSON Schema that describes the tool's expected arguments.

    :param identifier: Tool identifier (format: hub:server:tool or server:tool).
    :return: JSON Schema for the tool's input.

    """
    try:
        executor = _get_hub_executor()
        schema = executor.get_tool_schema(identifier)

        if schema is None:
            msg = f"Tool '{identifier}' not found. Run discover_hub_tools first."
            raise ToolError(msg)

        return {
            "identifier": identifier,
            "schema": schema,
        }

    except Exception as e:
        if isinstance(e, ToolError):
            raise
        msg = f"Failed to get tool schema: {e}"
        raise ToolError(msg) from e


@mcp.tool
async def add_hub_server(
    name: str,
    server_type: str,
    image: str | None = None,
    command: list[str] | None = None,
    url: str | None = None,
    category: str | None = None,
    description: str | None = None,
    capabilities: list[str] | None = None,
    environment: dict[str, str] | None = None,
    volumes: list[str] | None = None,
) -> dict[str, Any]:
    """Add a new MCP server to the hub.

    Register a new external MCP server that can be used for tool discovery
    and execution. Servers can be Docker images, local commands, or SSE endpoints.

    :param name: Unique name for the server (e.g., "nmap", "nuclei").
    :param server_type: Connection type ("docker", "command", or "sse").
    :param image: Docker image name (for docker type).
    :param command: Command and args (for command type).
    :param url: SSE endpoint URL (for sse type).
    :param category: Category for grouping (e.g., "reconnaissance").
    :param description: Human-readable description.
    :param capabilities: Docker capabilities to add (e.g., ["NET_RAW"]).
    :param environment: Environment variables to pass.
    :param volumes: Docker volume mounts (e.g., ["~/.fuzzforge/hub/workspace:/data"]).
    :return: Information about the added server.

    Examples:
    - Docker: add_hub_server("nmap", "docker", image="nmap-mcp:latest", capabilities=["NET_RAW"])
    - Command: add_hub_server("custom", "command", command=["python", "server.py"])

    """
    try:
        executor = _get_hub_executor()

        # Parse server type
        try:
            stype = HubServerType(server_type)
        except ValueError:
            msg = f"Invalid server type: {server_type}. Use 'docker', 'command', or 'sse'."
            raise ToolError(msg) from None

        # Validate required fields based on type
        if stype == HubServerType.DOCKER and not image:
            msg = "Docker image required for docker type"
            raise ToolError(msg)
        if stype == HubServerType.COMMAND and not command:
            msg = "Command required for command type"
            raise ToolError(msg)
        if stype == HubServerType.SSE and not url:
            msg = "URL required for sse type"
            raise ToolError(msg)

        config = HubServerConfig(
            name=name,
            type=stype,
            image=image,
            command=command,
            url=url,
            category=category,
            description=description,
            capabilities=capabilities or [],
            environment=environment or {},
            volumes=volumes or [],
        )

        server = executor.add_server(config)

        return {
            "success": True,
            "server": {
                "name": server.name,
                "identifier": server.identifier,
                "type": server.config.type.value,
                "enabled": server.config.enabled,
            },
            "message": f"Server '{name}' added. Use discover_hub_tools('{name}') to discover its tools.",
        }

    except ValueError as e:
        msg = f"Failed to add server: {e}"
        raise ToolError(msg) from e
    except Exception as e:
        if isinstance(e, ToolError):
            raise
        msg = f"Failed to add hub server: {e}"
        raise ToolError(msg) from e
