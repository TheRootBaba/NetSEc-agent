
"""Discover MCP tools and enforce assessment scope before execution."""

import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastmcp.mcp_config import MCPConfig, StdioMCPServer
from langchain.mcp import MCPAdapter
from langchain_core.tools import BaseTool, StructuredTool

from netsec_agent.authorization import AssessmentScope, validate_assessment
from netsec_agent.settings import get_settings

SERVER_PATH = Path(__file__).with_name("nmap_server.py")
APPROVED_TOOL_NAMES = frozenset({"run_nmap_assessment"})


def _guard_tool(tool: BaseTool, scope: AssessmentScope) -> StructuredTool:
    """Wrap a discovered tool so every invocation checks the assessment scope."""

    async def guarded_invoke(target: str, scan_type: str) -> str:
        normalized_target = validate_assessment(target, scan_type, scope)
        return await tool.ainvoke(
            {"target": normalized_target, "scan_type": scan_type}
        )

    return StructuredTool.from_function(
        coroutine=guarded_invoke,
        name=tool.name,
        description=tool.description,
        args_schema=tool.args_schema,
    )


@asynccontextmanager
async def assessment_tools(
    scope: AssessmentScope,
) -> AsyncIterator[list[BaseTool]]:
    """Yield authorized tools while the configured MCP server is connected."""
    settings = get_settings()

    server = StdioMCPServer(
        command=sys.executable,
        args=[str(SERVER_PATH)],
        env={
            "NETSEC_AUTHORIZED": str(scope.authorized).lower(),
            "NETSEC_AUTHORIZED_TARGETS": ",".join(scope.approved_targets),
            "NMAP_PATH": settings.nmap_path,
        },
        cwd=str(SERVER_PATH.parents[2]),
        timeout=10,
    )
    config = MCPConfig(mcpServers={"nmap": server})

    async with MCPAdapter(config) as adapter:
        discovered = await adapter.list_tools()
        approved = [
            tool for tool in discovered if tool.name in APPROVED_TOOL_NAMES
        ]

        if not approved:
            available = sorted(tool.name for tool in discovered)
            raise RuntimeError(
                f"No approved MCP tools discovered. Available tools: {available}"
            )

        yield [_guard_tool(tool, scope) for tool in approved]
