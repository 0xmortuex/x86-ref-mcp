"""MCP stdio handshake smoke test: spawns the real server subprocess over
stdio, initializes a client session, and checks the tool list.
"""

import sys

import pytest

pytest.importorskip("mcp")

from mcp import ClientSession  # noqa: E402
from mcp.client.stdio import StdioServerParameters, stdio_client  # noqa: E402

EXPECTED_TOOLS = {
    "x86_insn",
    "x86_flags",
    "x86_exceptions",
    "x86_decode",
    "x86_register",
    "x86_msr",
    "x86_vector",
    "x86_search",
    "x86_about",
}


@pytest.mark.anyio
async def test_stdio_handshake_lists_expected_tools():
    params = StdioServerParameters(command=sys.executable, args=["-m", "x86_ref_mcp"])
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        init_result = await session.initialize()
        assert init_result.server_info.name == "x86-ref"

        tools = await session.list_tools()
        names = {t.name for t in tools.tools}
        assert names == EXPECTED_TOOLS, (
            f"missing: {EXPECTED_TOOLS - names}, unexpected: {names - EXPECTED_TOOLS}"
        )


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.anyio
async def test_instructive_errors_reach_the_agent():
    """MCPServer hides any exception that isn't a ToolError behind a generic
    "Error executing tool X"; our messages must survive the trip over stdio."""
    params = StdioServerParameters(command=sys.executable, args=["-m", "x86_ref_mcp"])
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()

        result = await session.call_tool("x86_insn", {"mnemonic": "frobnicate"})
        assert result.is_error
        assert "no x86 instruction 'frobnicate'" in result.content[0].text

        result = await session.call_tool("x86_register", {"name": "cr9"})
        assert result.is_error and "no layout for 'cr9'" in result.content[0].text
