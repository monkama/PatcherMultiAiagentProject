from typing import Any, Callable, TypeVar

try:
    from strands import tool as strands_tool
except ImportError:
    strands_tool = None

F = TypeVar("F", bound=Callable[..., Any])


def tool(func: F) -> F:
    if strands_tool is not None:
        return strands_tool(func)
    return func
