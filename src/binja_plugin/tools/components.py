"""Component-tree tools: create components, look them up, and assign functions to them."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, TypedDict

from binaryninja import mcp

from binja_plugin.tools import (
    _MAX_LIMIT,
    _function_entry,
    _FunctionEntry,
    _Resolution,
    _resolve_address_batch,
    _ResolvedFunction,
    _truncate,
    _validate_range,
    _validate_text,
)

if TYPE_CHECKING:
    from binaryninja.binaryview import BinaryView
    from binaryninja.component import Component

# rex_component_* lexical bounds: component names persist in the database and paths are
# echoed back whole in every response, so both get length caps before reaching the core.
_MAX_COMPONENT_NAME_CHARS = 128
_MAX_COMPONENT_PATH_CHARS = 512
# rex_component_get child-component echo cap; functions are paginated instead.
_MAX_COMPONENT_CHILDREN = 256
_MAX_COMPONENT_ADD_FUNCTIONS = 128


class _AddedFunction(_ResolvedFunction):
    added: bool


class _ComponentAddResult(TypedDict):
    path: str
    added_count: int
    applied: int
    failed_count: int
    total: int
    results: list[_AddedFunction]


class _ComponentCreateResult(TypedDict):
    path: str
    display_name: str
    guid: str


class _ChildComponent(TypedDict):
    path: str
    display_name: str
    guid: str


class _ComponentGetResult(TypedDict):
    path: str
    guid: str
    display_name: str
    parent_path: str | None
    functions: list[_FunctionEntry]
    function_count: int
    truncated: bool
    children: list[_ChildComponent]
    children_truncated: bool


def _validate_component_path(parameter: str, path: str) -> str:
    """Lexically validate an absolute component path before handing it to the core."""
    _validate_text(parameter, path, _MAX_COMPONENT_PATH_CHARS, "invalid_params")
    if not path.startswith("/"):
        raise mcp.ToolError(
            "invalid_params", f"{parameter} must be an absolute path starting with '/'"
        )
    if path != "/" and path.endswith("/"):
        raise mcp.ToolError("invalid_params", f"{parameter} must not end with '/'")
    if "//" in path:
        raise mcp.ToolError("invalid_params", f"{parameter} must not contain empty path segments")
    return path


def _resolve_component(view: BinaryView, path: str) -> Component:
    """Return the component at an already-validated path, "/" mapping to the root."""
    if path == "/":
        return view.root_component
    component = view.get_component_by_path(path)
    if component is None:
        raise mcp.ToolError("component_not_found", f"no component at path '{_truncate(path)}'")
    return component


def _component_child_path(parent_path: str, display_name: str) -> str:
    """Join a child's display name onto its parent path; top-level children get "/name"."""
    # Validation guarantees at most one trailing slash — exactly the root's — so
    # removesuffix is an exact match, where a strip-set would act silently on any tail.
    prefix = parent_path.removesuffix("/")
    return f"{prefix}/{display_name}"


def _add_to_component(component: Component, resolution: _Resolution) -> _AddedFunction:
    added = component.add_function(resolution.function)
    return {**resolution.entry, "added": added}


@mcp.tool(destructive=True)
def rex_component_add_functions(
    call: mcp.ToolCall,
    path: str,
    functions: list[str],
) -> _ComponentAddResult:
    """Put functions into a component.

    :param path: Absolute component path; '/' selects the root component.
    :param functions: 1 to 128 address expressions of the functions to add.
    """
    bv = call.binary_view
    _validate_component_path("path", path)
    resolved = _resolve_address_batch(call, bv, functions, _MAX_COMPONENT_ADD_FUNCTIONS)
    component = _resolve_component(bv, path)
    results = [_add_to_component(component, resolution) for resolution in resolved]
    added_count = sum(1 for result in results if result["added"])
    return {
        "path": path,
        "added_count": added_count,
        # The uniform batch-summary keys (see rex_annotate_many); added_count is this
        # tool's legacy name for applied, kept so existing callers do not break.
        "applied": added_count,
        "failed_count": len(results) - added_count,
        "total": len(results),
        "results": results,
    }


@mcp.tool(destructive=True)
def rex_component_create(
    call: mcp.ToolCall,
    name: str,
    parent_path: str = "",
) -> _ComponentCreateResult:
    """Create a component, optionally nested under an existing one.

    :param name: Name of the new component; must not be empty or contain '/'.
    :param parent_path: Absolute parent path; empty or '/' creates a top-level component.
    """
    # Over-cap strings reject with the plugin's per-parameter *_too_large code family,
    # not the integer-argument invalid_params convention, so the same mistake maps to
    # the same code class in every tool.
    _validate_text("name", name, _MAX_COMPONENT_NAME_CHARS, "name_too_large")
    if "/" in name:
        # "/" is the path delimiter, so a name containing one can never be addressed by path.
        raise mcp.ToolError("invalid_params", "name must not contain '/'")
    bv = call.binary_view
    parent: Component | None = None
    if parent_path:
        _validate_component_path("parent_path", parent_path)
        parent = _resolve_component(bv, parent_path)
    component = bv.create_component(name, parent)
    return {
        "path": _component_child_path(parent_path, component.display_name),
        "display_name": _truncate(component.display_name),
        "guid": _truncate(component.guid),
    }


@mcp.tool(read_only=True)
def rex_component_get(
    call: mcp.ToolCall,
    path: str,
    limit: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_LIMIT)] = 100,
    offset: Annotated[int, mcp.Minimum(0)] = 0,
) -> _ComponentGetResult:
    """Look up a component by path and report its members.

    :param path: Absolute component path; '/' selects the root component.
    :param limit: Maximum member functions to return.
    :param offset: Member functions to skip before collecting results.
    """
    _validate_component_path("path", path)
    limit = _validate_range("limit", limit, 0, _MAX_LIMIT)
    offset = _validate_range("offset", offset, 0)
    component = _resolve_component(call.binary_view, path)
    functions = sorted(component.function_list, key=lambda function: function.start)
    total = len(functions)
    children = component.components
    if path == "/":
        parent_path = None
    else:
        parent_path = path.rsplit("/", 1)[0] or "/"
    return {
        "path": path,
        "guid": _truncate(component.guid),
        "display_name": _truncate(component.display_name),
        "parent_path": parent_path,
        "functions": [_function_entry(function) for function in functions[offset : offset + limit]],
        "function_count": total,
        "truncated": offset + limit < total,
        "children": [
            {
                "path": _component_child_path(path, child.display_name),
                "display_name": _truncate(child.display_name),
                "guid": _truncate(child.guid),
            }
            for child in children[:_MAX_COMPONENT_CHILDREN]
        ],
        "children_truncated": len(children) > _MAX_COMPONENT_CHILDREN,
    }
