"""Component-tree tools: create components, look them up, and assign functions to them."""

from __future__ import annotations

from typing import Annotated, Any

from binaryninja import mcp
from binaryninja.function import Function

from binja_plugin.tools import (
    _MAX_LIMIT,
    _require_analyzed_function,
    _truncate,
    _validate_range,
    _validate_text,
)

# rex_component_* lexical bounds: component names persist in the database and paths are
# echoed back whole in every response, so both get length caps before reaching the core.
_MAX_COMPONENT_NAME_CHARS = 128
_MAX_COMPONENT_PATH_CHARS = 512
# rex_component_get child-component echo cap; functions are paginated instead.
_MAX_COMPONENT_CHILDREN = 200
_MAX_COMPONENT_ADD_FUNCTIONS = 64


def _validate_component_path(parameter: str, path: str) -> str:
    """Lexically validate an absolute component path before handing it to the core.

    Path lookups are absolute from the root component and "/"-delimited, so empty,
    relative, trailing-slash and empty-segment paths can never resolve as written;
    rejecting them here keeps the core lookup and the echoed path well-defined. Exactly
    "/" selects the root component, which is resolved through the root_component
    property rather than the undocumented "/" pathname lookup.
    """
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


def _resolve_component(call: mcp.ToolCall, path: str) -> Any:
    """Return the component at an already-validated path, "/" mapping to the root."""
    if path == "/":
        return call.binary_view.root_component
    component = call.binary_view.get_component_by_path(path)
    if component is None:
        raise mcp.ToolError("component_not_found", f"no component at path '{_truncate(path)}'")
    return component


def _component_child_path(parent_path: str, display_name: str) -> str:
    """Join a child's display name onto its parent path; top-level children get "/name"."""
    # Validation guarantees at most one trailing slash — exactly the root's — so
    # removesuffix is an exact match, where a strip-set would act silently on any tail.
    prefix = parent_path.removesuffix("/")
    return f"{prefix}/{display_name}"


@mcp.tool(destructive=True)
def rex_component_add_functions(
    call: mcp.ToolCall,
    path: str,
    functions: list[str],
) -> dict[str, object]:
    """Put functions into a component.

    Destructive: membership changes persist in the analysis database, and the core may
    relocate a function that already belongs to another component. Every address
    expression is resolved and checked before anything is added, so one bad entry
    rejects the whole call and the component is left untouched. Each result reports the
    core's own success flag, so a declined add is visible instead of swallowed. The
    response summary is the one every batch tool carries: ``applied``, ``failed_count``,
    ``total`` (``added_count`` is this tool's original name for ``applied``).

    :param path: Absolute component path ("/" for the root component).
    :param functions: Address expressions of the functions to add; 1 to 64 entries.
    """
    bv = call.binary_view
    _validate_component_path("path", path)
    if not isinstance(functions, list):
        raise mcp.ToolError("invalid_params", "functions must be a list of address expressions")
    if not 1 <= len(functions) <= _MAX_COMPONENT_ADD_FUNCTIONS:
        raise mcp.ToolError(
            "invalid_params",
            "functions must contain between 1 and "
            f"{_MAX_COMPONENT_ADD_FUNCTIONS} address expressions",
        )
    resolved: list[Function] = []
    for index, entry in enumerate(functions):
        if not isinstance(entry, str):
            raise mcp.ToolError(
                "invalid_params", f"functions[{index}] must be a string address expression"
            )
        try:
            address = call.parse_address(entry)
        except Exception as error:
            raise mcp.ToolError(
                "invalid_params", f"bad address expression '{_truncate(entry)}': {error}"
            ) from None
        resolved.append(_require_analyzed_function(bv, address))
    component = _resolve_component(call, path)
    results = []
    for function in resolved:
        added = component.add_function(function)
        results.append(
            {"start": hex(function.start), "name": _truncate(function.name), "added": added}
        )
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
) -> dict[str, object]:
    """Create a component, optionally nested under an existing one.

    Destructive: components persist in the analysis database. Duplicate sibling names
    are kept distinct by the core with an automatic " (1)"-style suffix, and the
    response reports the created component's canonical absolute path — built from its
    display name, which is what path lookups match — so the suffix is visible
    immediately. An empty parent_path creates a top-level component and "/" parents it
    on the root.

    :param name: Name of the new component; must not be empty or contain '/'.
    :param parent_path: Absolute path of the parent component (empty or "/" for top-level).
    """
    # Over-cap strings reject with the plugin's per-parameter *_too_large code family,
    # not the integer-argument invalid_params convention, so the same mistake maps to
    # the same code class in every tool.
    _validate_text("name", name, _MAX_COMPONENT_NAME_CHARS, "name_too_large")
    if "/" in name:
        # "/" is the path delimiter, so a name containing one can never be addressed by path.
        raise mcp.ToolError("invalid_params", "name must not contain '/'")
    bv = call.binary_view
    parent: Any = None
    if parent_path:
        _validate_component_path("parent_path", parent_path)
        parent = _resolve_component(call, parent_path)
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
) -> dict[str, object]:
    """Look up a component by path and report its members.

    The path is absolute from the root component and matched against display names,
    exactly as the core's own pathname lookup resolves it; "/" selects the root
    component, whose children are the top-level entries of the module tree. Member
    functions are sorted by start address so a page is a true window of the
    address-ordered listing, and child components are capped at 200 entries with
    children_truncated marking the rest.

    :param path: Absolute component path ("/" for the root component).
    :param limit: Maximum number of member functions to return (0 to 500).
    :param offset: Number of member functions to skip before collecting results (>= 0).
    """
    _validate_component_path("path", path)
    limit = _validate_range("limit", limit, 0, _MAX_LIMIT)
    offset = _validate_range("offset", offset, 0)
    component = _resolve_component(call, path)
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
        "functions": [
            {"start": hex(function.start), "name": _truncate(function.name)}
            for function in functions[offset : offset + limit]
        ],
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
