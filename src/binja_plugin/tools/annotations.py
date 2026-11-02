"""Batch function annotations: names, comments, and prototypes in one undoable transaction."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated, Any

from binaryninja import mcp
from binaryninja.binaryview import BinaryView
from binaryninja.function import Function

from binja_plugin.tools import _truncate

# rex_annotate_many caps: 100 items bound one call's mutation cost and its echoed result
# rows; the string caps bound what reaches the core per field. The name cap is far below
# any sane symbol length, the type cap matches the pattern-string cap (both feed a
# parser), and the comment cap matches the tag-data cap.
_MAX_ANNOTATE_ITEMS = 100
_MAX_ANNOTATE_NAME_CHARS = 256
_MAX_ANNOTATE_COMMENT_CHARS = 65536
_MAX_ANNOTATE_PROTOTYPE_CHARS = 8192
_ANNOTATE_FIELDS = frozenset({"addr", "name", "comment", "prototype"})
# Schema-side description of one rex_annotate_many item. The bundled mcp layer cannot
# describe object arrays structurally: mcp.Schema hands the item through as decoded JSON
# and the handler validates every field, so this schema is what the client sees while
# the checks below are what actually rejects.
_ANNOTATE_ITEMS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "addr": {
            "type": ["integer", "string"],
            "description": "address expression at or inside the function to annotate",
        },
        "name": {"type": "string", "minLength": 1, "maxLength": _MAX_ANNOTATE_NAME_CHARS},
        "comment": {"type": "string", "maxLength": _MAX_ANNOTATE_COMMENT_CHARS},
        "prototype": {"type": "string", "minLength": 1, "maxLength": _MAX_ANNOTATE_PROTOTYPE_CHARS},
    },
    "required": ["addr"],
}


@dataclass
class _AnnotationPlan:
    """One fully validated annotation, staged for the batch transaction's apply phase."""

    function: Function
    name: str | None = None
    comment: str | None = None
    parsed_type: object | None = None


def _annotate_item_error(item: object, message: str) -> dict[str, object]:
    """Result row for an item too broken to carry an address: echo the whole item."""
    return {"addr": _truncate(repr(item)), "ok": False, "error": message}


def _annotate_addr_error(addr_value: object, message: str) -> dict[str, object]:
    """Result row for an item whose address itself failed a check: echo the address."""
    return {"addr": _truncate(str(addr_value)), "ok": False, "error": message}


def _annotate_function_error(address: int, message: str) -> dict[str, object]:
    """Result row for an item that parsed to a known address but failed there."""
    return {"addr": hex(address), "ok": False, "error": message}


def _annotate_resolve(
    call: mcp.ToolCall, bv: BinaryView, item: Any
) -> tuple[dict[str, object], _AnnotationPlan | None]:
    """Validate one annotation item completely, staging a plan only if it can fully apply.

    The type string is parsed up front and discarded until the apply phase, so an item
    can never half-apply: everything that can fail on the item's own content fails here,
    before any mutation is staged.
    """
    if not isinstance(item, dict):
        return _annotate_item_error(item, "each item must be a JSON object"), None
    if "addr" not in item:
        return _annotate_item_error(item, "addr is required"), None
    addr_value = item["addr"]
    if not isinstance(addr_value, (int, str)) or isinstance(addr_value, bool):
        # bool is an int subclass: a JSON true/false address is a caller bug.
        return (
            _annotate_addr_error(
                addr_value, "addr must be an integer or a string address expression"
            ),
            None,
        )
    unknown = sorted(str(key) for key in item if key not in _ANNOTATE_FIELDS)
    if unknown:
        return _annotate_addr_error(addr_value, f"unknown field(s): {', '.join(unknown)}"), None
    try:
        address = call.parse_address(addr_value)
    except Exception as error:
        return _annotate_addr_error(addr_value, f"bad address expression: {error}"), None
    functions = bv.get_functions_containing(address)
    if not functions:
        return (
            _annotate_function_error(address, f"no analyzed function contains {address:#x}"),
            None,
        )
    function = functions[0]
    name = item.get("name")
    comment = item.get("comment")
    if name is not None and (not isinstance(name, str) or not name):
        return _annotate_function_error(address, "name must be a non-empty string"), None
    if name is not None and len(name) > _MAX_ANNOTATE_NAME_CHARS:
        return (
            _annotate_function_error(
                address, f"name exceeds {_MAX_ANNOTATE_NAME_CHARS} characters"
            ),
            None,
        )
    if comment is not None and not isinstance(comment, str):
        return _annotate_function_error(address, "comment must be a string"), None
    if comment is not None and len(comment) > _MAX_ANNOTATE_COMMENT_CHARS:
        return (
            _annotate_function_error(
                address, f"comment exceeds {_MAX_ANNOTATE_COMMENT_CHARS} characters"
            ),
            None,
        )
    prototype = item.get("prototype")
    if prototype is not None and (not isinstance(prototype, str) or not prototype):
        return _annotate_function_error(address, "prototype must be a non-empty string"), None
    if prototype is not None and len(prototype) > _MAX_ANNOTATE_PROTOTYPE_CHARS:
        return (
            _annotate_function_error(
                address, f"prototype exceeds {_MAX_ANNOTATE_PROTOTYPE_CHARS} characters"
            ),
            None,
        )
    parsed_type: object | None = None
    if prototype is not None:
        try:
            parsed_type, _ = bv.parse_type_string(prototype)
        except Exception as error:
            return _annotate_function_error(address, f"bad type: {_truncate(str(error))}"), None
    return (
        {"addr": hex(function.start), "ok": True},
        _AnnotationPlan(function=function, name=name, comment=comment, parsed_type=parsed_type),
    )


@mcp.tool(destructive=True)
def rex_annotate_many(
    call: mcp.ToolCall,
    items: list[Annotated[Any, mcp.Schema(_ANNOTATE_ITEMS_SCHEMA)]],
) -> dict[str, object]:
    """Apply many function annotations in one undoable transaction.

    Batch counterpart of one-at-a-time renaming and commenting: up to 100 items of
    ``{addr, name?, comment?, prototype?}`` in one call. Every item resolves
    before anything is applied; the applying items commit inside a single
    ``bv.undoable_transaction()`` (begin actions, commit on success, revert and re-raise
    on failure), so the whole batch is one undo step that ``rex_undo`` reverses as a
    unit. If a core error escapes mid-apply, the context manager has already reverted
    every change and the response says the batch rolled back.

    Per-item failures never abort the batch: an address with no analyzed function, an
    unparsable address, or an invalid field is one ``{"ok": false}`` row while the other
    items still apply. When every item fails, nothing is applied and no undo step is
    created. Each row echoes the annotated function's start on success (the input may
    have been mid-function or a symbol name) or what was looked up on failure. The
    response summary is the one every batch tool carries — ``applied``, ``failed_count``,
    ``total`` — plus this tool's original ``failed`` count key.

    Annotations are function-level, not instruction-level: an ``addr`` anywhere inside a
    function — mid-function addresses included — annotates that whole function, so the
    comment, user type, and name land on the function itself. Composing with
    per-instruction producers like rex_derived_string_refs therefore collapses their
    output onto containing functions. Items that resolve to the same function apply in
    item order with last write winning: a repeated field is overwritten by the later
    item, and each item still counts as applied.

    ``prototype`` sets the function's user type — its signature: Binary Ninja stores one
    user type per function. The string is parsed per item with the parsed name discarded,
    unlike assigning the ``type`` property, which would also rename the function.

    Per item the apply order is ``comment``, then the prototype, then ``name`` last, so
    an explicit ``name`` has the final word on naming.

    :param items: 1 to 100 objects of ``{addr, name?, comment?, prototype?}``;
        ``addr`` is an address expression (integer or string), the rest are strings.
    """
    bv = call.binary_view
    if not isinstance(items, list):
        raise mcp.ToolError("invalid_params", "items must be a list of annotation objects")
    if not 1 <= len(items) <= _MAX_ANNOTATE_ITEMS:
        raise mcp.ToolError(
            "invalid_params", f"items must contain between 1 and {_MAX_ANNOTATE_ITEMS} entries"
        )
    results: list[dict[str, object]] = []
    staged: list[_AnnotationPlan] = []
    for item in items:
        row, plan = _annotate_resolve(call, bv, item)
        results.append(row)
        if plan is not None:
            staged.append(plan)
    if staged:
        try:
            with bv.undoable_transaction():
                for plan in staged:
                    if plan.comment is not None:
                        plan.function.comment = plan.comment
                    if plan.parsed_type is not None:
                        plan.function.set_user_type(plan.parsed_type)
                    if plan.name is not None:
                        plan.function.name = plan.name
        except Exception as error:
            # undoable_transaction reverted the whole batch core-side before this runs;
            # saying so keeps a caller from retrying a half-applied batch.
            raise mcp.ToolError("annotate_failed", f"batch rolled back: {error}") from None
    applied = sum(1 for row in results if row["ok"] is True)
    # Every batch tool answers the same applied/failed_count/total summary; "failed" is
    # this tool's legacy count key, kept so existing callers do not break.
    return {
        "applied": applied,
        "failed": len(results) - applied,
        "failed_count": len(results) - applied,
        "total": len(results),
        "results": results,
    }
