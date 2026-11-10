"""Batch function annotations: names, comments, and prototypes in one undoable transaction."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Annotated, Final, NotRequired, TypedDict

from binaryninja import mcp
from binaryninja.binaryview import BinaryView
from binaryninja.function import Function

from binja_plugin.tools import _is_json_object, _truncate

if TYPE_CHECKING:
    from binaryninja.types import Type

# rex_annotate_many caps: 128 items bound one call's mutation cost and its echoed result
# rows; the string caps bound what reaches the core per field. The name cap is far below
# any sane symbol length, the type cap matches the pattern-string cap (both feed a
# parser), and the comment cap matches the tag-data cap.
_MAX_ANNOTATE_ITEMS: Final = 128
_MAX_ANNOTATE_NAME_CHARS: Final = 256
_MAX_ANNOTATE_COMMENT_CHARS: Final = 65536
_MAX_ANNOTATE_PROTOTYPE_CHARS: Final = 8192
_ANNOTATE_FIELDS: Final = frozenset({"addr", "name", "comment", "prototype"})
# Schema-side description of one rex_annotate_many item. The bundled mcp layer cannot
# describe object arrays structurally: mcp.Schema hands the item through as decoded JSON
# and the handler validates every field, so this schema is what the client sees while
# the checks below are what actually rejects.
_ANNOTATE_ITEMS_SCHEMA: Final[dict[str, object]] = {
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


class _AnnotationRow(TypedDict):
    addr: str
    ok: bool
    error: NotRequired[str]


class _AnnotateManyResult(TypedDict):
    applied: int
    failed: int
    failed_count: int
    total: int
    results: list[_AnnotationRow]


@dataclass(frozen=True, slots=True)
class _AnnotationFields:
    name: str | None
    comment: str | None
    prototype: str | None


@dataclass(frozen=True, slots=True)
class _AnnotationPlan:
    """One fully validated annotation, staged for the batch transaction's apply phase."""

    function: Function
    # The parsed address the item named: comments land exactly here, while name and
    # prototype are function-level and always apply to the whole function.
    address: int
    name: str | None = None
    comment: str | None = None
    parsed_type: Type | None = None


def _annotate_item_error(item: object, message: str) -> _AnnotationRow:
    """Result row for an item too broken to carry an address: echo the whole item."""
    return {"addr": _truncate(repr(item)), "ok": False, "error": message}


def _annotate_addr_error(addr_value: object, message: str) -> _AnnotationRow:
    """Result row for an item whose address itself failed a check: echo the address."""
    return {"addr": _truncate(str(addr_value)), "ok": False, "error": message}


def _annotate_function_error(address: int, message: str) -> _AnnotationRow:
    """Result row for an item that parsed to a known address but failed there."""
    return {"addr": hex(address), "ok": False, "error": message}


def _annotate_fields(item: dict[str, object], address: int) -> _AnnotationFields | _AnnotationRow:
    """The validated optional fields, or the first error among them.

    Fields are checked in name, comment, prototype order so a multi-bad item reports
    the same single error the item would have hit first before the split.
    """
    name = item.get("name")
    if name is not None:
        if not isinstance(name, str) or not name:
            return _annotate_function_error(address, "name must be a non-empty string")
        if len(name) > _MAX_ANNOTATE_NAME_CHARS:
            return _annotate_function_error(
                address, f"name exceeds {_MAX_ANNOTATE_NAME_CHARS} characters"
            )
    comment = item.get("comment")
    if comment is not None:
        if not isinstance(comment, str):
            return _annotate_function_error(address, "comment must be a string")
        if len(comment) > _MAX_ANNOTATE_COMMENT_CHARS:
            return _annotate_function_error(
                address, f"comment exceeds {_MAX_ANNOTATE_COMMENT_CHARS} characters"
            )
    prototype = item.get("prototype")
    if prototype is not None:
        if not isinstance(prototype, str) or not prototype:
            return _annotate_function_error(address, "prototype must be a non-empty string")
        if len(prototype) > _MAX_ANNOTATE_PROTOTYPE_CHARS:
            return _annotate_function_error(
                address, f"prototype exceeds {_MAX_ANNOTATE_PROTOTYPE_CHARS} characters"
            )
    return _AnnotationFields(name=name, comment=comment, prototype=prototype)


def _annotate_apply_plans(bv: BinaryView, staged: list[_AnnotationPlan]) -> None:
    """Apply every staged plan inside one undoable transaction."""
    try:
        with bv.undoable_transaction():
            for plan in staged:
                if plan.comment is not None:
                    # The comment lands at the exact address the item named, not as the
                    # function-level comment snapped to the start.
                    plan.function.set_comment_at(plan.address, plan.comment)
                if plan.parsed_type is not None:
                    plan.function.set_user_type(plan.parsed_type)
                # Name last, so an explicit name has the final word on naming.
                if plan.name is not None:
                    plan.function.name = plan.name
    except Exception as error:
        # undoable_transaction reverted the whole batch core-side before this runs;
        # saying so keeps a caller from retrying a half-applied batch.
        raise mcp.ToolError("annotate_failed", f"batch rolled back: {error}") from None


def _annotate_resolve(
    call: mcp.ToolCall, bv: BinaryView, item: object
) -> tuple[_AnnotationRow, _AnnotationPlan | None]:
    """Validate one annotation item completely, staging a plan only if it can fully apply."""
    if not _is_json_object(item):
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
    fields = _annotate_fields(item, address)
    if not isinstance(fields, _AnnotationFields):
        return fields, None
    parsed_type: Type | None = None
    if fields.prototype is not None:
        try:
            parsed_type, _ = bv.parse_type_string(fields.prototype)
        except Exception as error:
            return _annotate_function_error(address, f"bad type: {_truncate(str(error))}"), None
    function = functions[0]
    # A comment lands at the exact address the item named; the other fields are
    # function-level and apply to the start, so the row echoes where it landed.
    annotated = address if fields.comment is not None else function.start
    return (
        {"addr": hex(annotated), "ok": True},
        _AnnotationPlan(
            function=function,
            address=address,
            name=fields.name,
            comment=fields.comment,
            parsed_type=parsed_type,
        ),
    )


@mcp.tool(destructive=True)
def rex_annotate_many(
    call: mcp.ToolCall,
    items: list[Annotated[object, mcp.Schema(_ANNOTATE_ITEMS_SCHEMA)]],
) -> _AnnotateManyResult:
    """Apply many function annotations in one undoable transaction.

    :param items: 1 to 128 annotation objects; the item schema defines the fields.
    """
    bv = call.binary_view
    if not isinstance(items, list):
        raise mcp.ToolError("invalid_params", "items must be a list of annotation objects")
    if not 1 <= len(items) <= _MAX_ANNOTATE_ITEMS:
        raise mcp.ToolError(
            "invalid_params", f"items must contain between 1 and {_MAX_ANNOTATE_ITEMS} entries"
        )
    results: list[_AnnotationRow] = []
    staged: list[_AnnotationPlan] = []
    for item in items:
        row, plan = _annotate_resolve(call, bv, item)
        results.append(row)
        if plan is not None:
            staged.append(plan)
    if staged:
        _annotate_apply_plans(bv, staged)
    applied = sum(1 for row in results if row["ok"])
    # Every batch tool answers the same applied/failed_count/total summary; "failed" is
    # this tool's legacy count key, kept so existing callers do not break.
    return {
        "applied": applied,
        "failed": len(results) - applied,
        "failed_count": len(results) - applied,
        "total": len(results),
        "results": results,
    }
