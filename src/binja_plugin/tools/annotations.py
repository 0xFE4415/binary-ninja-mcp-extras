"""Batch function annotations: names, comments, and prototypes in one undoable transaction."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Annotated, NotRequired, TypedDict

from binaryninja import mcp
from binaryninja.binaryview import BinaryView
from binaryninja.function import Function
from binaryninja.types import Symbol

from binja_plugin.tools import (
    _containment_miss,
    _is_json_object,
    _nul_message,
    _resolve_containing,
    _resolved_entry,
    _ResolvedFunction,
    _truncate,
)

if TYPE_CHECKING:
    from binaryninja.types import Type

# The prototype cap matches the pattern cap (both feed a parser), the comment cap the tag cap.
_MAX_ANNOTATE_ITEMS = 128
_MAX_ANNOTATE_NAME_CHARS = 256
_MAX_ANNOTATE_COMMENT_CHARS = 65536
_MAX_ANNOTATE_PROTOTYPE_CHARS = 8192
_ANNOTATE_FIELDS = frozenset({"addr", "name", "comment", "prototype"})
# The mcp layer cannot describe object arrays: the client sees this, the handler checks.
_ANNOTATE_ITEMS_SCHEMA: dict[str, object] = {
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
    function: NotRequired[_ResolvedFunction]
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
    containing: list[Function]
    # Comments land at this exact address; name and prototype apply to the whole function.
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


def _addr_value_error(addr_value: object) -> str | None:
    if not isinstance(addr_value, (int, str)) or isinstance(addr_value, bool):
        # bool is an int subclass: a JSON true/false address is a caller bug.
        return "addr must be an integer or a string address expression"
    if isinstance(addr_value, str) and "\x00" in addr_value:
        return _nul_message("addr")
    return None


def _required_text_error(field: str, value: object, max_chars: int) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        return f"{field} must be a non-empty string"
    if "\x00" in value:
        return _nul_message(field)
    if len(value) > max_chars:
        return f"{field} exceeds {max_chars} characters"
    return None


def _optional_text_error(field: str, value: object, max_chars: int) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        return f"{field} must be a string"
    if "\x00" in value:
        return _nul_message(field)
    if len(value) > max_chars:
        return f"{field} exceeds {max_chars} characters"
    return None


def _optional_text(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _annotate_fields(item: dict[str, object], address: int) -> _AnnotationFields | _AnnotationRow:
    # Checked in name, comment, prototype order: a multi-bad item reports its first error.
    name = item.get("name")
    comment = item.get("comment")
    prototype = item.get("prototype")
    error = (
        _required_text_error("name", name, _MAX_ANNOTATE_NAME_CHARS)
        or _optional_text_error("comment", comment, _MAX_ANNOTATE_COMMENT_CHARS)
        or _required_text_error("prototype", prototype, _MAX_ANNOTATE_PROTOTYPE_CHARS)
    )
    if error is not None:
        return _annotate_function_error(address, error)
    return _AnnotationFields(
        name=_optional_text(name),
        comment=_optional_text(comment),
        prototype=_optional_text(prototype),
    )


def _annotate_rename(bv: BinaryView, function: Function, name: str) -> None:
    current = function.symbol
    renamed = Symbol(
        current.type,
        function.start,
        name,
        binding=current.binding,
        namespace=current.namespace,
        ordinal=current.ordinal,
    )
    bv.define_user_symbol(renamed)


def _annotate_apply_plans(bv: BinaryView, staged: list[_AnnotationPlan]) -> None:
    """Apply every staged plan inside one undoable transaction."""
    try:
        with bv.undoable_transaction():
            for plan in staged:
                if plan.comment is not None:
                    plan.function.set_comment_at(plan.address, plan.comment)
                if plan.parsed_type is not None:
                    plan.function.set_user_type(plan.parsed_type)
                # Name last, so an explicit name has the final word on naming.
                if plan.name is not None:
                    _annotate_rename(bv, plan.function, plan.name)
    except Exception as error:
        # The transaction already reverted the batch; saying so stops a retry of a half-applied one.
        raise mcp.ToolError("annotate_failed", f"batch rolled back: {error}") from None


def _annotate_resolve(
    call: mcp.ToolCall, bv: BinaryView, item: object
) -> _AnnotationRow | _AnnotationPlan:
    """Validate one annotation item completely: an error row, or a plan that can fully apply."""
    if not _is_json_object(item):
        return _annotate_item_error(item, "each item must be a JSON object")
    if "addr" not in item:
        return _annotate_item_error(item, "addr is required")
    addr_value = item["addr"]
    addr_error = _addr_value_error(addr_value)
    if addr_error is not None:
        return _annotate_addr_error(addr_value, addr_error)
    unknown = sorted(str(key) for key in item if key not in _ANNOTATE_FIELDS)
    if unknown:
        return _annotate_addr_error(addr_value, f"unknown field(s): {', '.join(unknown)}")
    try:
        address = call.parse_address(addr_value)
    except Exception as error:
        return _annotate_addr_error(addr_value, f"bad address expression: {error}")
    containing = bv.get_functions_containing(address)
    if not containing:
        _, message = _containment_miss(bv, address, "analyzed function")
        return _annotate_function_error(address, message)
    fields = _annotate_fields(item, address)
    if not isinstance(fields, _AnnotationFields):
        return fields
    parsed_type: Type | None = None
    if fields.prototype is not None:
        try:
            parsed_type, _ = bv.parse_type_string(fields.prototype)
        except Exception as error:
            return _annotate_function_error(address, f"bad type: {_truncate(str(error))}")
    return _AnnotationPlan(
        function=_resolve_containing(bv, containing).function,
        containing=containing,
        address=address,
        name=fields.name,
        comment=fields.comment,
        parsed_type=parsed_type,
    )


def _applied_row(bv: BinaryView, plan: _AnnotationPlan) -> _AnnotationRow:
    """Row for an applied plan, read after the batch so it shows the function's new name."""
    # A comment lands at the named address, other fields at the function start; the row echoes it.
    annotated = plan.address if plan.comment is not None else plan.function.start
    return {
        "addr": hex(annotated),
        "ok": True,
        "function": _resolved_entry(bv, plan.function, plan.containing),
    }


@mcp.tool(destructive=True)
def rex_annotate_many(
    call: mcp.ToolCall,
    items: list[Annotated[object, mcp.Schema(_ANNOTATE_ITEMS_SCHEMA)]],
) -> _AnnotateManyResult:
    """Apply many function annotations in one undoable transaction. Writes; one rex_undo reverts it.

    :param items: 1 to 128 annotation objects; the item schema defines the fields.
    """
    bv = call.binary_view
    if not isinstance(items, list):
        raise mcp.ToolError("invalid_params", "items must be a list of annotation objects")
    if not 1 <= len(items) <= _MAX_ANNOTATE_ITEMS:
        raise mcp.ToolError(
            "invalid_params", f"items must contain between 1 and {_MAX_ANNOTATE_ITEMS} entries"
        )
    resolved = [_annotate_resolve(call, bv, item) for item in items]
    staged = [outcome for outcome in resolved if isinstance(outcome, _AnnotationPlan)]
    if staged:
        _annotate_apply_plans(bv, staged)
    results: list[_AnnotationRow] = []
    for outcome in resolved:
        if isinstance(outcome, _AnnotationPlan):
            results.append(_applied_row(bv, outcome))
        else:
            results.append(outcome)
    applied = sum(1 for row in results if row["ok"])
    # "failed" is this tool's legacy count key, kept so existing callers do not break.
    return {
        "applied": applied,
        "failed": len(results) - applied,
        "failed_count": len(results) - applied,
        "total": len(results),
        "results": results,
    }
