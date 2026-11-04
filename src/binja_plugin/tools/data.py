"""Address-keyed cross-references: what code and data point at an address."""

from __future__ import annotations

from typing import Annotated, Any

from binaryninja import mcp
from binaryninja.enums import LowLevelILOperation

from binja_plugin.tools import _MAX_LIMIT, _paginate, _truncate, _validate_range

_CALL_OPERATIONS = (
    LowLevelILOperation.LLIL_CALL,
    LowLevelILOperation.LLIL_TAILCALL,
)


def _xref_kind(reference: Any) -> str:
    instruction = reference.llil
    if instruction is not None and instruction.operation in _CALL_OPERATIONS:
        return "call"
    return "code"


def _code_ref_entry(reference: Any) -> dict[str, object]:
    return {
        "function_start": None if reference.function is None else hex(reference.function.start),
        "function_name": None if reference.function is None else _truncate(reference.function.name),
        "arch": None if reference.arch is None else reference.arch.name,
        "address": hex(reference.address),
        "kind": _xref_kind(reference),
    }


@mcp.tool(read_only=True)
def rex_xrefs_to(
    call: mcp.ToolCall,
    addr: mcp.Address,
    limit: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_LIMIT)] = 100,
    offset: Annotated[int, mcp.Minimum(0)] = 0,
) -> dict[str, object]:
    """Code and data references to an address; either list may be empty.

    :param addr: Referenced address.
    :param limit: Maximum references to return.
    :param offset: References to skip before collecting results.
    """
    bv = call.binary_view
    limit = _validate_range("limit", limit, 0, _MAX_LIMIT)
    offset = _validate_range("offset", offset, 0)
    # The core's reference order is not guaranteed sorted; sort before slicing so the
    # window is address-ordered, not a first-fit subset of whatever the core yielded.
    code_refs = sorted(
        bv.get_code_refs(addr, max_items=_MAX_LIMIT + 1), key=lambda ref: ref.address
    )
    data_refs = sorted(bv.get_data_refs(addr, max_items=_MAX_LIMIT + 1))
    combined = [("code", reference) for reference in code_refs] + [
        ("data", source) for source in data_refs
    ]
    page, total, truncated = _paginate(combined, offset, limit)
    return {
        "total": total,
        "truncated": truncated,
        "code_refs": [_code_ref_entry(reference) for kind, reference in page if kind == "code"],
        "data_refs": [{"source": hex(source)} for kind, source in page if kind == "data"],
    }
