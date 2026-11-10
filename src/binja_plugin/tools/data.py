"""Mapped-memory reads, relocation inspection, and address-keyed cross-references."""

from __future__ import annotations

from itertools import chain
from typing import TYPE_CHECKING, Annotated, Literal, TypedDict

from binaryninja import mcp
from binaryninja.enums import LowLevelILOperation

from binja_plugin.tools import _MAX_LIMIT, _paginate, _truncate, _validate_range

if TYPE_CHECKING:
    from binaryninja.binaryview import ReferenceSource, Relocation

_MAX_DATA_READ_BYTES = 0x100000

_CALL_OPERATIONS = (
    LowLevelILOperation.LLIL_CALL,
    LowLevelILOperation.LLIL_TAILCALL,
)


class _CodeReferenceEntry(TypedDict):
    function_start: str | None
    function_name: str | None
    arch: str | None
    address: str
    kind: Literal["call", "code"]


class _RelocationEntry(TypedDict):
    address: str
    size: int
    type: str
    addend: int
    implicit_addend: bool
    pc_relative: bool
    target: str
    reloc: str
    symbol: str | None


class _DataReference(TypedDict):
    source: str


class _XrefsToResult(TypedDict):
    total: int
    truncated: bool
    code_refs: list[_CodeReferenceEntry]
    data_refs: list[_DataReference]


class _DataReadResult(TypedDict):
    address: str
    length: int
    bytes_read: int
    data: str
    complete: bool


class _RelocationAtResult(TypedDict):
    address: str
    count: int
    relocations: list[_RelocationEntry]


def _xref_kind(reference: ReferenceSource) -> Literal["call", "code"]:
    instruction = reference.llil
    if instruction is not None and instruction.operation in _CALL_OPERATIONS:
        return "call"
    return "code"


def _code_ref_entry(reference: ReferenceSource) -> _CodeReferenceEntry:
    return {
        "function_start": None if reference.function is None else hex(reference.function.start),
        "function_name": None if reference.function is None else _truncate(reference.function.name),
        "arch": None if reference.arch is None else reference.arch.name,
        "address": hex(reference.address),
        "kind": _xref_kind(reference),
    }


def _relocation_entry(relocation: Relocation) -> _RelocationEntry:
    info = relocation.info
    symbol = relocation.symbol
    return {
        "address": hex(info.address),
        "size": info.size,
        "type": info.type.name,
        "addend": info.addend,
        "implicit_addend": info.implicit_addend,
        "pc_relative": info.pc_relative,
        "target": hex(relocation.target),
        "reloc": hex(relocation.reloc),
        "symbol": None if symbol is None else symbol.full_name,
    }


@mcp.tool(read_only=True)
def rex_xrefs_to(
    call: mcp.ToolCall,
    addr: mcp.Address,
    limit: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_LIMIT)] = 100,
    offset: Annotated[int, mcp.Minimum(0)] = 0,
) -> _XrefsToResult:
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
    page, total, truncated = _paginate(chain(code_refs, data_refs), offset, limit)
    code_entries: list[_CodeReferenceEntry] = []
    data_entries: list[_DataReference] = []
    for reference in page:
        if isinstance(reference, int):
            data_entries.append({"source": hex(reference)})
        else:
            code_entries.append(_code_ref_entry(reference))
    return {
        "total": total,
        "truncated": truncated,
        "code_refs": code_entries,
        "data_refs": data_entries,
    }


@mcp.tool(read_only=True)
def rex_data_read(
    call: mcp.ToolCall,
    addr: mcp.Address,
    length: Annotated[int, mcp.Minimum(1), mcp.Maximum(_MAX_DATA_READ_BYTES)],
) -> _DataReadResult:
    """Read mapped bytes at an address, with relocations applied.

    :param addr: Address to read from.
    :param length: Byte count to read, capped at 0x100000.
    """
    length = _validate_range("length", length, 1, _MAX_DATA_READ_BYTES)
    data = call.binary_view.read(addr, length)
    return {
        "address": hex(addr),
        "length": length,
        "bytes_read": len(data),
        "data": data.hex(),
        "complete": len(data) == length,
    }


@mcp.tool(read_only=True)
def rex_relocation_at(call: mcp.ToolCall, addr: mcp.Address) -> _RelocationAtResult:
    """List the relocations covering an address; an empty list means none.

    :param addr: Address of the relocation, or any address the relocation covers.
    """
    relocations = [
        _relocation_entry(relocation) for relocation in call.binary_view.relocations_at(addr)
    ]
    return {"address": hex(addr), "count": len(relocations), "relocations": relocations}
