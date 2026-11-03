"""Mapped-memory data reads and relocation inspection."""

from __future__ import annotations

from typing import Annotated

from binaryninja import mcp

from binja_plugin.tools import _validate_range

_MAX_DATA_READ_BYTES = 0x100000


@mcp.tool(read_only=True)
def rex_data_read(
    call: mcp.ToolCall,
    addr: mcp.Address,
    length: Annotated[int, mcp.Minimum(1), mcp.Maximum(_MAX_DATA_READ_BYTES)],
) -> dict[str, object]:
    """Read mapped bytes at an address, with relocations applied.

    :param addr: Address to read from.
    :param length: Byte count to read, capped at 0x100000.
    """
    length = _validate_range("length", length, 1, _MAX_DATA_READ_BYTES)
    # bv.read hands back at most the requested length, silently shortening at the first
    # unmapped byte and returning empty for an unmapped address, so bytes_read and
    # complete carry what actually came back instead of the read lying by omission.
    data = call.binary_view.read(addr, length)
    return {
        "address": hex(addr),
        "length": length,
        "bytes_read": len(data),
        "data": data.hex(),
        "complete": len(data) == length,
    }


@mcp.tool(read_only=True)
def rex_relocation_at(call: mcp.ToolCall, addr: mcp.Address) -> dict[str, object]:
    """List the relocations covering an address; an empty list means none.

    :param addr: Address of the relocation, or any address the relocation covers.
    """
    relocations = []
    for relocation in call.binary_view.relocations_at(addr):
        info = relocation.info
        symbol = relocation.symbol
        # The core may hand the same relocation back more than once; the list is echoed
        # as the core reports it rather than deduplicated into what it ought to be.
        relocations.append(
            {
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
        )
    return {"address": hex(addr), "count": len(relocations), "relocations": relocations}
