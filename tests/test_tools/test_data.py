from __future__ import annotations

import pytest
from helpers import (
    FakeBinaryView,
    FakeCoreSymbol,
    FakeRelocation,
    FakeRelocationInfo,
    FakeSegment,
    FakeToolError,
    _call,
    get_tool,
)

from binja_plugin.tools import data

# --- rex_data_read ---------------------------------------------------------------------


def test_data_read_returns_mapped_bytes() -> None:
    view = FakeBinaryView(memory={0x1000: b"\x7fELF\x02\x01\x01"})
    _, read = get_tool("rex_data_read")
    assert read(_call(view), 0x1004, 3) == {
        "address": "0x1004",
        "length": 3,
        "bytes_read": 3,
        "data": "020101",
        "complete": True,
    }


def test_data_read_reports_a_partially_mapped_range() -> None:
    view = FakeBinaryView(memory={0x1000: b"\x01\x02\x03\x04"})
    _, read = get_tool("rex_data_read")
    assert read(_call(view), 0x1000, 8) == {
        "address": "0x1000",
        "length": 8,
        "bytes_read": 4,
        "data": "01020304",
        "complete": False,
    }


def test_data_read_reports_an_unmapped_address_as_zero_bytes() -> None:
    view = FakeBinaryView(segments=[FakeSegment(0x1000, 0x10)], memory={0x1000: b"abc"})
    _, read = get_tool("rex_data_read")
    assert read(_call(view), 0x2000, 4) == {
        "address": "0x2000",
        "length": 4,
        "bytes_read": 0,
        "data": "",
        "complete": False,
    }


def test_data_read_rejects_out_of_range_lengths() -> None:
    view = FakeBinaryView(memory={0x1000: b"abc"})
    _, read = get_tool("rex_data_read")
    for length, message in (
        (-1, "Invalid integer parameter 'length': Must be at least 1"),
        (0, "Invalid integer parameter 'length': Must be at least 1"),
        (
            data._MAX_DATA_READ_BYTES + 1,
            f"Invalid integer parameter 'length': Must be at most {data._MAX_DATA_READ_BYTES}",
        ),
    ):
        with pytest.raises(FakeToolError) as exc:
            read(_call(view), 0x1000, length)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == message
    # Both bounds are inclusive: exactly 1 and exactly the cap are honored reads.
    assert read(_call(view), 0x1000, 1) == {
        "address": "0x1000",
        "length": 1,
        "bytes_read": 1,
        "data": "61",
        "complete": True,
    }
    at_cap = read(_call(view), 0x1000, data._MAX_DATA_READ_BYTES)
    assert at_cap["bytes_read"] == 3
    assert at_cap["complete"] is False


# --- rex_relocation_at -----------------------------------------------------------------


def test_relocation_at_reports_each_field_of_a_symbol_relocation() -> None:
    view = FakeBinaryView(
        relocations=[
            FakeRelocation(
                FakeRelocationInfo(
                    type_name="ELFGlobalRelocationType",
                    address=0x40EFC0,
                    size=4,
                    pc_relative=True,
                ),
                target=0x412800,
                reloc=0x40EFC0,
                symbol=FakeCoreSymbol("__libc_start_main"),
            )
        ]
    )
    _, relocation_at = get_tool("rex_relocation_at")
    assert relocation_at(_call(view), 0x40EFC2) == {
        "address": "0x40efc2",
        "count": 1,
        "relocations": [
            {
                "address": "0x40efc0",
                "size": 4,
                "type": "ELFGlobalRelocationType",
                "addend": 0,
                "implicit_addend": False,
                "pc_relative": True,
                "target": "0x412800",
                "reloc": "0x40efc0",
                "symbol": "__libc_start_main",
            }
        ],
    }


def test_relocation_at_reports_a_symbolless_relocation() -> None:
    view = FakeBinaryView(
        relocations=[
            FakeRelocation(
                FakeRelocationInfo(
                    type_name="StandardRelocationType",
                    address=0x40EDC0,
                    size=2,
                    addend=33440,
                    implicit_addend=True,
                ),
                target=0x400000,
                reloc=0x40EDC0,
            )
        ]
    )
    _, relocation_at = get_tool("rex_relocation_at")
    assert relocation_at(_call(view), 0x40EDC1) == {
        "address": "0x40edc1",
        "count": 1,
        "relocations": [
            {
                "address": "0x40edc0",
                "size": 2,
                "type": "StandardRelocationType",
                "addend": 33440,
                "implicit_addend": True,
                "pc_relative": False,
                "target": "0x400000",
                "reloc": "0x40edc0",
                "symbol": None,
            }
        ],
    }


def test_relocation_at_answers_an_empty_list_where_nothing_is_relocated() -> None:
    _, relocation_at = get_tool("rex_relocation_at")
    assert relocation_at(_call(FakeBinaryView()), 0x400000) == {
        "address": "0x400000",
        "count": 0,
        "relocations": [],
    }


def test_relocation_at_echoes_duplicate_entries_as_the_core_hands_them() -> None:
    relocation = FakeRelocation(
        FakeRelocationInfo(type_name="ELFGlobalRelocationType", address=0x40EFC0),
        target=0x412800,
        reloc=0x40EFC0,
    )
    view = FakeBinaryView(relocations=[relocation, relocation])
    _, relocation_at = get_tool("rex_relocation_at")
    result = relocation_at(_call(view), 0x40EFC0)
    assert result["count"] == 2
    assert result["relocations"][0] == result["relocations"][1]


def test_relocation_at_matches_any_address_a_relocation_covers() -> None:
    view = FakeBinaryView(
        relocations=[
            FakeRelocation(
                FakeRelocationInfo(type_name="ELFJumpSlotRelocationType", address=0x40F000),
                target=0x412818,
                reloc=0x40F000,
            )
        ]
    )
    _, relocation_at = get_tool("rex_relocation_at")
    # A mid-relocation address still hits, mirroring the core's covering lookup.
    assert relocation_at(_call(view), 0x40F004)["count"] == 1
    assert relocation_at(_call(view), 0x40F008)["count"] == 0
