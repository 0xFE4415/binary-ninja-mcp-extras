"""String fakes: a leaf module so helpers_view can import it."""

from __future__ import annotations

import types
from typing import Protocol


class FakeStringReference:
    def __init__(self, value: str, start: int, type_name: str = "AsciiString") -> None:
        self._value = value
        self.start = start
        self._type_name = type_name

    def __len__(self) -> int:
        return len(self._value)

    @property
    def value(self) -> str:
        return self._value

    @property
    def type(self) -> types.SimpleNamespace:
        return types.SimpleNamespace(name=self._type_name)


class _ReadableView(Protocol):
    start: int
    end: int

    def read(self, address: int, length: int) -> bytes: ...


def ascii_string_at(
    view: _ReadableView,
    address: int,
    min_length: int,
    max_length: int | None,
    require_cstring: bool,
) -> FakeStringReference | None:
    """Mirror BinaryView.get_ascii_string_at: bytes 1..0x7f from address, max_length-bounded."""
    if address < view.start or address >= view.end:
        return None
    length = 0
    byte = view.read(address, 1)
    while byte and 0 < byte[0] <= 0x7F:
        if length == max_length:
            break
        length += 1
        byte = view.read(address + length, 1)
    if length < min_length:
        return None
    if require_cstring and byte != b"\x00":
        return None
    return FakeStringReference(view.read(address, length).decode("ascii"), address)
