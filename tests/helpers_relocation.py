"""Relocation fakes: a leaf module so helpers_view and helpers can both import it."""

from __future__ import annotations

import types
from typing import Any


class RelocationWriteException(Exception):
    """Mirrors binaryninja.exceptions.RelocationWriteException."""


class FakeRelocationInfo:
    """Mirrors the RelocationInfo fields rex_relocation_at reads.

    ``type`` is a namespace with ``name`` like the other fakes, mirroring the enum
    member the real core hands back.
    """

    def __init__(
        self,
        *,
        type_name: str,
        address: int,
        size: int = 8,
        addend: int = 0,
        implicit_addend: bool = False,
        pc_relative: bool = False,
    ) -> None:
        self.type = types.SimpleNamespace(name=type_name)
        self.address = address
        self.size = size
        self.addend = addend
        self.implicit_addend = implicit_addend
        self.pc_relative = pc_relative


class FakeRelocation:
    """Mirrors the Relocation fields rex_relocation_at reads."""

    def __init__(
        self,
        info: FakeRelocationInfo,
        target: int,
        reloc: int,
        symbol: Any = None,
    ) -> None:
        self.info = info
        self.target = target
        self.reloc = reloc
        self.symbol = symbol
