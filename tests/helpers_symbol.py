"""Symbol fakes: a leaf module so helpers_view and helpers can both import it."""

from __future__ import annotations

import enum


class FakeSymbolType(enum.IntEnum):
    """Mirrors binaryninja.enums.SymbolType."""

    FunctionSymbol = 0
    ImportAddressSymbol = 1
    ImportedFunctionSymbol = 2
    DataSymbol = 3
    ImportedDataSymbol = 4
    ExternalSymbol = 5
    LibraryFunctionSymbol = 6
    SymbolicFunctionSymbol = 7
    LocalLabelSymbol = 8


class FakeSymbolBinding(enum.IntEnum):
    """Mirrors binaryninja.enums.SymbolBinding."""

    NoBinding = 0
    LocalBinding = 1
    GlobalBinding = 2
    WeakBinding = 3


class FakeSymbol:
    """Mirrors the CoreSymbol fields rex_export_symbols and the object export read.

    ``type`` is the SymbolType member the real core hands back, looked up by name.
    """

    def __init__(
        self,
        address: int,
        type_name: str,
        name: str,
        *,
        binding: FakeSymbolBinding = FakeSymbolBinding.NoBinding,
        namespace: str = "",
        ordinal: int = 0,
    ) -> None:
        self.address = address
        self.type = FakeSymbolType[type_name]
        self.name = name
        self.binding = binding
        self.namespace = namespace
        self.ordinal = ordinal


def fake_symbol_constructor(
    sym_type: FakeSymbolType,
    addr: int,
    short_name: str,
    full_name: str | None = None,
    raw_name: str | None = None,
    binding: FakeSymbolBinding | None = None,
    namespace: str | None = None,
    ordinal: int = 0,
) -> FakeSymbol:
    """Mirror binaryninja.types.Symbol.__init__: an omitted binding becomes NoBinding."""
    return FakeSymbol(
        addr,
        FakeSymbolType(sym_type).name,
        short_name,
        binding=FakeSymbolBinding.NoBinding if binding is None else binding,
        namespace="" if namespace is None else namespace,
        ordinal=ordinal,
    )
