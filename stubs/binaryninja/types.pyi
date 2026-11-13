from typing import Any

from binaryninja.enums import StructureVariant, SymbolBinding, SymbolType, TypeClass


class Type:
    @property
    def type_class(self) -> TypeClass: ...


class TypeBuilder: ...


class QualifiedName: ...


class NamedTypeReferenceType(Type):
    # import_library_type returns one of these per its docstring; the name is the
    # deconflicted name the core actually inserted.
    name: Any


class StructureMember:
    type: Any
    name: str
    offset: int


class StructureType(Type):
    members: list[StructureMember]
    type: StructureVariant
    width: int


class NameSpace: ...


class Symbol:
    def __init__(
        self,
        sym_type: SymbolType,
        addr: int,
        short_name: str,
        full_name: str | None = None,
        raw_name: str | None = None,
        binding: SymbolBinding | None = None,
        namespace: NameSpace | str | None = None,
        ordinal: int = 0,
    ) -> None: ...
