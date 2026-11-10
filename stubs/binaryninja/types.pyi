from typing import Any

from binaryninja.enums import TypeClass


class Type:
    @property
    def type_class(self) -> TypeClass: ...
    @staticmethod
    def generate_auto_type_id(source: str, name: Any) -> str: ...


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
    width: int
