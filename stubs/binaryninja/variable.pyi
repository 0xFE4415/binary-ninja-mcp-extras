from typing import Any

from binaryninja.enums import RegisterValueType, VariableSourceType
from binaryninja.types import Type


class Variable:
    name: str
    source_type: VariableSourceType
    storage: int
    type: Type


class ArchAndAddr:
    """One definition site: the architecture and address of the defining MLIL instruction."""

    arch: Any
    addr: int


class PossibleValueSet:
    type: RegisterValueType

    def __str__(self) -> str: ...
