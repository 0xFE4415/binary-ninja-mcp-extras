from typing import Any

from binaryninja.enums import RegisterValueType


class Variable:
    name: str


class ArchAndAddr:
    """One definition site: the architecture and address of the defining MLIL instruction."""

    arch: Any
    addr: int


class PossibleValueSet:
    type: RegisterValueType

    def __str__(self) -> str: ...
