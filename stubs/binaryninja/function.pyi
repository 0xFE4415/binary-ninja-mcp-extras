from collections.abc import Iterable
from typing import Any

from binaryninja.architecture import Architecture
from binaryninja.basicblock import BasicBlock
from binaryninja.highlevelil import HighLevelILFunction
from binaryninja.mediumlevelil import MediumLevelILFunction
from binaryninja.types import Type, TypeBuilder
from binaryninja.variable import ArchAndAddr, PossibleValueSet, Variable


class DisassemblySettings: ...


class InstructionTextToken:
    def __str__(self) -> str: ...


class DisassemblyTextLine:
    tokens: list[InstructionTextToken]
    address: int | None


class Function:
    name: str
    arch: Architecture
    start: int
    end: int
    highest_address: int
    callers: list[Function]
    callees: list[Function]
    hlil: HighLevelILFunction | None
    mlil: MediumLevelILFunction | None
    comment: str
    type: Type
    basic_blocks: Iterable[BasicBlock]
    vars: list[Variable]

    def set_comment_at(self, addr: int, comment: str) -> None: ...
    def set_user_type(self, value: str | Type | TypeBuilder) -> None: ...
    def set_user_var_value(
        self, var: Variable, def_addr: int, value: PossibleValueSet, after: bool = True
    ) -> None: ...
    def get_all_user_var_values(self) -> dict[Variable, dict[ArchAndAddr, PossibleValueSet]]: ...
    def clear_user_var_value(self, var: Variable, def_addr: int, after: bool = True) -> None: ...
    def clear_all_user_var_values(self) -> None: ...
