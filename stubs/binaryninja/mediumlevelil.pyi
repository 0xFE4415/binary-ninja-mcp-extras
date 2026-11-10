from typing import Any

from binaryninja.variable import Variable


class MediumLevelILInstruction:
    operation: Any
    operands: list[Any]
    constant: Any
    address: int
    instr_index: int
    vars_written: list[Variable]


class MediumLevelILFunction:
    instructions: Any
    vars: list[Variable]

    def get_var_definitions(self, var: Variable) -> list[MediumLevelILInstruction]: ...
    def get_var_uses(self, var: Variable) -> list[MediumLevelILInstruction]: ...
