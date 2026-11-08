from typing import Any

from binaryninja.variable import Variable


class MediumLevelILInstruction:
    operation: Any
    operands: list[Any]
    constant: Any
    address: int


class MediumLevelILFunction:
    instructions: Any

    def get_var_definitions(self, var: Variable) -> list[MediumLevelILInstruction]: ...
    def get_var_uses(self, var: Variable) -> list[MediumLevelILInstruction]: ...
