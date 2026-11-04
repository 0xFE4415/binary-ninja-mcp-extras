from typing import Any

from binaryninja.variable import Variable


class MediumLevelILInstruction:
    operation: Any
    operands: list[Any]
    constant: Any
    address: int


class MediumLevelILFunction:
    def get_var_definitions(self, var: Variable) -> list[MediumLevelILInstruction]: ...
