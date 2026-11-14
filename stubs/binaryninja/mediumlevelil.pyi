from typing import Any

from binaryninja.variable import Variable


class SSAVariable:
    var: Variable
    version: int


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
    ssa_form: MediumLevelILFunction | None
    ssa_vars: list[SSAVariable]

    def get_var_definitions(self, var: Variable) -> list[MediumLevelILInstruction]: ...
    def get_var_uses(self, var: Variable) -> list[MediumLevelILInstruction]: ...
    def get_ssa_var_definition(self, ssa_var: SSAVariable) -> MediumLevelILInstruction | None: ...
    def get_ssa_var_uses(self, ssa_var: SSAVariable) -> list[MediumLevelILInstruction]: ...
