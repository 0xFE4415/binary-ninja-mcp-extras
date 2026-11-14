"""Instruction-tree fakes for the dataflow tools: MLIL/HLIL nodes, MLIL SSA, and values.

A leaf module by design: it reuses the variable fake from helpers_uidf and does not import
helpers back.
"""

from __future__ import annotations

import copy
import enum
from typing import Any, override

from helpers_uidf import FakeRegisterValueType, FakeVariable, FakeVariableSourceType

_DEST_WRITES = ("MLIL_SET_VAR", "MLIL_SET_VAR_SSA", "MLIL_FORCE_VER")
_SPLIT_WRITES = ("MLIL_SET_VAR_SPLIT", "MLIL_SET_VAR_SPLIT_SSA")
_OUTPUT_WRITES = (
    "MLIL_CALL",
    "MLIL_CALL_UNTYPED",
    "MLIL_SYSCALL",
    "MLIL_SYSCALL_UNTYPED",
    "MLIL_TAILCALL",
    "MLIL_TAILCALL_UNTYPED",
    "MLIL_INTRINSIC",
)


class FakeMediumLevelILOperation(enum.IntEnum):
    """Mirrors binaryninja.enums.MediumLevelILOperation for the members the tests build."""

    MLIL_NOP = 0
    MLIL_SET_VAR = 1
    MLIL_SET_VAR_FIELD = 2
    MLIL_SET_VAR_SPLIT = 3
    MLIL_FORCE_VER = 5
    MLIL_LOAD = 6
    MLIL_LOAD_STRUCT = 7
    MLIL_STORE = 8
    MLIL_VAR = 10
    MLIL_CONST = 17
    MLIL_CONST_PTR = 19
    MLIL_FLOAT_CONST = 21
    MLIL_IMPORT = 22
    MLIL_ADD = 23
    MLIL_SX = 50
    MLIL_ZX = 51
    MLIL_LOW_PART = 52
    MLIL_CALL = 56
    MLIL_CALL_UNTYPED = 57
    MLIL_RET = 64
    MLIL_IF = 66
    MLIL_CMP_E = 68
    MLIL_CMP_NE = 69
    MLIL_CMP_SLT = 70
    MLIL_CMP_ULT = 71
    MLIL_CMP_SLE = 72
    MLIL_CMP_ULE = 73
    MLIL_CMP_SGE = 74
    MLIL_CMP_UGE = 75
    MLIL_CMP_SGT = 76
    MLIL_CMP_UGT = 77
    MLIL_SYSCALL = 81
    MLIL_SYSCALL_UNTYPED = 82
    MLIL_TAILCALL = 83
    MLIL_TAILCALL_UNTYPED = 84
    MLIL_INTRINSIC = 85
    MLIL_FCMP_E = 106
    MLIL_FCMP_NE = 107
    MLIL_FCMP_LT = 108
    MLIL_FCMP_LE = 109
    MLIL_FCMP_GE = 110
    MLIL_FCMP_GT = 111
    MLIL_FCMP_O = 112
    MLIL_FCMP_UO = 113
    MLIL_SET_VAR_SSA = 114
    MLIL_SET_VAR_SPLIT_SSA = 116
    MLIL_VAR_SSA = 119
    MLIL_LOAD_SSA = 139
    MLIL_LOAD_STRUCT_SSA = 140
    MLIL_VAR_PHI = 146


class FakeOperation:
    """An HLIL operation: only .name is read by the tools."""

    def __init__(self, name: str) -> None:
        self.name = name


class FakeRegisterValue:
    """Mirrors binaryninja.variable.RegisterValue: the state and its value."""

    def __init__(
        self, state: FakeRegisterValueType = FakeRegisterValueType.UndeterminedValue, value: int = 0
    ) -> None:
        self.type = state
        self.value = value


_UNDETERMINED = FakeRegisterValue()


class FakeSSAVariable:
    """Mirrors binaryninja.mediumlevelil.SSAVariable: equal by variable and version."""

    def __init__(self, variable: FakeVariable, version: int) -> None:
        self.var = variable
        self.version = version

    @override
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, FakeSSAVariable):
            return NotImplemented
        return (self.var, self.version) == (other.var, other.version)

    @override
    def __hash__(self) -> int:
        return hash((self.var, self.version))

    @override
    def __str__(self) -> str:
        return f"{self.var.name}#{self.version}"


class FakeInstruction:
    """One IL node. Operands are attributes named as the real API names them."""

    # Operands __str__ renders; the builders set them per operation.
    constant: Any = None
    condition: Any = None
    left: Any = None
    right: Any = None
    dest: Any = None
    src: Any = None
    high: Any = None
    low: Any = None
    output: Any = ()
    size: int = 8
    value: FakeRegisterValue = _UNDETERMINED
    non_ssa_form: Any = None

    def __init__(
        self,
        operation: str,
        address: int = 0,
        *,
        instr_index: int = 0,
        text: str | None = None,
        **operands: Any,
    ) -> None:
        self.operation: FakeMediumLevelILOperation | FakeOperation = (
            FakeMediumLevelILOperation[operation]
            if operation.startswith("MLIL_")
            else FakeOperation(operation)
        )
        self.address = address
        self.instr_index = instr_index
        self._text = text
        for name, value in operands.items():
            setattr(self, name, value)

    @property
    def vars_written(self) -> list[Any]:
        """Mirrors the real property: SET_VAR_FIELD does not override it and reports nothing."""
        name = self.operation.name
        if name in _DEST_WRITES:
            return [self.dest]
        if name in _SPLIT_WRITES:
            return [self.high, self.low]
        if name in _OUTPUT_WRITES:
            return list(self.output)
        return []

    @override
    def __str__(self) -> str:
        if self._text is not None:
            return self._text
        name = self.operation.name
        if name == "MLIL_CONST":
            return hex(self.constant)
        if name == "MLIL_ADD":
            return f"{self.left} + {self.right}"
        if name in ("MLIL_SET_VAR", "MLIL_SET_VAR_SSA"):
            return f"{self.dest.name} = {self.src}"
        if name == "MLIL_LOAD":
            return f"*({self.src})"
        return name


def constant_value(value: int) -> FakeRegisterValue:
    return FakeRegisterValue(FakeRegisterValueType.ConstantValue, value)


def const(value: int, size: int = 8) -> FakeInstruction:
    """A constant as the core states it: .value repeats .constant, as observed live."""
    return FakeInstruction("MLIL_CONST", constant=value, size=size, value=constant_value(value))


def const_pointer(value: int, size: int = 8) -> FakeInstruction:
    pointer = FakeRegisterValue(FakeRegisterValueType.ConstantPointerValue, value)
    return FakeInstruction("MLIL_CONST_PTR", constant=value, size=size, value=pointer)


def float_const(number: float, bits: int, size: int = 8) -> FakeInstruction:
    """A float constant: .constant is the float, .value its IEEE bits, as observed live."""
    return FakeInstruction(
        "MLIL_FLOAT_CONST", constant=number, size=size, value=constant_value(bits), text=str(number)
    )


def import_address(slot: int, name: str) -> FakeInstruction:
    """An import: .constant and .value name the import address slot, not the import itself."""
    imported = FakeRegisterValue(FakeRegisterValueType.ImportedAddressValue, slot)
    return FakeInstruction("MLIL_IMPORT", constant=slot, value=imported, text=name)


def var(variable: FakeVariable) -> FakeInstruction:
    return FakeInstruction("MLIL_VAR", src=variable, text=variable.name)


def load(address: FakeInstruction, size: int = 8) -> FakeInstruction:
    return FakeInstruction("MLIL_LOAD", src=address, size=size)


def load_struct(address: FakeInstruction, offset: int, field: str) -> FakeInstruction:
    return FakeInstruction(
        "MLIL_LOAD_STRUCT", src=address, offset=offset, text=f"{address}->{field}"
    )


def low_part(src: FakeInstruction, size: int = 1) -> FakeInstruction:
    return FakeInstruction("MLIL_LOW_PART", src=src, size=size, text=f"({src}).{size}")


def add(left: FakeInstruction, right: FakeInstruction) -> FakeInstruction:
    return FakeInstruction("MLIL_ADD", left=left, right=right)


def sign_extend(
    src: FakeInstruction, size: int = 8, value: FakeRegisterValue = _UNDETERMINED
) -> FakeInstruction:
    return FakeInstruction("MLIL_SX", src=src, size=size, value=value)


def zero_extend(
    src: FakeInstruction, size: int = 8, value: FakeRegisterValue = _UNDETERMINED
) -> FakeInstruction:
    return FakeInstruction("MLIL_ZX", src=src, size=size, value=value)


def compare(operation: str, left: FakeInstruction, right: FakeInstruction) -> FakeInstruction:
    return FakeInstruction(operation, left=left, right=right)


def branch(address: int, condition: FakeInstruction) -> FakeInstruction:
    return FakeInstruction("MLIL_IF", address, condition=condition)


def set_var(address: int, variable: FakeVariable, src: FakeInstruction) -> FakeInstruction:
    return FakeInstruction("MLIL_SET_VAR", address, dest=variable, src=src)


def var_ssa(variable: FakeSSAVariable) -> FakeInstruction:
    return FakeInstruction("MLIL_VAR_SSA", src=variable, text=str(variable))


def _non_ssa(expression: FakeInstruction) -> FakeInstruction:
    if expression.operation == FakeMediumLevelILOperation.MLIL_VAR_SSA:
        return var(expression.src.var)
    plain = copy.copy(expression)
    for name in ("src", "left", "right"):
        operand = getattr(expression, name)
        if isinstance(operand, FakeInstruction):
            setattr(plain, name, _non_ssa(operand))
    return plain


def set_var_ssa(
    address: int, dest: FakeSSAVariable, src: FakeInstruction, text: str
) -> FakeInstruction:
    """An SSA assignment paired with its non-SSA form, which renders as ``text``."""
    plain = FakeInstruction("MLIL_SET_VAR", address, dest=dest.var, src=_non_ssa(src), text=text)
    return FakeInstruction("MLIL_SET_VAR_SSA", address, dest=dest, src=src, non_ssa_form=plain)


def phi(address: int, dest: FakeSSAVariable, sources: list[FakeSSAVariable]) -> FakeInstruction:
    return FakeInstruction("MLIL_VAR_PHI", address, dest=dest, src=sources)


def _ssa_reads(instruction: FakeInstruction) -> list[FakeSSAVariable]:
    operation = instruction.operation
    if operation == FakeMediumLevelILOperation.MLIL_VAR_PHI:
        return list(instruction.src)
    if operation == FakeMediumLevelILOperation.MLIL_VAR_SSA:
        return [instruction.src]
    reads: list[FakeSSAVariable] = []
    for operand in (instruction.src, instruction.left, instruction.right, instruction.condition):
        if isinstance(operand, FakeInstruction):
            reads.extend(_ssa_reads(operand))
    return reads


class FakeMLILSSA:
    """Mirrors the SSA form of a MediumLevelILFunction: uses and definitions per SSA variable."""

    def __init__(self, instructions: list[FakeInstruction]) -> None:
        self.instructions = instructions
        for position, instruction in enumerate(instructions):
            instruction.instr_index = position

    @property
    def ssa_vars(self) -> list[FakeSSAVariable]:
        """Every SSA variable read or written, entry versions included, as the core lists them."""
        found: list[FakeSSAVariable] = []
        for instruction in self.instructions:
            found.extend(_ssa_reads(instruction))
            if isinstance(instruction.dest, FakeSSAVariable):
                found.append(instruction.dest)
        return list(dict.fromkeys(found))

    def get_ssa_var_uses(self, variable: FakeSSAVariable) -> list[FakeInstruction]:
        return [
            instruction for instruction in self.instructions if variable in _ssa_reads(instruction)
        ]

    def get_ssa_var_definition(self, variable: FakeSSAVariable) -> FakeInstruction | None:
        for instruction in self.instructions:
            if instruction.dest == variable:
                return instruction
        return None


class FakeMLILInstructions:
    """Mirrors MediumLevelILFunction for the surface the dataflow tools read."""

    def __init__(
        self,
        instructions: list[FakeInstruction],
        uses: dict[FakeVariable, list[FakeInstruction]] | None = None,
        definitions: dict[FakeVariable, list[FakeInstruction]] | None = None,
        ssa_form: FakeMLILSSA | None = None,
    ) -> None:
        self.instructions = instructions
        for position, instruction in enumerate(instructions):
            instruction.instr_index = position
        self._uses = uses or {}
        self._definitions = definitions or {}
        self.ssa_form = FakeMLILSSA([]) if ssa_form is None else ssa_form

    @property
    def vars(self) -> list[FakeVariable]:
        """Every variable with a recorded definition or use, as the core lists them."""
        return list(dict.fromkeys([*self._definitions, *self._uses]))

    def get_var_definitions(self, variable: FakeVariable) -> list[FakeInstruction]:
        return list(self._definitions.get(variable, []))

    def get_var_uses(self, variable: FakeVariable) -> list[FakeInstruction]:
        return list(self._uses.get(variable, []))


class FakeHLIL:
    """Mirrors HighLevelILFunction.basic_blocks: each block iterates its statements."""

    def __init__(self, blocks: list[list[FakeInstruction]]) -> None:
        self.basic_blocks = blocks


def _stack_variable(name: str, offset: int, type_string: str = "int32_t") -> FakeVariable:
    return FakeVariable(
        name,
        source_type=FakeVariableSourceType.StackVariableSourceType,
        storage=offset,
        type_string=type_string,
    )


def _flag_variable(storage: int) -> FakeVariable:
    return FakeVariable(
        "f", source_type=FakeVariableSourceType.FlagVariableSourceType, storage=storage
    )
