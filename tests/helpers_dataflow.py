"""Instruction-tree fakes for the dataflow tools: MLIL/HLIL nodes with named operations.

A leaf module by design: it reuses the variable fake from helpers_uidf and does not import
helpers back.
"""

from __future__ import annotations

from typing import Any, override

from helpers_uidf import FakeVariable

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


class FakeOperation:
    """Mirrors MediumLevelILOperation: only .name is read by the tools."""

    def __init__(self, name: str) -> None:
        self.name = name


class FakeInstruction:
    """One IL node. Operands are attributes named as the real API names them."""

    # Operands __str__ renders; the builders set them per operation.
    constant: Any = None
    left: Any = None
    right: Any = None
    dest: Any = None
    src: Any = None
    high: Any = None
    low: Any = None
    output: Any = ()
    size: int = 8

    def __init__(
        self,
        operation: str,
        address: int = 0,
        *,
        instr_index: int = 0,
        text: str | None = None,
        **operands: Any,
    ) -> None:
        self.operation = FakeOperation(operation)
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


def const(value: int, size: int = 8) -> FakeInstruction:
    return FakeInstruction("MLIL_CONST", constant=value, size=size)


def var(variable: FakeVariable) -> FakeInstruction:
    return FakeInstruction("MLIL_VAR", src=variable, text=variable.name)


def load(address: FakeInstruction) -> FakeInstruction:
    return FakeInstruction("MLIL_LOAD", src=address)


def add(left: FakeInstruction, right: FakeInstruction) -> FakeInstruction:
    return FakeInstruction("MLIL_ADD", left=left, right=right)


def sign_extend(src: FakeInstruction) -> FakeInstruction:
    return FakeInstruction("MLIL_SX", src=src)


def compare(operation: str, left: FakeInstruction, right: FakeInstruction) -> FakeInstruction:
    return FakeInstruction(operation, left=left, right=right)


def branch(address: int, condition: FakeInstruction) -> FakeInstruction:
    return FakeInstruction("MLIL_IF", address, condition=condition)


def set_var(
    address: int, variable: FakeVariable, src: FakeInstruction, *, ssa: bool = False
) -> FakeInstruction:
    name = "MLIL_SET_VAR_SSA" if ssa else "MLIL_SET_VAR"
    return FakeInstruction(name, address, dest=variable, src=src)


class FakeMLILInstructions:
    """Mirrors MediumLevelILFunction for the surface the dataflow tools read."""

    def __init__(
        self,
        instructions: list[FakeInstruction],
        uses: dict[FakeVariable, list[FakeInstruction]] | None = None,
        definitions: dict[FakeVariable, list[FakeInstruction]] | None = None,
    ) -> None:
        self.instructions = instructions
        for position, instruction in enumerate(instructions):
            instruction.instr_index = position
        self._uses = uses or {}
        self._definitions = definitions or {}

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
