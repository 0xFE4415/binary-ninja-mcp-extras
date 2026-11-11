from collections.abc import Iterable, Iterator


class HighLevelILInstruction:
    address: int
    instr_index: int


class HighLevelILConstPtr(HighLevelILInstruction):
    constant: int


class HighLevelILConst(HighLevelILInstruction):
    constant: int


class HighLevelILImport(HighLevelILInstruction):
    constant: int


class HighLevelILVar(HighLevelILInstruction): ...


class HighLevelILTailcall(HighLevelILInstruction):
    dest: HighLevelILInstruction
    params: list[HighLevelILInstruction]


class HighLevelILBasicBlock:
    def __iter__(self) -> Iterator[HighLevelILInstruction]: ...


class HighLevelILFunction:
    basic_blocks: Iterable[HighLevelILBasicBlock]
