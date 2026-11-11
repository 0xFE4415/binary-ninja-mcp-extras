from collections.abc import Iterable, Iterator


class HighLevelILInstruction:
    address: int
    instr_index: int


class HighLevelILConstPtr(HighLevelILInstruction):
    constant: int


class HighLevelILTailcall(HighLevelILInstruction):
    dest: HighLevelILInstruction


class HighLevelILBasicBlock:
    def __iter__(self) -> Iterator[HighLevelILInstruction]: ...


class HighLevelILFunction:
    basic_blocks: Iterable[HighLevelILBasicBlock]
