from collections.abc import Iterable, Iterator


class HighLevelILInstruction:
    address: int
    instr_index: int


class HighLevelILBasicBlock:
    def __iter__(self) -> Iterator[HighLevelILInstruction]: ...


class HighLevelILFunction:
    basic_blocks: Iterable[HighLevelILBasicBlock]
