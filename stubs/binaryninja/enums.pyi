from enum import IntEnum


class MediumLevelILOperation(IntEnum):
    MLIL_SET_VAR = 0
    MLIL_CONST = 15
    MLIL_CONST_PTR = 16


class AnalysisState(IntEnum):
    InitialState = 0
    HoldState = 1
    IdleState = 2
    DiscoveryState = 3
    DisassembleState = 4
    AnalyzeState = 5
    ExtendedAnalyzeState = 6
