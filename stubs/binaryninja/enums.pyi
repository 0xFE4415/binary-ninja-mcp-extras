from enum import IntEnum


class MediumLevelILOperation(IntEnum):
    MLIL_SET_VAR = 1
    MLIL_LOAD = 6
    MLIL_LOAD_STRUCT = 7
    MLIL_VAR = 10
    MLIL_CONST = 17
    MLIL_CONST_PTR = 19
    MLIL_IMPORT = 22
    MLIL_ADD = 23
    MLIL_SX = 50
    MLIL_ZX = 51
    MLIL_LOW_PART = 52
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
    MLIL_FCMP_E = 106
    MLIL_FCMP_NE = 107
    MLIL_FCMP_LT = 108
    MLIL_FCMP_LE = 109
    MLIL_FCMP_GE = 110
    MLIL_FCMP_GT = 111
    MLIL_SET_VAR_SSA = 114
    MLIL_VAR_SSA = 119
    MLIL_VAR_PHI = 146


class LowLevelILOperation(IntEnum):
    LLIL_LOAD = 8
    LLIL_CALL = 56
    LLIL_TAILCALL = 58


class InstructionTextTokenType(IntEnum):
    TextToken = 0
    InstructionToken = 1
    OperandSeparatorToken = 2
    RegisterToken = 3
    IntegerToken = 4
    PossibleAddressToken = 5
    FloatingPointToken = 8
    AnnotationToken = 9
    CodeRelativeAddressToken = 10
    CharacterConstantToken = 18
    EnumerationMemberToken = 35
    CodeSymbolToken = 64
    DataSymbolToken = 65
    ImportToken = 67
    ExternalSymbolToken = 70
    StackVariableToken = 71
    AddressSeparatorToken = 72


class AnalysisState(IntEnum):
    InitialState = 0
    HoldState = 1
    IdleState = 2
    DiscoveryState = 3
    DisassembleState = 4
    AnalyzeState = 5
    ExtendedAnalyzeState = 6


class AnalysisSkipReason(IntEnum):
    NoSkipReason = 0
    AlwaysSkipReason = 1
    ExceedFunctionSizeSkipReason = 2
    ExceedFunctionAnalysisTimeSkipReason = 3
    ExceedFunctionUpdateCountSkipReason = 4
    NewAutoFunctionAnalysisSuppressedReason = 5
    BasicAnalysisSkipReason = 6
    IntermediateAnalysisSkipReason = 7
    AnalysisPipelineSuspendedReason = 8


class RegisterValueType(IntEnum):
    UndeterminedValue = 0
    EntryValue = 1
    ConstantValue = 2
    ConstantPointerValue = 3
    ExternalPointerValue = 4
    StackFrameOffset = 5
    ReturnAddressValue = 6
    ImportedAddressValue = 7
    ResultPointerValue = 8
    ParameterPointerValue = 9
    SignedRangeValue = 10
    UnsignedRangeValue = 11
    LookupTableValue = 12
    InSetOfValues = 13
    NotInSetOfValues = 14
    ConstantDataValue = 32768
    ConstantDataZeroExtendValue = 32769
    ConstantDataSignExtendValue = 32770
    ConstantDataAggregateValue = 32771


class DerivedStringLocationType(IntEnum):
    DataBackedStringLocation = 0
    CodeStringLocation = 1


class RelocationType(IntEnum):
    ELFGlobalRelocationType = 0
    ELFCopyRelocationType = 1
    ELFJumpSlotRelocationType = 2
    StandardRelocationType = 3
    IgnoredRelocation = 4
    UnhandledRelocation = 5


class StructureVariant(IntEnum):
    ClassStructureType = 0
    StructStructureType = 1
    UnionStructureType = 2


class TypeClass(IntEnum):
    VoidTypeClass = 0
    BoolTypeClass = 1
    IntegerTypeClass = 2
    FloatTypeClass = 3
    StructureTypeClass = 4
    EnumerationTypeClass = 5
    PointerTypeClass = 6
    ArrayTypeClass = 7
    FunctionTypeClass = 8
    VarArgsTypeClass = 9
    ValueTypeClass = 10
    NamedTypeReferenceClass = 11
    WideCharTypeClass = 12
    FragmentTypeClass = 13


class SymbolType(IntEnum):
    FunctionSymbol = 0
    ImportAddressSymbol = 1
    ImportedFunctionSymbol = 2
    DataSymbol = 3
    ImportedDataSymbol = 4
    ExternalSymbol = 5
    LibraryFunctionSymbol = 6
    SymbolicFunctionSymbol = 7
    LocalLabelSymbol = 8


class SymbolBinding(IntEnum):
    NoBinding = 0
    LocalBinding = 1
    GlobalBinding = 2
    WeakBinding = 3


class VariableSourceType(IntEnum):
    StackVariableSourceType = 0
    RegisterVariableSourceType = 1
    FlagVariableSourceType = 2
    CompositeReturnValueSourceType = 3
    CompositeParameterSourceType = 4
