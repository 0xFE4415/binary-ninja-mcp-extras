from enum import IntEnum


class MediumLevelILOperation(IntEnum):
    MLIL_SET_VAR = 0
    MLIL_CONST = 15
    MLIL_CONST_PTR = 16


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


class VariableSourceType(IntEnum):
    StackVariableSourceType = 0
    RegisterVariableSourceType = 1
    FlagVariableSourceType = 2
    CompositeReturnValueSourceType = 3
    CompositeParameterSourceType = 4
