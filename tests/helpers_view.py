"""View fakes for exercising binja_plugin without a Binary Ninja installation.

A leaf module by design: helpers imports its installer-facing subset back, so it must
not import helpers.
"""

from __future__ import annotations

import contextlib
import enum
import types
from collections.abc import Callable, Generator, Iterator, Mapping
from typing import Any, Final, override

from helpers_dataflow import FakeMLILInstructions
from helpers_uidf import (
    FakeMediumLevelIL,
    FakePossibleValueSet,
    FakeRegisterValueType,
    FakeVariable,
    parse_possible_value_set,
)


class FakeSegment:
    def __init__(self, start: int, length: int, readable: bool = True) -> None:
        self.start = start
        self.length = length
        # Mirrors binaryview.Segment.readable (the SegmentFlag readability bit).
        self.readable = readable


class FakeStringReference:
    def __init__(self, value: str, start: int, type_name: str = "AsciiString") -> None:
        self._value = value
        self.start = start
        self._type_name = type_name

    def __len__(self) -> int:
        return len(self._value)

    @property
    def value(self) -> str:
        return self._value

    @property
    def type(self) -> types.SimpleNamespace:
        return types.SimpleNamespace(name=self._type_name)


class FakeTag:
    def __init__(self, type_name: str, data: str) -> None:
        self.data = data
        self._type_name = type_name

    @property
    def type(self) -> types.SimpleNamespace:
        return types.SimpleNamespace(name=self._type_name)


class RenderableText:
    def __init__(self, text: str) -> None:
        self._text = text

    @override
    def __str__(self) -> str:
        return self._text


class FakeLinearDisassemblyLine:
    """Mirrors the LinearDisassemblyLine yielded by BinaryView.find_all_constant."""

    def __init__(self, function: FakeFunction | None) -> None:
        self.function = function


class FakeSymbolType(enum.IntEnum):
    """Mirrors binaryninja.enums.SymbolType."""

    FunctionSymbol = 0
    ImportAddressSymbol = 1
    ImportedFunctionSymbol = 2
    DataSymbol = 3
    ImportedDataSymbol = 4
    ExternalSymbol = 5
    LibraryFunctionSymbol = 6
    SymbolicFunctionSymbol = 7
    LocalLabelSymbol = 8


class FakeSymbol:
    """Mirrors the CoreSymbol fields rex_export_symbols and the object export read.

    ``type`` is the SymbolType member the real core hands back, looked up by name.
    """

    def __init__(self, address: int, type_name: str, name: str) -> None:
        self.address = address
        self.type = FakeSymbolType[type_name]
        self.name = name


class FakeCoreSymbol:
    """Mirrors the CoreSymbol surface rex_relocation_at reads."""

    def __init__(self, full_name: str) -> None:
        self.full_name = full_name


class FakeRelocationInfo:
    """Mirrors the RelocationInfo fields rex_relocation_at reads.

    ``type`` is a namespace with ``name`` like the other fakes, mirroring the enum
    member the real core hands back.
    """

    def __init__(
        self,
        *,
        type_name: str,
        address: int,
        size: int = 8,
        addend: int = 0,
        implicit_addend: bool = False,
        pc_relative: bool = False,
    ) -> None:
        self.type = types.SimpleNamespace(name=type_name)
        self.address = address
        self.size = size
        self.addend = addend
        self.implicit_addend = implicit_addend
        self.pc_relative = pc_relative


class FakeRelocation:
    """Mirrors the Relocation fields rex_relocation_at reads."""

    def __init__(
        self,
        info: FakeRelocationInfo,
        target: int,
        reloc: int,
        symbol: FakeCoreSymbol | None = None,
    ) -> None:
        self.info = info
        self.target = target
        self.reloc = reloc
        self.symbol = symbol


class FakeAnalysisState(enum.IntEnum):
    """Mirrors binaryninja.enums.AnalysisState."""

    InitialState = 0
    HoldState = 1
    IdleState = 2
    DiscoveryState = 3
    DisassembleState = 4
    AnalyzeState = 5
    ExtendedAnalyzeState = 6


class FakeAnalysisSkipReason(enum.IntEnum):
    """Mirrors binaryninja.enums.AnalysisSkipReason."""

    NoSkipReason = 0
    AlwaysSkipReason = 1
    ExceedFunctionSizeSkipReason = 2
    ExceedFunctionAnalysisTimeSkipReason = 3
    ExceedFunctionUpdateCountSkipReason = 4
    NewAutoFunctionAnalysisSuppressedReason = 5
    BasicAnalysisSkipReason = 6
    IntermediateAnalysisSkipReason = 7
    AnalysisPipelineSuspendedReason = 8


class FakeAnalysisProgress:
    """Mirrors binaryninja.binaryview.AnalysisProgress.

    ``state`` is stored as whatever the caller passes: the real core hands back a raw
    int in at least one of the info structs (observed live), and the plugin is expected
    to normalize through AnalysisState itself.
    """

    def __init__(self, state: int, count: int = 0, total: int = 0) -> None:
        self.state = state
        self.count = count
        self.total = total


class FakeActiveAnalysisInfo:
    """Mirrors binaryninja.binaryview.ActiveAnalysisInfo (rex_analysis_wait reads)."""

    def __init__(
        self,
        function: FakeFunction,
        analysis_time: int,
        update_count: int = 0,
        submit_count: int = 0,
    ) -> None:
        self.func = function
        self.analysis_time = analysis_time
        self.update_count = update_count
        self.submit_count = submit_count


class FakeAnalysisInfo:
    """Mirrors binaryninja.binaryview.AnalysisInfo (rex_analysis_wait reads)."""

    def __init__(
        self, state: int, analysis_time: int, active_info: list[FakeActiveAnalysisInfo]
    ) -> None:
        self.state = state
        self.analysis_time = analysis_time
        self.active_info = active_info


class FakeArchAndAddr:
    """Mirrors binaryninja.variable.ArchAndAddr: the definition site's arch and address."""

    def __init__(self, arch_name: str, addr: int) -> None:
        self.arch = FakeArchitecture(arch_name)
        self.addr = addr


class FakeFunction:
    def __init__(
        self,
        name: str,
        start: int,
        end: int,
        *,
        hlil: object = None,
        callers: list[FakeFunction] | None = None,
        callees: list[FakeFunction] | None = None,
        vars: list[FakeVariable] | None = None,
        mlil: FakeMediumLevelIL | FakeMLILInstructions | None = None,
        arch: FakeArchitecture | None = None,
        analysis_skipped: bool = False,
        analysis_skip_reason: FakeAnalysisSkipReason = FakeAnalysisSkipReason.NoSkipReason,
    ) -> None:
        self.arch = arch if arch is not None else FakeArchitecture("x86_64")
        self.analysis_skipped = analysis_skipped
        self.analysis_skip_reason = analysis_skip_reason
        self.name = name
        self.start = start
        self.end = end
        self.hlil = hlil
        self.callers = callers if callers is not None else []
        self.callees = callees if callees is not None else []
        self.comment = ""
        # Addressed comments, separate storage from the function-level ``comment``:
        # the real core keeps BNSetFunctionComment and BNSetCommentForAddress apart,
        # and get_comment_at answers "" wherever set_comment_at never ran.
        self.comments: dict[int, str] = {}
        self.user_type: object | None = None
        self.type: FakeType | None = None
        self.user_type_error: Exception | None = None
        self.vars = vars if vars is not None else []
        self.mlil = mlil
        # UIDF state: informed values keyed (variable, def-site address), the calls the
        # tools made, and per-operation error injection.
        self.user_var_values: dict[FakeVariable, dict[int, FakePossibleValueSet]] = {}
        self.set_user_var_value_calls: list[
            tuple[FakeVariable, int, FakePossibleValueSet, bool]
        ] = []
        self.cleared_user_var_values: list[tuple[FakeVariable, int]] = []
        self.cleared_all_user_var_values = 0
        self.set_user_var_value_error: Exception | None = None
        self.clear_user_var_value_error: Exception | None = None
        self.clear_all_user_var_values_error: Exception | None = None
        # Empty until "analyzed": the define tools' wait gates on the first block.
        self.basic_blocks: list[FakeBasicBlock] = []

    @property
    def highest_address(self) -> int:
        """Mirror Function.highest_address: the largest address the function contains.

        FakeFunction.end is exclusive for containment lookups, so the highest contained
        address is one below it.
        """
        return self.end - 1

    def set_user_type(self, value: object) -> None:
        if self.user_type_error is not None:
            raise self.user_type_error
        self.user_type = value

    def get_comment_at(self, address: int) -> str:
        return self.comments.get(address, "")

    def set_comment_at(self, address: int, comment: str) -> None:
        self.comments[address] = comment

    def _definition_addresses(self, variable: FakeVariable) -> list[int]:
        if self.mlil is None:
            return []
        return [definition.address for definition in self.mlil.get_var_definitions(variable)]

    def set_user_var_value(
        self, variable: FakeVariable, def_addr: int, value: FakePossibleValueSet, after: bool = True
    ) -> None:
        if self.set_user_var_value_error is not None:
            raise self.set_user_var_value_error
        if def_addr not in self._definition_addresses(variable):
            raise Exception("No definition for Variable found at given address")
        self.set_user_var_value_calls.append((variable, def_addr, value, after))
        self.user_var_values.setdefault(variable, {})[def_addr] = value

    def get_all_user_var_values(
        self,
    ) -> dict[FakeVariable, dict[FakeArchAndAddr, FakePossibleValueSet]]:
        return {
            variable: {
                FakeArchAndAddr("x86_64", address): value for address, value in sites.items()
            }
            for variable, sites in self.user_var_values.items()
        }

    def clear_user_var_value(
        self, variable: FakeVariable, def_addr: int, after: bool = True
    ) -> None:
        if self.clear_user_var_value_error is not None:
            raise self.clear_user_var_value_error
        if def_addr not in self._definition_addresses(variable):
            raise Exception("No definition for Variable found at given address")
        self.cleared_user_var_values.append((variable, def_addr))
        sites = self.user_var_values.get(variable)
        if sites is not None:
            sites.pop(def_addr, None)
            if not sites:
                del self.user_var_values[variable]

    def clear_all_user_var_values(self) -> None:
        if self.clear_all_user_var_values_error is not None:
            raise self.clear_all_user_var_values_error
        self.cleared_all_user_var_values += 1
        self.user_var_values.clear()


class FakeFileMetadata:
    """Mirrors the FileMetadata surface rex_binary_close and the undo/redo tools touch.

    undo()/redo() move one entry between the stacks the way BNUndo/BNRedo do, so the
    post-operation depth rex_undo/rex_redo report is observable; error injection models
    a core-side failure.
    """

    def __init__(self, filename: str = "") -> None:
        self.filename = filename
        self._modified = False
        self.saved_marks = 0
        self.closed = False
        self.close_error: Exception | None = None
        self.undo_entries: list[str] = []
        self.redo_entries: list[str] = []
        self.undo_error: Exception | None = None
        self.redo_error: Exception | None = None

    @property
    def modified(self) -> bool:
        return self._modified

    @modified.setter
    def modified(self, value: bool) -> None:
        self._modified = value
        if not value:
            self.saved_marks += 1

    def close(self) -> None:
        if self.close_error is not None:
            raise self.close_error
        self.closed = True

    def undo(self) -> None:
        if self.undo_error is not None:
            raise self.undo_error
        if self.undo_entries:
            self.redo_entries.append(self.undo_entries.pop())

    def redo(self) -> None:
        if self.redo_error is not None:
            raise self.redo_error
        if self.redo_entries:
            self.undo_entries.append(self.redo_entries.pop())


class FakeDataVariable:
    """Mirrors DataVariable, which is falsy exactly when its type is (zero width, e.g. void)."""

    def __init__(self, address: int, type_obj: FakeType) -> None:
        self.address = address
        self.type = type_obj

    def __len__(self) -> int:
        return len(self.type)


class FakeBinaryView:
    data_variable_types: Mapping[int, FakeType] = types.MappingProxyType({})

    def __init__(
        self,
        *,
        strings: list[FakeStringReference] | None = None,
        segments: list[FakeSegment] | None = None,
        functions: list[FakeFunction] | None = None,
        sections: dict[str, tuple[int, int]] | None = None,
        memory: dict[int, bytes] | None = None,
        start: int = 0,
        end: int = 0x10000,
        constant_references: list[tuple[int, int, FakeFunction | None]] | None = None,
        symbols: list[FakeSymbol] | None = None,
        entry_point: int = 0,
        analysis_progress_sequence: list[FakeAnalysisProgress] | None = None,
        analysis_info: FakeAnalysisInfo | None = None,
        file: FakeFileMetadata | None = None,
        arch: FakeArchitecture | None = None,
        library_types: dict[str, str | None] | None = None,
        code_refs: dict[int, list[FakeReferenceSource]] | None = None,
        data_refs: dict[int, list[int]] | None = None,
        types: dict[str, FakeType] | None = None,
        structure: FakeStructureType | None = None,
        defined_type_name: str | None = None,
        derived_strings: list[FakeDerivedString] | None = None,
        component_root: FakeComponent | None = None,
        relocations: list[FakeRelocation] | None = None,
        pending_functions: list[FakeFunction] | None = None,
        create_user_function_analyzes: bool = True,
    ) -> None:
        self.strings = strings if strings is not None else []
        self.segments = segments if segments is not None else []
        self.functions = functions if functions is not None else []
        self._sections: dict[str, tuple[int, int]] = sections or {}
        self._memory: dict[int, bytes] = memory or {}
        self._metadata: dict[str, object] = {}
        self._tags: list[tuple[int, FakeTag]] = []
        self._tag_types: dict[str, object] = {}
        self.written: list[tuple[int, bytes]] = []
        self.shown_reports: list[tuple[str, str, str]] = []
        self.created_functions: list[FakeFunction] = []
        self.removed_functions: list[FakeFunction] = []
        self.start = start
        self.end = end
        self.entry_point = entry_point
        # (value, address, function) triples answered by find_all_constant; a None
        # function models a match on a line that belongs to no function (data text).
        self.constant_references = constant_references or []
        self._symbols: list[FakeSymbol] = symbols if symbols is not None else []
        self.constant_scan_yields = 0
        # Set once progress_func declines, modeling the core honoring the abort.
        self.constant_scan_aborted: bool | None = None
        # rex_analysis_wait: successive analysis_progress reads walk this sequence; once
        # exhausted the last snapshot repeats, modeling an engine stuck in that state.
        self._analysis_progress_sequence = (
            analysis_progress_sequence
            if analysis_progress_sequence is not None
            else [FakeAnalysisProgress(FakeAnalysisState.IdleState)]
        )
        self._analysis_progress_index = 0
        self.analysis_info = (
            analysis_info
            if analysis_info is not None
            else FakeAnalysisInfo(FakeAnalysisState.IdleState, 0, [])
        )
        self.file = file if file is not None else FakeFileMetadata()
        # rex_annotate_many: transaction lifecycle markers in application order.
        self.transactions: list[str] = []
        # Injected into parse_type_string to model a type string the core rejects.
        self.parse_type_error: Exception | None = None
        # Type-system state for the type-library and struct-inference tools: ``arch`` is
        # Optional to model views without a default architecture; ``library_types`` maps a
        # requested name to the deconflicted name the core would insert (None fails the
        # import); ``structure`` is what create_structure_from_offset_access hands back
        # (None models the core refusing to build anything).
        self.arch = arch
        self._library_types = library_types or {}
        # Address -> code refs pointing at it, answered by get_code_refs.
        self._code_refs = code_refs or {}
        self.code_ref_requests: list[tuple[int, int | None]] = []
        # Address -> data-ref source addresses, answered by get_data_refs.
        self._data_refs = data_refs or {}
        self.data_ref_requests: list[tuple[int, int | None]] = []
        self._types = types or {}
        self._structure = structure
        self._defined_type_name = defined_type_name
        self.type_libraries: list[FakeTypeLibrary] = []
        self.imported_library_types: list[tuple[FakeTypeLibrary | None, str]] = []
        self.exported_types: list[tuple[FakeTypeLibrary, str, FakeType]] = []
        self.exported_objects: list[tuple[FakeTypeLibrary, str, FakeType]] = []
        self.defined_types: list[tuple[str, str, FakeStructureType]] = []
        self.derived_strings = derived_strings if derived_strings is not None else []
        # max_items values the tool sent with each derived-string code-ref request, in
        # order, so tests can pin the bounding contract without parsing responses.
        self.derived_code_ref_requests: list[int | None] = []
        # Every path handed to get_component_by_path, so tests can prove that paths the
        # installed API does not document (like "/") never reach the lookup.
        self.component_path_lookups: list[str] = []
        self._component_root = (
            component_root if component_root is not None else FakeComponent("__root__", "guid-root")
        )
        self._created_components: list[FakeComponent] = []
        self._relocations = relocations if relocations is not None else []
        # Defined functions the analysis engine has not produced blocks for yet: found by
        # get_function_at but invisible to get_functions_containing, mirroring the real
        # core's treatment of freshly created user functions.
        self._pending_functions = pending_functions if pending_functions is not None else []
        self.create_user_function_analyzes = create_user_function_analyzes
        # UIDF surface: every parse call's (spec, state, here) plus the scheduled updates.
        self.possible_value_parses: list[tuple[str, FakeRegisterValueType, int]] = []
        self.parse_possiblevalueset_error: Exception | None = None
        self.update_analysis_calls = 0

    def get_section_by_name(self, name: str) -> object:
        if name not in self._sections:
            return None
        start, end = self._sections[name]
        return types.SimpleNamespace(start=start, end=end)

    def find_all_constant(
        self,
        start: int,
        end: int,
        value: int,
        progress_func: Callable[[int, int], bool] | None = None,
    ) -> Iterator[tuple[int, FakeLinearDisassemblyLine]]:
        """Yield (address, line) matches in the order listed, aborting when progress declines."""
        matches = [
            (address, function)
            for matched_value, address, function in self.constant_references
            if matched_value == value and start <= address < end
        ]
        try:
            for address, function in matches:
                self.constant_scan_yields += 1
                yield address, FakeLinearDisassemblyLine(function)
        finally:
            # The core keeps scanning — and polling progress — after the caller stops
            # consuming matches, so model the shutdown poll even on an early break.
            if progress_func is not None and progress_func(self.end, self.end) is False:
                self.constant_scan_aborted = True

    def read(self, address: int, length: int) -> bytes:
        # Mirrors the real BinaryView.read: at most length bytes, silently shortened at
        # the end of the blob holding the address, empty when nothing is mapped there.
        # A stalled chunked scan would read below every readable segment forever.
        readable_starts = [segment.start for segment in self.segments if segment.readable]
        if address < 0 or (readable_starts and address < min(readable_starts)):
            raise AssertionError(f"read below the lowest readable segment: {address:#x}")
        for base, blob in self._memory.items():
            offset = address - base
            if 0 <= offset < len(blob):
                return blob[offset : offset + length]
        return b""

    def write(self, address: int, data: bytes) -> int:
        self.written.append((address, bytes(data)))
        return len(data)

    def get_functions_containing(self, address: int) -> list[FakeFunction]:
        return [f for f in self.functions if f.start <= address < f.end]

    def is_valid_offset(self, address: int) -> bool:
        """Mirror BinaryView.is_valid_offset: the address is mapped by the view.

        The real check consults the segment map. A fake view with no segments models one
        without segmentation, so fall back to its memory blobs and declared address range.
        """
        if address < 0:
            return False
        if self.segments:
            return any(
                segment.start <= address < segment.start + segment.length
                for segment in self.segments
            )
        if any(base <= address < base + len(blob) for base, blob in self._memory.items()):
            return True
        return self.start <= address < self.end

    def get_previous_function_start_before(self, address: int) -> int:
        """Mirror BinaryView.get_previous_function_start_before: 0 when none precedes."""
        starts = [function.start for function in self.functions if function.start < address]
        return max(starts) if starts else 0

    def get_functions_by_name(self, name: str) -> list[FakeFunction]:
        return [f for f in self.functions if f.name == name]

    @property
    def analysis_progress(self) -> FakeAnalysisProgress:
        index = min(self._analysis_progress_index, len(self._analysis_progress_sequence) - 1)
        self._analysis_progress_index += 1
        return self._analysis_progress_sequence[index]

    def get_symbols(self, start: int | None = None, length: int | None = None) -> list[FakeSymbol]:
        """Mirror BinaryView.get_symbols(start, length): address in [start, start+length)."""
        if start is None:
            return list(self._symbols)
        end = start + length if length is not None else None
        return [
            symbol
            for symbol in self._symbols
            if start <= symbol.address and (end is None or symbol.address < end)
        ]

    def get_string_at(self, address: int) -> object:
        for string in self.strings:
            if string.start == address:
                return string
        return None

    def relocations_at(self, addr: int) -> list[FakeRelocation]:
        # Mirrors the observed core lookup: a relocation matches any address in its
        # [info.address, info.address + info.size) span, and the list is echoed as
        # stored — duplicate entries included.
        return [
            relocation
            for relocation in self._relocations
            if relocation.info.address <= addr < relocation.info.address + relocation.info.size
        ]

    def get_function_at(self, address: int) -> FakeFunction | None:
        """Mirror BinaryView.get_function_at: exact start match, pending functions included."""
        for function in [*self.functions, *self._pending_functions]:
            if function.start == address:
                return function
        return None

    def create_user_function(self, address: int) -> FakeFunction:
        function = FakeFunction(f"sub_{address:x}", address, address + 1)
        if self.create_user_function_analyzes:
            function.basic_blocks = [FakeBasicBlock([(address, "push rbp")])]
        self.created_functions.append(function)
        self.functions.append(function)
        return function

    def remove_user_function(self, function: FakeFunction) -> None:
        self.removed_functions.append(function)

    def undo(self) -> None:
        # The real BinaryView.undo delegates to the file (binaryview.py self._file.undo()).
        self.file.undo()

    def redo(self) -> None:
        self.file.redo()

    def parse_type_string(self, text: str) -> tuple[str, str]:
        if self.parse_type_error is not None:
            raise self.parse_type_error
        return text, text

    def parse_possiblevalueset(
        self, value: str, state: FakeRegisterValueType, here: int = 0
    ) -> FakePossibleValueSet:
        self.possible_value_parses.append((value, state, here))
        if self.parse_possiblevalueset_error is not None:
            raise self.parse_possiblevalueset_error
        return parse_possible_value_set(value, state, here)

    def update_analysis(self) -> None:
        self.update_analysis_calls += 1

    @contextlib.contextmanager
    def undoable_transaction(self) -> Generator[None]:
        """Record the lifecycle the real context manager drives: commit, or revert + raise.

        A committed transaction also leaves one undo entry: the installed API documents
        ``BinaryView.undoable_transaction`` as creating "an Undo state containing those
        actions" (binaryview.py:5114-5117), so rex_undo reversing a committed batch is
        modelable here. Operations the API does not document as undoable (tag, metadata,
        type-library writes) push nothing, matching the provenance note on the undo tools
        in binja_plugin/tools/state.py.
        """
        self.transactions.append("open")
        try:
            yield
        except Exception:
            self.transactions.append("revert")
            raise
        self.transactions.append("commit")
        self.file.undo_entries.append("rex_annotate_many batch")

    @property
    def tag_types(self) -> dict[str, object]:
        return self._tag_types

    def create_tag_type(self, name: str, icon: str) -> None:
        self._tag_types[name] = types.SimpleNamespace(name=name, icon=icon)

    def add_tag(self, address: int, tag_type_name: str, data: str) -> None:
        self._tags.append((address, FakeTag(tag_type_name, data)))

    def get_tags(self) -> list[tuple[int, FakeTag]]:
        return list(self._tags)

    def store_metadata(self, key: str, value: object) -> None:
        self._metadata[key] = value

    def query_metadata(self, key: str) -> object:
        if key not in self._metadata:
            raise KeyError(key)
        return self._metadata[key]

    def remove_metadata(self, key: str) -> None:
        self._metadata.pop(key, None)

    def add_type_library(self, library: FakeTypeLibrary) -> None:
        self.type_libraries.append(library)

    def import_library_type(
        self, name: str, library: FakeTypeLibrary | None = None
    ) -> FakeType | None:
        self.imported_library_types.append((library, name))
        # Mirrors the core: an NTR comes back for every requested name. Names absent
        # from ``library_types`` get the requested name back and register nothing; a
        # None entry models the core returning no handle despite provision.
        resolved = self._library_types.get(name)
        if name not in self._library_types:
            return FakeType(name=name)
        if resolved is None:
            return None
        self._types[resolved] = FakeType(name=resolved)
        return FakeType(name=resolved)

    def get_symbols_by_name(self, name: str) -> list[FakeSymbol]:
        return [symbol for symbol in self._symbols if symbol.name == name]

    def get_data_var_at(self, address: int) -> FakeDataVariable | None:
        """Mirror BinaryView.get_data_var_at: a DataVariable-like with ``type``, or None."""
        if address not in self.data_variable_types:
            return None
        return FakeDataVariable(address, self.data_variable_types[address])

    def get_type_by_name(self, name: str) -> FakeType | None:
        return self._types.get(name)

    def export_type_to_library(
        self, library: FakeTypeLibrary, name: str, type_obj: FakeType
    ) -> None:
        self.exported_types.append((library, name, type_obj))

    def export_object_to_library(
        self, library: FakeTypeLibrary, name: str, type_obj: FakeType
    ) -> None:
        self.exported_objects.append((library, name, type_obj))

    def define_type(self, type_id: str, default_name: str, type_obj: FakeStructureType) -> str:
        self.defined_types.append((type_id, default_name, type_obj))
        return self._defined_type_name if self._defined_type_name is not None else default_name

    def create_structure_from_offset_access(self, name: str) -> FakeStructureType:
        # Mirrors the real wrapper's refusal (binaryview.py raises when the core hands
        # back no structure), so the failure path is exercised at the same layer.
        if self._structure is None:
            raise Exception(
                "BNCreateStructureFromOffsetAccess failed to create struct from offsets"
            )
        return self._structure

    def get_derived_string_code_refs(
        self, derived_string: FakeDerivedString, max_items: int | None = None
    ) -> Iterator[FakeReferenceSource]:
        # The real core bounds its own enumeration by max_items; mirror that so a request
        # for cap+1 items cannot silently return the whole unbounded list.
        self.derived_code_ref_requests.append(max_items)
        refs = list(derived_string.refs)
        if max_items is not None:
            refs = refs[:max_items]
        yield from refs

    def get_code_refs(
        self, addr: int, length: int | None = None, max_items: int | None = None
    ) -> Iterator[FakeReferenceSource]:
        # Same bounding contract as get_derived_string_code_refs above.
        self.code_ref_requests.append((addr, max_items))
        refs = list(self._code_refs.get(addr, []))
        if max_items is not None:
            refs = refs[:max_items]
        yield from refs

    def get_data_refs(
        self, addr: int, length: int | None = None, max_items: int | None = None
    ) -> Iterator[int]:
        # Same bounding contract as get_code_refs above.
        self.data_ref_requests.append((addr, max_items))
        refs = list(self._data_refs.get(addr, []))
        if max_items is not None:
            refs = refs[:max_items]
        yield from refs

    @property
    def root_component(self) -> FakeComponent:
        return self._component_root

    def create_component(
        self, name: str | None = None, parent: FakeComponent | None = None
    ) -> FakeComponent:
        # Mirrors the core's observed naming: an empty name leaves the component unnamed,
        # and duplicate sibling names get the automatic " (1)"-style suffix shown in the
        # installed get_component_by_path docstring example.
        parent = parent if parent is not None else self._component_root
        if name is None or not name:
            base = f"unnamed-{len(self._created_components) + 1}"
        else:
            base = name
        display_name = base
        suffix = 1
        while any(sibling.display_name == display_name for sibling in parent.children):
            display_name = f"{base} ({suffix})"
            suffix += 1
        component = FakeComponent(display_name, f"guid-{len(self._created_components) + 1}")
        parent.children.append(component)
        self._created_components.append(component)
        return component

    def get_component_by_path(self, path: str) -> FakeComponent | None:
        self.component_path_lookups.append(path)
        target: FakeComponent | None = self._component_root
        for part in path.split("/"):
            if not part or target is None:
                continue
            matches = [child for child in target.children if child.display_name == part]
            target = matches[0] if matches else None
        return target

    def show_markdown_report(self, title: str, contents: str, plaintext: str = "") -> None:
        """Record the exact arguments BinaryView.show_markdown_report hands the core."""
        self.shown_reports.append((title, contents, plaintext))


class SpyBinaryView(FakeBinaryView):
    """Records the address of every read and function lookup to bound scan work."""

    def __init__(self, **options: Any) -> None:
        super().__init__(**options)
        self.read_addresses: list[int] = []
        self.lookup_addresses: list[int] = []

    @override
    def read(self, address: int, length: int) -> bytes:
        self.read_addresses.append(address)
        return super().read(address, length)

    @override
    def get_functions_containing(self, address: int) -> list[FakeFunction]:
        self.lookup_addresses.append(address)
        return super().get_functions_containing(address)


X86_64_REGISTERS: Final = types.MappingProxyType(
    {
        98: "rax",
        99: "rcx",
        100: "rdx",
        104: "rsi",
        105: "rdi",
        106: "r8",
        107: "r9",
        112: "r14",
        333: "zmm0",
        2147483678: "temp30",
    }
)
X86_64_FLAGS: Final = types.MappingProxyType(
    {0: "c", 2: "p", 4: "a", 6: "z", 7: "s", 2147483648: "flag2147483648"}
)


class FakeArchitecture:
    """Mirrors Architecture: register and flag indexes the core knows resolve to names."""

    def __init__(
        self,
        name: str,
        registers: Mapping[int, str] = X86_64_REGISTERS,
        flags: Mapping[int, str] = X86_64_FLAGS,
    ) -> None:
        self.name = name
        self._registers = registers
        self._flags = flags

    def get_reg_name(self, reg: int) -> str:
        return self._registers[reg]

    def get_flag_name(self, flag: int) -> str:
        return self._flags[flag]


class FakeTypeClass(enum.IntEnum):
    """Mirrors binaryninja.enums.TypeClass."""

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


class FakeType:
    """Mirrors the Type surface the tools touch: str() is the rendered type string, and
    ``name`` models the deconflicted name of a NamedTypeReference (the documented return
    contract of import_library_type)."""

    def __init__(
        self,
        name: str,
        type_string: str = "",
        width: int = 0,
        type_class: FakeTypeClass = FakeTypeClass.IntegerTypeClass,
    ) -> None:
        self.name = name
        self._type_string = type_string
        self._width = width
        self.type_class = type_class

    @override
    def __str__(self) -> str:
        return self._type_string

    def __len__(self) -> int:
        """Mirrors Type.__len__, the width: void and function types are falsy on the real core."""
        return self._width

    @staticmethod
    def generate_auto_type_id(source: str, name: str) -> str:
        return f"auto:{source}:{name}"


class FakeStructureMember:
    def __init__(self, name: str, offset: int, type_obj: FakeType) -> None:
        self.name = name
        self.offset = offset
        self.type = type_obj


class FakeStructureType:
    def __init__(self, members: list[FakeStructureMember], width: int) -> None:
        self.members = members
        self.width = width


# Stands in for .bntl files on disk: tests register FakeTypeLibrary instances under the
# path load_from_file should find, mirroring TypeLibrary.load_from_file.
TYPE_LIBRARIES_ON_DISK: dict[str, FakeTypeLibrary] = {}


class FakeTypeLibrary:
    def __init__(
        self,
        name: str | None = None,
        arch: FakeArchitecture | None = None,
        file_bytes: bytes = b"BNTL",
        finalize_result: bool = True,
        write_error: OSError | None = None,
        named_types: dict[str, FakeType] | None = None,
    ) -> None:
        self.name = name
        self.arch = arch
        self.file_bytes = file_bytes
        self.finalize_result = finalize_result
        self.write_error = write_error
        # Names the library provides, answered by get_named_type; everything else is
        # absent from the library even though the view-level import still returns an NTR.
        self.named_types = named_types or {}
        self.finalized = False
        self.written_paths: list[str] = []

    def get_named_type(self, name: str) -> FakeType | None:
        return self.named_types.get(name)

    @staticmethod
    def load_from_file(path: str) -> FakeTypeLibrary | None:
        return TYPE_LIBRARIES_ON_DISK.get(path)

    @staticmethod
    def new(arch: FakeArchitecture, name: str) -> FakeTypeLibrary:
        return FakeTypeLibrary(name=name, arch=arch)

    def finalize(self) -> bool:
        self.finalized = True
        return self.finalize_result

    def write_to_file(self, path: str) -> None:
        # Writes real bytes so the tool's post-write size check sees the file, like the
        # core's BNWriteTypeLibraryToFile does.
        if self.write_error is not None:
            raise self.write_error
        with open(path, "wb") as handle:
            handle.write(self.file_bytes)
        self.written_paths.append(path)


class FakeDerivedStringLocation:
    """Mirrors binaryninja.binaryview.DerivedStringLocation."""

    def __init__(self, type_name: str, address: int, length: int) -> None:
        self.location_type = types.SimpleNamespace(name=type_name)
        self.address = address
        self.length = length


class FakeDerivedString:
    """Mirrors binaryninja.binaryview.DerivedString.

    ``value`` is a plain str here; the real core hands back a StringRef that tools
    convert with ``str()``. ``refs`` is the FakeReferenceSource list answered by
    FakeBinaryView.get_derived_string_code_refs for this exact object.
    """

    def __init__(
        self,
        value: str,
        location: FakeDerivedStringLocation | None = None,
        refs: list[FakeReferenceSource] | None = None,
    ) -> None:
        self.value = value
        self.location = location
        self.refs = refs if refs is not None else []


class FakeReferenceSource:
    """Mirrors the binaryninja.binaryview.ReferenceSource fields the tools read.

    ``arch`` is the architecture name, ``llil_operation`` the operation of the LLIL
    instruction at the reference site; the real ``llil`` property is None without a
    function or arch, or when no instruction exists at the address.
    """

    def __init__(
        self,
        function: FakeFunction | None,
        address: int,
        arch: str | None = None,
        llil_operation: int | None = None,
    ) -> None:
        self.function = function
        self.arch = None if arch is None else FakeArchitecture(arch)
        self.address = address
        self._llil_operation = llil_operation

    @property
    def llil(self) -> object | None:
        if self.function is None or self.arch is None or self._llil_operation is None:
            return None
        return types.SimpleNamespace(operation=self._llil_operation)


class FakeComponent:
    """Mirrors the binaryninja.component.Component surface rex_component_* tools read.

    ``add_function`` declines exactly the functions listed in ``rejected_functions`` so a
    failed core add can be modeled; successful adds are recorded for all-or-nothing
    assertions.
    """

    def __init__(
        self,
        display_name: str,
        guid: str,
        *,
        functions: list[FakeFunction] | None = None,
        children: list[FakeComponent] | None = None,
        rejected_functions: list[FakeFunction] | None = None,
    ) -> None:
        self.display_name = display_name
        self.name = display_name
        self.guid = guid
        self.functions = functions if functions is not None else []
        self.children = children if children is not None else []
        self.rejected_functions = rejected_functions if rejected_functions is not None else []
        self.added_functions: list[FakeFunction] = []

    @property
    def function_list(self) -> list[FakeFunction]:
        return list(self.functions)

    @property
    def components(self) -> list[FakeComponent]:
        return list(self.children)

    def add_function(self, function: FakeFunction) -> bool:
        if function in self.rejected_functions:
            return False
        self.added_functions.append(function)
        self.functions.append(function)
        return True


class FakeDisassemblyLine:
    """Mirrors the DisassemblyTextLine fields rex_disasm_at reads."""

    def __init__(self, address: int | None, text: str) -> None:
        self.address = address
        self.tokens = [text]


class FakeBasicBlock:
    def __init__(self, lines: list[tuple[int | None, str]]) -> None:
        self._lines = lines

    def get_disassembly_text(self) -> list[FakeDisassemblyLine]:
        return [FakeDisassemblyLine(address, text) for address, text in self._lines]
