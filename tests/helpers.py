"""Fakes for exercising binja_plugin without a Binary Ninja installation."""

from __future__ import annotations

import contextlib
import enum
import inspect
import re
import sys
import types
from collections.abc import Callable, Generator, Iterator
from pathlib import Path
from typing import Any, override

import pytest

REGISTERED_TOOLS: list[tuple[str, dict[str, object], Any]] = []


class FakeToolError(Exception):
    def __init__(self, code: str, message: str, details: object = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details


def _fake_tool(name: str | None = None, **options: object):
    def decorate(function: Any) -> Any:
        tool_name = name or function.__name__
        # The real binaryninja.mcp.tool refuses to register a tool whose docstring has no
        # leading paragraph or whose parameters lack :param: lines, raising these same
        # TypeErrors at decoration time (installed mcp.py). Mirroring both checks keeps a
        # docstring strip that would kill real registration from passing these gates
        # against the fake.
        text = inspect.cleandoc(function.__doc__ or "")
        summary = re.split(r"\n\s*\n|\n(?=:)", text, maxsplit=1)[0]
        if not " ".join(line.strip() for line in summary.splitlines()):
            raise TypeError(f"MCP tool '{tool_name}' needs a docstring describing it")
        described = {
            match.group(1) for match in re.finditer(r"^:param\s+(\w+):", text, re.MULTILINE)
        }
        for parameter in list(inspect.signature(function).parameters)[1:]:
            if parameter not in described:
                raise TypeError(
                    f"MCP tool '{function.__name__}': parameter '{parameter}' "
                    f"needs a ':param {parameter}:' description"
                )
        REGISTERED_TOOLS.append((tool_name, options, function))
        return function

    return decorate


class FakeAddress(int):
    pass


class FakeIntegerExpression(int):
    pass


class FakeMinimum:
    """Mirrors binaryninja.mcp.Minimum; the fake decorator does not apply rejection."""

    def __init__(self, value: int) -> None:
        self.value = value


class FakeMaximum:
    """Mirrors binaryninja.mcp.Maximum; the fake decorator does not apply rejection."""

    def __init__(self, value: int) -> None:
        self.value = value


class FakeNonEmpty:
    """Mirrors binaryninja.mcp.NonEmpty; the fake decorator does not apply rejection."""

    def __init__(self) -> None:
        pass


class FakeToolCallBase:
    pass


def install_fake_binaryninja() -> None:
    """Create the fake binaryninja package in sys.modules when it is absent."""
    if "binaryninja" in sys.modules:
        return
    mcp_module = types.ModuleType("binaryninja.mcp")
    setattr(mcp_module, "tool", _fake_tool)
    setattr(mcp_module, "Address", FakeAddress)
    setattr(mcp_module, "IntegerExpression", FakeIntegerExpression)
    setattr(mcp_module, "ToolCall", FakeToolCallBase)
    setattr(mcp_module, "ToolError", FakeToolError)
    setattr(mcp_module, "Minimum", FakeMinimum)
    setattr(mcp_module, "Maximum", FakeMaximum)
    setattr(mcp_module, "NonEmpty", FakeNonEmpty)
    setattr(
        mcp_module,
        "McpToolScope",
        enum.IntEnum("McpToolScope", {"GlobalScope": 0, "BinaryViewScope": 1}),
    )
    setattr(
        mcp_module,
        "McpToolAnnotation",
        enum.IntFlag(
            "McpToolAnnotation",
            {"ReadOnlyHint": 1, "DestructiveHint": 2, "IdempotentHint": 4, "OpenWorldHint": 8},
        ),
    )

    bv_module = types.ModuleType("binaryninja.binaryview")

    class FakeBinaryViewBase:
        pass

    setattr(bv_module, "BinaryView", FakeBinaryViewBase)

    fn_module = types.ModuleType("binaryninja.function")

    class FakeFunctionBase:
        pass

    setattr(fn_module, "Function", FakeFunctionBase)

    enums_module = types.ModuleType("binaryninja.enums")
    setattr(enums_module, "AnalysisState", FakeAnalysisState)

    package = types.ModuleType("binaryninja")
    setattr(package, "mcp", mcp_module)
    setattr(package, "binaryview", bv_module)
    setattr(package, "function", fn_module)
    setattr(package, "enums", enums_module)
    setattr(package, "Type", FakeType)
    setattr(package, "TypeLibrary", FakeTypeLibrary)

    for name, module in (
        ("binaryninja", package),
        ("binaryninja.mcp", mcp_module),
        ("binaryninja.binaryview", bv_module),
        ("binaryninja.function", fn_module),
        ("binaryninja.enums", enums_module),
    ):
        sys.modules[name] = module
    REGISTERED_TOOLS.clear()
    TYPE_LIBRARIES_ON_DISK.clear()


class FakeSegment:
    def __init__(self, start: int, length: int) -> None:
        self.start = start
        self.length = length


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


class FakeSymbol:
    """Mirrors the CoreSymbol fields rex_export_symbols reads.

    ``type`` is a namespace with ``name`` like the other fakes, mirroring the enum
    member the real core hands back.
    """

    def __init__(self, address: int, type_name: str, name: str) -> None:
        self.address = address
        self.type = types.SimpleNamespace(name=type_name)
        self.name = name


class FakeAnalysisState(enum.IntEnum):
    """Mirrors binaryninja.enums.AnalysisState."""

    InitialState = 0
    HoldState = 1
    IdleState = 2
    DiscoveryState = 3
    DisassembleState = 4
    AnalyzeState = 5
    ExtendedAnalyzeState = 6


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
    ) -> None:
        self.name = name
        self.start = start
        self.end = end
        self.hlil = hlil
        self.callers = callers if callers is not None else []
        self.callees = callees if callees is not None else []
        self.comment = ""
        self.user_type: object | None = None
        self.user_type_error: Exception | None = None

    def set_user_type(self, value: object) -> None:
        if self.user_type_error is not None:
            raise self.user_type_error
        self.user_type = value


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


class FakeBinaryView:
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
        types: dict[str, FakeType] | None = None,
        structure: FakeStructureType | None = None,
        defined_type_name: str | None = None,
        derived_strings: list[FakeDerivedString] | None = None,
        component_root: FakeComponent | None = None,
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
        """Yield (address, line) matches in address order, aborting when progress declines."""
        matches = sorted(
            (
                (address, function)
                for matched_value, address, function in self.constant_references
                if matched_value == value and start <= address < end
            ),
            key=lambda match: match[0],
        )
        try:
            for address, function in matches:
                self.constant_scan_yields += 1
                yield address, FakeLinearDisassemblyLine(function)
        finally:
            # The core keeps scanning — and polling progress — after the caller stops
            # consuming matches, so model the shutdown poll even on an early break.
            if progress_func is not None and progress_func(self.end, self.end) is False:
                self.constant_scan_aborted = True

    def read(self, address: int, length: int) -> bytes | None:
        for base, blob in self._memory.items():
            offset = address - base
            if 0 <= offset < len(blob):
                return blob[offset : offset + length]
        return None

    def write(self, address: int, data: bytes) -> int:
        self.written.append((address, bytes(data)))
        return len(data)

    def get_functions_containing(self, address: int) -> list[FakeFunction]:
        return [f for f in self.functions if f.start <= address < f.end]

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

    def create_user_function(self, address: int) -> FakeFunction:
        function = FakeFunction(f"sub_{address:x}", address, address + 1)
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
    def read(self, address: int, length: int) -> bytes | None:
        self.read_addresses.append(address)
        return super().read(address, length)

    @override
    def get_functions_containing(self, address: int) -> list[FakeFunction]:
        self.lookup_addresses.append(address)
        return super().get_functions_containing(address)


class FakeToolCall:
    def __init__(self, binary_view: FakeBinaryView) -> None:
        self.binary_view = binary_view


class FakeArchitecture:
    def __init__(self, name: str) -> None:
        self.name = name


class FakeType:
    """Mirrors the Type surface the tools touch: str() is the rendered type string, and
    ``name`` models the deconflicted name of a NamedTypeReference (the documented return
    contract of import_library_type)."""

    def __init__(self, name: str, type_string: str = "") -> None:
        self.name = name
        self._type_string = type_string

    @override
    def __str__(self) -> str:
        return self._type_string

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


def get_tool(name: str) -> tuple[dict[str, object], Any]:
    for tool_name, options, function in REGISTERED_TOOLS:
        if tool_name == name:
            return options, function
    raise KeyError(name)


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
    """Mirrors the binaryninja.binaryview.ReferenceSource fields the tools read."""

    def __init__(self, function: FakeFunction | None, address: int) -> None:
        self.function = function
        self.address = address


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


# --- view builders and tool-call fakes shared by the per-category tool test modules ----------


def _call(view: FakeBinaryView) -> FakeToolCall:
    return FakeToolCall(view)


def _view_with_functions() -> FakeBinaryView:
    main = FakeFunction(
        "main",
        0x1100,
        0x1200,
        hlil=RenderableText("void main() {\n    if (recv(fd, buf, n) <= 0)\n        return 1;\n}"),
    )
    handler = FakeFunction("handler", 0x2000, 0x2100)
    sink = FakeFunction("sink", 0x3000, 0x3100)
    main.callers = [handler]
    handler.callers = [sink]
    sink.callees = [handler]
    handler.callees = [main]
    return FakeBinaryView(functions=[main, handler, sink])


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


class FakeDisasmFunction(FakeFunction):
    """FakeFunction with the basic_blocks attribute rex_disasm_at reads."""

    def __init__(
        self,
        name: str,
        start: int,
        end: int,
        blocks: list[FakeBasicBlock],
        hlil: object = None,
    ) -> None:
        super().__init__(name, start, end, hlil=hlil)
        self.basic_blocks = blocks


def _disasm_view() -> FakeBinaryView:
    main = FakeDisasmFunction(
        "main",
        0x1100,
        0x1200,
        blocks=[
            FakeBasicBlock(
                [
                    (0x1100, "push rbp"),
                    (0x1101, "mov rbp, rsp"),
                    (0x1104, "sub rsp, 0x20"),
                    (0x1108, "mov eax, 1"),
                    (0x110D, "leave"),
                    (0x110E, "ret"),
                ]
            )
        ],
    )
    handler = FakeDisasmFunction(
        "handler", 0x2000, 0x2100, blocks=[FakeBasicBlock([(0x2000, "push rbp"), (0x2001, "ret")])]
    )
    return FakeBinaryView(functions=[main, handler])


class FakeParsingToolCall(FakeToolCall):
    """FakeToolCall with the parse_address surface rex_decompile_many/rex_quick_main read.

    Deliberately raises a plain ValueError for unparsable input instead of a ToolError:
    the handler owns the conversion of expression-parse failures to invalid_params, so
    the fake must not hand it an error to pass through. ``data_<hex>`` tokens resolve the
    way the core's address-expression parser was observed to resolve them live.
    """

    def parse_address(self, value: object, here: int = 0) -> int:
        text = value if isinstance(value, str) else str(value)
        try:
            return int(text, 16) if text.lower().startswith("0x") else int(text, 10)
        except ValueError:
            pass
        if text.startswith("data_"):
            return int(text[5:], 16)
        raise ValueError(f"unparsable address expression '{text}'") from None


def _use_export_root(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Point the export tools at a per-test root so nothing lands in the real home."""
    # Deferred: helpers is imported before the fake binaryninja is installed, so a
    # module-level binja_plugin import here would pull in the real (absent) package.
    from binja_plugin import tools

    root = tmp_path / "exports"
    monkeypatch.setattr(tools, "_EXPORT_ROOT", root)
    return root
