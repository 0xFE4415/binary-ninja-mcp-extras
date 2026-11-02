"""Fakes for exercising binja_plugin without a Binary Ninja installation."""

from __future__ import annotations

import enum
import sys
import types
from collections.abc import Callable, Iterator
from typing import Any, override

REGISTERED_TOOLS: list[tuple[str, dict[str, object], Any]] = []


class FakeToolError(Exception):
    def __init__(self, code: str, message: str, details: object = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details


def _fake_tool(name: str | None = None, **options: object):
    def decorate(function: Any) -> Any:
        REGISTERED_TOOLS.append((name or function.__name__, options, function))
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


class FakeFileMetadata:
    """Mirrors the FileMetadata surface rex_binary_close touches."""

    def __init__(self, filename: str = "") -> None:
        self.filename = filename
        self._modified = False
        self.saved_marks = 0
        self.closed = False
        self.close_error: Exception | None = None

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
        resolved = self._library_types.get(name)
        return FakeType(name=resolved) if resolved is not None else None

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
    ) -> None:
        self.name = name
        self.arch = arch
        self.file_bytes = file_bytes
        self.finalize_result = finalize_result
        self.write_error = write_error
        self.finalized = False
        self.written_paths: list[str] = []

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
