from collections.abc import Callable, Iterator, Mapping
from typing import Any

from binaryninja.component import Component
from binaryninja.enums import (
    AnalysisState,
    DerivedStringLocationType,
    RegisterValueType,
    RelocationType,
    SymbolBinding,
    SymbolType,
)
from binaryninja.filemetadata import FileMetadata
from binaryninja.function import DisassemblyTextLine, Function
from binaryninja.types import NamedTypeReferenceType, NameSpace, QualifiedName, StructureType, Symbol, Type
from binaryninja.variable import PossibleValueSet


class LinearDisassemblyLine:
    """One rendered line of the linear view; function is None for non-function lines."""

    function: Function | None
    contents: DisassemblyTextLine


class Section:
    start: int
    end: int
    name: str
    length: int


class StringReference:
    def __len__(self) -> int: ...
    @property
    def value(self) -> str: ...
    @property
    def raw(self) -> bytes: ...
    @property
    def type(self) -> Any: ...
    @property
    def start(self) -> int: ...
    @property
    def length(self) -> int: ...


class Tag:
    @property
    def type(self) -> Any: ...
    @property
    def data(self) -> str: ...
    @property
    def id(self) -> str: ...


class ActiveAnalysisInfo:
    """One function currently under analysis; times are in milliseconds."""

    func: Function
    analysis_time: int
    update_count: int
    submit_count: int


class AnalysisInfo:
    state: AnalysisState
    analysis_time: int
    active_info: list[ActiveAnalysisInfo]


class AnalysisProgress:
    state: AnalysisState
    count: int
    total: int


class RelocationInfo:
    type: RelocationType
    pc_relative: bool
    base_relative: bool
    base: int
    size: int
    truncate_size: int
    native_type: int
    addend: int
    has_sign: bool
    implicit_addend: bool
    external: bool
    symbol_index: int
    section_index: int
    address: int
    target: int
    data_relocation: bool


class CoreSymbol:
    full_name: str
    address: int
    type: SymbolType
    binding: SymbolBinding
    namespace: NameSpace
    ordinal: int


class Relocation:
    @property
    def info(self) -> RelocationInfo: ...
    @property
    def target(self) -> int: ...
    @property
    def reloc(self) -> int: ...
    @property
    def symbol(self) -> CoreSymbol | None: ...


class DataVariable:
    address: int
    type: Type


class BinaryView:
    strings: list[StringReference]
    segments: list[Any]
    functions: list[Function]
    tag_types: Mapping[str, Any]
    start: int
    end: int
    entry_point: int
    analysis_progress: AnalysisProgress
    analysis_info: AnalysisInfo
    file: FileMetadata
    arch: Any

    def get_section_by_name(self, name: str) -> Section | None: ...
    def get_functions_by_name(
        self, name: str, plat: Any = None, ordered_filter: Any = None
    ) -> list[Function]: ...
    def get_symbols_by_name(
        self, name: str, namespace: Any = None, ordered_filter: Any = None
    ) -> list[CoreSymbol]: ...
    def get_data_var_at(self, addr: int) -> DataVariable | None: ...
    def find_all_constant(
        self,
        start: int,
        end: int,
        constant: int,
        progress_func: Callable[[int, int], bool] | None = None,
    ) -> Iterator[tuple[int, LinearDisassemblyLine]]: ...
    def read(self, address: int, length: int) -> bytes: ...
    def relocations_at(self, addr: int) -> list[Relocation]: ...
    def write(self, address: int, data: bytes) -> int: ...
    def get_functions_containing(self, address: int) -> list[Function]: ...
    def get_function_at(self, address: int) -> Function | None: ...
    def get_functions_at(self, address: int) -> list[Function]: ...
    def get_previous_function_start_before(self, address: int) -> int: ...
    def is_valid_offset(self, address: int) -> bool: ...
    def create_user_function(self, address: int) -> Function | None: ...
    def remove_user_function(self, function: Function) -> None: ...
    def get_string_at(self, address: int, partial: bool = False) -> StringReference | None: ...
    def get_tags(self, auto: bool | None = None) -> list[tuple[int, Tag]]: ...
    @property
    def tags_for_data(self) -> list[tuple[int, Tag]]: ...
    @property
    def tags_for_address(self) -> list[tuple[int, Tag]]: ...
    @property
    def tags_for_function(self) -> list[tuple[int, Tag]]: ...
    @property
    def metadata(self) -> dict[str, Any]: ...
    def add_tag(self, address: int, tag_type_name: str, data: str, user: bool = True) -> None: ...
    def create_tag_type(self, name: str, icon: str) -> Any: ...
    def store_metadata(self, key: str, md: Any, **kwargs: Any) -> None: ...
    def query_metadata(self, key: str) -> Any: ...
    def remove_metadata(self, key: str) -> None: ...
    def parse_type_string(
        self, text: str, import_dependencies: bool = True
    ) -> tuple[Type, QualifiedName]: ...
    def parse_possiblevalueset(
        self, value: str, state: RegisterValueType, here: int = 0
    ) -> PossibleValueSet: ...
    def update_analysis(self) -> None: ...
    def undo(self) -> None: ...
    def redo(self) -> None: ...
    def define_user_symbol(self, sym: Symbol) -> None: ...
    def undoable_transaction(self) -> Any: ...
    def add_type_library(self, lib: Any) -> None: ...
    def import_library_type(self, name: str, lib: Any = None) -> NamedTypeReferenceType | None: ...
    def export_type_to_library(self, lib: Any, name: str | None, type_obj: Any) -> None: ...
    def export_object_to_library(self, lib: Any, name: str | None, type_obj: Any) -> None: ...
    def get_type_by_name(self, name: Any) -> Type | None: ...
    def define_type(self, type_id: str, default_name: Any, type_obj: Any) -> Any: ...
    def create_structure_from_offset_access(self, name: Any) -> StructureType: ...
    derived_strings: list[DerivedString]
    root_component: Component

    def create_component(
        self, name: str | None = None, parent: Component | str | None = None
    ) -> Component: ...
    def get_component_by_path(self, path: str) -> Component | None: ...
    def get_derived_string_code_refs(
        self, derived_string: DerivedString, max_items: int | None = None
    ) -> Iterator[ReferenceSource]: ...
    def get_code_refs(
        self, addr: int, length: int | None = None, max_items: int | None = None
    ) -> Iterator[ReferenceSource]: ...
    def get_data_refs(
        self, addr: int, length: int | None = None, max_items: int | None = None
    ) -> Iterator[int]: ...
    def show_markdown_report(self, title: str, contents: str, plaintext: str = "") -> None: ...


class StringRef:
    """Deduplicated reference to a string owned by the core; convert with str()."""

    def __len__(self) -> int: ...
    def __str__(self) -> str: ...


class DerivedStringLocation:
    location_type: DerivedStringLocationType
    address: int
    length: int


class DerivedString:
    value: StringRef
    location: DerivedStringLocation | None
    custom_type: Any


class ReferenceSource:
    function: Function | None
    arch: Any
    address: int
    llil: Any
