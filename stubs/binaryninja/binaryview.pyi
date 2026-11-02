from collections.abc import Callable, Iterator, Mapping
from typing import Any

from binaryninja.component import Component
from binaryninja.enums import AnalysisState, DerivedStringLocationType
from binaryninja.filemetadata import FileMetadata
from binaryninja.function import Function


class LinearDisassemblyLine:
    """One rendered line of the linear view; function is None for non-function lines."""

    function: Function | None


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

    def get_section_by_name(self, name: str) -> Section | None: ...
    def get_functions_by_name(
        self, name: str, plat: Any = None, ordered_filter: Any = None
    ) -> list[Function]: ...
    def find_all_constant(
        self,
        start: int,
        end: int,
        constant: int,
        progress_func: Callable[[int, int], bool] | None = None,
    ) -> Iterator[tuple[int, LinearDisassemblyLine]]: ...
    def read(self, address: int, length: int) -> bytes: ...
    def write(self, address: int, data: bytes) -> int: ...
    def get_functions_containing(self, address: int) -> list[Function]: ...
    def create_user_function(self, address: int) -> Function | None: ...
    def remove_user_function(self, function: Function) -> None: ...
    def get_string_at(self, address: int, partial: bool = False) -> StringReference | None: ...
    def get_tags(self, auto: bool | None = None) -> list[tuple[int, Tag]]: ...
    def add_tag(self, address: int, tag_type_name: str, data: str, user: bool = True) -> None: ...
    def create_tag_type(self, name: str, icon: str) -> Any: ...
    def store_metadata(self, key: str, md: Any, **kwargs: Any) -> None: ...
    def query_metadata(self, key: str) -> Any: ...
    def remove_metadata(self, key: str) -> None: ...
    derived_strings: list[DerivedString]
    root_component: Component

    def create_component(
        self, name: str | None = None, parent: Component | str | None = None
    ) -> Component: ...
    def get_component_by_path(self, path: str) -> Component | None: ...
    def get_derived_string_code_refs(
        self, derived_string: DerivedString, max_items: int | None = None
    ) -> Iterator[ReferenceSource]: ...


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
