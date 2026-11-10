"""String tools: static string search, point reads, and code references to strings."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from functools import partial
from typing import TYPE_CHECKING, Annotated, Literal

from binaryninja import mcp

from binja_plugin.tools import (
    _MAX_CHARS,
    _MAX_LIMIT,
    _compile_user_regex,
    _paginate,
    _resolve_section,
    _truncate,
    _truncate_with_flag,
    _validate_range,
)

if TYPE_CHECKING:
    from binaryninja.binaryview import (
        BinaryView,
        DerivedString,
        ReferenceSource,
        StringReference,
    )

_MAX_STRING_READ_CHARS = 4096

# Core calls use max_items = cap + 1, so truncation is detected without enumerating past the cap.
_MAX_STRING_REFS = 64

StringType = Literal["AsciiString", "Utf16String", "Utf32String", "Utf8String"]


def _text_matcher(pattern: str, regex: bool, ignore_case: bool) -> Callable[[str], bool]:
    if regex:
        compiled = _compile_user_regex("pattern", pattern, ignore_case=ignore_case)
        return lambda value: compiled.search(value) is not None
    if ignore_case:
        needle = pattern.lower()
        return lambda value: needle in value.lower()
    return lambda value: pattern in value


def _string_reference_entry(
    value: str,
    location: dict[str, object] | None,
    derived: bool,
    refs: list[ReferenceSource],
) -> dict[str, object]:
    return {
        "value": _truncate(value),
        "location": location,
        "derived": derived,
        "refs": [
            {
                "function_start": None if ref.function is None else hex(ref.function.start),
                "function_name": None if ref.function is None else _truncate(ref.function.name),
                "address": hex(ref.address),
            }
            for ref in refs[:_MAX_STRING_REFS]
        ],
        "refs_truncated": len(refs) > _MAX_STRING_REFS,
    }


def _detected_string_entry(view: BinaryView, string: StringReference) -> dict[str, object]:
    refs = list(view.get_code_refs(string.start, max_items=_MAX_STRING_REFS + 1))
    location: dict[str, object] = {
        "type": string.type.name,
        "address": hex(string.start),
        "length": len(string),
    }
    return _string_reference_entry(str(string.value), location, False, refs)


def _derived_string_entry(view: BinaryView, string: DerivedString) -> dict[str, object]:
    refs = list(view.get_derived_string_code_refs(string, max_items=_MAX_STRING_REFS + 1))
    string_location = string.location
    location: dict[str, object] | None = (
        None
        if string_location is None
        else {
            "type": string_location.location_type.name,
            "address": hex(string_location.address),
            "length": string_location.length,
        }
    )
    return _string_reference_entry(str(string.value), location, True, refs)


@mcp.tool(read_only=True)
def rex_string_refs(
    call: mcp.ToolCall,
    pattern: str = "",
    regex: bool = False,
    ignore_case: bool = False,
    limit: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_LIMIT)] = 20,
    offset: Annotated[int, mcp.Minimum(0)] = 0,
) -> dict[str, object]:
    """Code references to the view's detected strings, recognizer-synthesized ones included.

    :param pattern: Substring or regular expression to match; empty matches every string.
    :param regex: Treat pattern as a regular expression instead of a substring.
    :param ignore_case: Match case-insensitively.
    :param limit: Maximum strings to return.
    :param offset: Matching strings to skip before collecting results.
    """
    bv = call.binary_view
    limit = _validate_range("limit", limit, 0, _MAX_LIMIT)
    offset = _validate_range("offset", offset, 0)
    matches_text = _text_matcher(pattern, regex, ignore_case)

    def keep(string: StringReference | DerivedString) -> bool:
        # str() is total: the API layer falls back to charmap decoding for non-UTF-8 bytes.
        return matches_text(str(string.value))

    def entry_builders() -> Iterator[Callable[[], dict[str, object]]]:
        for string in bv.strings:
            if keep(string):
                yield partial(_detected_string_entry, bv, string)
        for derived_string in bv.derived_strings:
            if keep(derived_string):
                yield partial(_derived_string_entry, bv, derived_string)

    page, total, truncated = _paginate(entry_builders(), offset, limit)
    strings = [build_entry() for build_entry in page]
    return {"total": total, "truncated": truncated, "strings": strings}


@mcp.tool(read_only=True)
def rex_string_read_at(
    call: mcp.ToolCall,
    addr: mcp.Address,
    max_chars: Annotated[int, mcp.Minimum(1), mcp.Maximum(_MAX_STRING_READ_CHARS)] = _MAX_CHARS,
) -> dict[str, object]:
    """Read the detected string at an address.

    :param addr: Address of the string.
    :param max_chars: Characters past this are truncated from the echoed value.
    """
    max_chars = _validate_range("max_chars", max_chars, 1, _MAX_STRING_READ_CHARS)
    string = call.binary_view.get_string_at(addr)
    if string is None:
        raise mcp.ToolError("no_string", f"no detected string at {addr:#x}")
    value, truncated = _truncate_with_flag(string.value, max_chars)
    return {
        "address": hex(string.start),
        "length": len(string),
        "type": string.type.name,
        "value": value,
        "truncated": truncated,
    }


@mcp.tool(read_only=True)
def rex_string_search(
    call: mcp.ToolCall,
    pattern: str = "",
    regex: bool = False,
    ignore_case: bool = False,
    section: str | None = None,
    string_type: StringType | None = None,
    limit: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_LIMIT)] = 50,
    offset: Annotated[int, mcp.Minimum(0)] = 0,
) -> dict[str, object]:
    """Search the binary's detected strings by substring or regular expression.

    :param pattern: Substring or regular expression to match; empty matches every string.
    :param regex: Treat pattern as a regular expression instead of a substring.
    :param ignore_case: Match case-insensitively.
    :param section: Only include strings within this section.
    :param string_type: Only include strings of this type.
    :param limit: Maximum strings to return.
    :param offset: Matching strings to skip before collecting results.
    """
    bv = call.binary_view
    limit = _validate_range("limit", limit, 0, _MAX_LIMIT)
    offset = _validate_range("offset", offset, 0)
    matches_text = _text_matcher(pattern, regex, ignore_case)
    bounds = _resolve_section(bv, section) if section is not None else None

    def keep(string: StringReference) -> bool:
        if string_type is not None and string.type.name != string_type:
            return False
        if bounds is not None and not bounds[0] <= string.start < bounds[1]:
            return False
        return matches_text(string.value)

    page, total, truncated = _paginate(filter(keep, bv.strings), offset, limit)
    found = [
        {
            "address": hex(string.start),
            "length": len(string),
            "type": string.type.name,
            "value": _truncate(string.value),
        }
        for string in page
    ]
    return {"total": total, "truncated": truncated, "strings": found}
