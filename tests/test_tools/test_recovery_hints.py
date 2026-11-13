from __future__ import annotations

import pytest
from helpers import FakeParsingToolCall, FakeToolError, get_tool
from helpers_view import FakeBinaryView, FakeComponent, FakeFunction


def _error(tool_name: str, view: FakeBinaryView, *arguments: object, **keywords: object) -> str:
    _, tool = get_tool(tool_name)
    with pytest.raises(FakeToolError) as caught:
        tool(FakeParsingToolCall(view), *arguments, **keywords)
    return caught.value.message


def test_a_missing_tag_type_says_how_to_create_it() -> None:
    message = _error("rex_tag_set", FakeBinaryView(), 0x10, "Crashes", "x", create_missing=False)
    assert message == "no tag type named 'Crashes'; pass create_missing=true to create it"


def test_a_missing_kv_key_says_how_to_store_one() -> None:
    message = _error("rex_kv_get", FakeBinaryView(), "absent")
    assert message == "no value stored under 'absent'; store one with rex_kv_set"


def test_a_missing_component_names_the_tools_that_create_and_list() -> None:
    view = FakeBinaryView(component_root=FakeComponent("__root__", "guid-root"))
    assert _error("rex_component_get", view, "/Absent") == (
        "no component at path '/Absent'; "
        "rex_component_create makes one, rex_component_get lists the existing ones"
    )


def test_a_missing_string_names_the_tool_that_lists_strings() -> None:
    message = _error("rex_string_read_at", FakeBinaryView(), 0x1000)
    assert message == (
        "no string at 0x1000: none detected and no NUL-terminated ASCII text there; "
        "rex_data_read reads raw bytes and rex_string_search lists detected strings"
    )


def test_an_annotate_row_for_a_pending_function_says_to_wait_for_analysis() -> None:
    view = FakeBinaryView(pending_functions=[FakeFunction("sub_4000", 0x4000, 0x4010)])
    _, annotate = get_tool("rex_annotate_many")
    rows = annotate(FakeParsingToolCall(view), [{"addr": "0x4000", "name": "x"}])["results"]
    assert rows[0]["error"] == (
        "function at 0x4000 exists but has not been analyzed yet; wait for analysis "
        "(rex_analysis_wait, or rex_function_define with wait=true) or run bn_analysis_update"
    )
