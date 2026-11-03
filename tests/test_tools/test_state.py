from __future__ import annotations

import pytest
from helpers import FakeBinaryView, FakeFileMetadata, FakeToolError, _call, get_tool

from binja_plugin import tools
from binja_plugin.tools import state


def test_kv_set_get_delete_roundtrip() -> None:
    view = FakeBinaryView()
    _, kv_set = get_tool("rex_kv_set")
    _, kv_get = get_tool("rex_kv_get")
    _, kv_delete = get_tool("rex_kv_delete")
    assert kv_set(_call(view), "notes", "C2 at 0x401000") == {
        "key": "notes",
        "length": 14,
        "value": "C2 at 0x401000",
        "truncated": False,
    }
    assert kv_get(_call(view), "notes") == {
        "key": "notes",
        "value": "C2 at 0x401000",
        "truncated": False,
    }
    assert kv_delete(_call(view), "notes") == {"key": "notes"}
    with pytest.raises(FakeToolError) as exc:
        kv_get(_call(view), "notes")
    assert exc.value.code == "not_found"
    for name in ("rex_kv_set", "rex_kv_get", "rex_kv_delete"):
        _, function = get_tool(name)
        with pytest.raises(FakeToolError) as exc:
            if name == "rex_kv_set":
                function(_call(view), "", "")
            else:
                function(_call(view), "")
        assert exc.value.code == "invalid_key"


def test_kv_set_truncates_echo_and_rejects_oversized_value() -> None:
    view = FakeBinaryView()
    _, kv_set = get_tool("rex_kv_set")
    _, kv_get = get_tool("rex_kv_get")
    with pytest.raises(FakeToolError) as exc:
        kv_set(_call(view), "notes", "a" * (state._MAX_KV_VALUE_CHARS + 1))
    assert exc.value.code == "value_too_large"
    assert "aaaa" not in exc.value.message
    echoed = kv_set(_call(view), "notes", "a" * 600)
    assert echoed["length"] == 600
    assert echoed["truncated"] is True
    assert len(echoed["value"]) == 512 + len("... [88 chars truncated]")
    # The stored value is untouched; only the response echo is truncated.
    assert kv_get(_call(view), "notes")["value"] == "a" * 600
    # At exactly the echo cap the value comes back whole; one past it is truncated.
    exact = kv_set(_call(view), "exact", "c" * tools._MAX_CHARS)
    assert exact["value"] == "c" * tools._MAX_CHARS
    assert exact["truncated"] is False
    one_past = kv_set(_call(view), "exact", "c" * (tools._MAX_CHARS + 1))
    assert one_past["truncated"] is True
    assert one_past["value"] == "c" * tools._MAX_CHARS + "... [1 chars truncated]"


def test_kv_get_truncates_oversized_stored_value() -> None:
    view = FakeBinaryView()
    view.store_metadata("rex/legacy", "b" * (state._MAX_KV_VALUE_CHARS + 10))
    _, kv_get = get_tool("rex_kv_get")
    result = kv_get(_call(view), "legacy")
    assert result["truncated"] is True
    assert len(result["value"]) == state._MAX_KV_VALUE_CHARS + len("... [10 chars truncated]")


def test_kv_error_messages_truncate_key() -> None:
    view = FakeBinaryView()
    _, kv_get = get_tool("rex_kv_get")
    with pytest.raises(FakeToolError) as exc:
        kv_get(_call(view), "k" * 1000)
    assert exc.value.code == "not_found"
    assert "chars truncated]" in exc.value.message


def test_tag_set_creates_missing_type() -> None:
    view = FakeBinaryView()
    _, tag_set = get_tool("rex_tag_set")
    result = tag_set(_call(view), 0x4010, "Finding", "C2 config")
    assert result == {
        "address": "0x4010",
        "tag_type": "Finding",
        "data": "C2 config",
        "data_truncated": False,
        "length": 9,
    }
    assert "Finding" in view.tag_types
    tag_set(_call(view), 0x4020, "Finding", "second")
    assert [tag.data for _, tag in view.get_tags()] == ["C2 config", "second"]


def test_tag_set_caps_data_and_truncates_echo() -> None:
    view = FakeBinaryView()
    _, tag_set = get_tool("rex_tag_set")
    with pytest.raises(FakeToolError) as exc:
        tag_set(_call(view), 0x4010, "Finding", "d" * (state._MAX_TAG_DATA_CHARS + 1))
    assert exc.value.code == "data_too_large"
    assert "dddd" not in exc.value.message
    # A rejected call must have no side effects: no tag type created, no tag added, even
    # though the tag type check would have passed before the data check raised.
    assert view.tag_types == {}
    assert view.get_tags() == []
    # The data cap is checked before the tag type lookup regardless of create_missing.
    with pytest.raises(FakeToolError) as exc:
        tag_set(
            _call(view),
            0x4010,
            "Missing",
            "d" * (state._MAX_TAG_DATA_CHARS + 1),
            create_missing=False,
        )
    assert exc.value.code == "data_too_large"
    with pytest.raises(FakeToolError) as exc:
        tag_set(_call(view), 0x4010, "T" * 1000, "x", create_missing=False)
    assert exc.value.code == "tag_type_not_found"
    assert "chars truncated]" in exc.value.message
    # A name past the creation cap can only be echoed if the tag type already exists.
    view.create_tag_type("F" * 1000, "\u25c6")
    result = tag_set(_call(view), 0x4010, "F" * 1000, "d" * 600)
    assert result["tag_type"].endswith("chars truncated]")
    assert result["data_truncated"] is True
    assert len(result["data"]) == 512 + len("... [88 chars truncated]")
    assert result["length"] == 600
    # The stored tag data is untouched; only the response echo is truncated.
    assert [tag.data for _, tag in view.get_tags()] == ["d" * 600]


def test_tag_set_without_create_and_listing() -> None:
    view = FakeBinaryView()
    _, tag_set = get_tool("rex_tag_set")
    with pytest.raises(FakeToolError) as exc:
        tag_set(_call(view), 0x4010, "Missing", "x", create_missing=False)
    assert exc.value.code == "tag_type_not_found"
    view.add_tag(0x4010, "Finding", "a")
    view.add_tag(0x4020, "Finding", "b")
    _, tag_list = get_tool("rex_tag_list")
    result = tag_list(_call(view), limit=1)
    assert result["total"] == 2
    assert result["truncated"] is True
    assert result["tags"][0]["data"] == "a"
    assert result["tags"][0]["data_truncated"] is False


def test_tag_list_caps_limit_and_truncates_data() -> None:
    view = FakeBinaryView()
    view.add_tag(0x1000, "Finding", "a" * 600)
    for index in range(600):
        view.add_tag(0x2000 + index, "Finding", f"n{index}")
    _, tag_list = get_tool("rex_tag_list")
    result = tag_list(_call(view), limit=tools._MAX_LIMIT)
    assert result["total"] == 601
    assert len(result["tags"]) == tools._MAX_LIMIT
    assert result["truncated"] is True
    assert result["tags"][0]["data_truncated"] is True
    assert result["tags"][0]["data"].endswith("chars truncated]")
    assert result["tags"][1]["data_truncated"] is False


def test_tag_list_rejects_out_of_range_limit() -> None:
    view = FakeBinaryView()
    view.add_tag(0x1000, "Finding", "a")
    view.add_tag(0x1100, "Finding", "b")
    _, tag_list = get_tool("rex_tag_list")
    # A negative limit is invalid on its face: rejected, never normalized to 0.
    for limit in (-1, -100):
        with pytest.raises(FakeToolError) as exc:
            tag_list(_call(view), limit=limit)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == "Invalid integer parameter 'limit': Must be at least 0"
    with pytest.raises(FakeToolError) as exc:
        tag_list(_call(view), limit=tools._MAX_LIMIT + 1)
    assert exc.value.code == "invalid_params"
    assert exc.value.message == (
        f"Invalid integer parameter 'limit': Must be at most {tools._MAX_LIMIT}"
    )
    # limit=0 pages nothing out; unlike the scan tools, "total" stays the true total.
    assert tag_list(_call(view), limit=0) == {"total": 2, "truncated": True, "tags": []}


def test_tag_list_paginates_with_offset() -> None:
    view = FakeBinaryView()
    for index in range(4):
        view.add_tag(0x1000 + index, "Finding", f"t{index}")
    _, tag_list = get_tool("rex_tag_list")
    result = tag_list(_call(view), limit=2, offset=1)
    assert result == {
        "total": 4,
        "truncated": True,
        "tags": [
            {"address": "0x1001", "tag_type": "Finding", "data": "t1", "data_truncated": False},
            {"address": "0x1002", "tag_type": "Finding", "data": "t2", "data_truncated": False},
        ],
    }
    # A page starting past the end is empty and not truncated.
    assert tag_list(_call(view), limit=2, offset=4) == {
        "total": 4,
        "truncated": False,
        "tags": [],
    }
    # A negative offset is invalid on its face: rejected, never normalized to 0.
    with pytest.raises(FakeToolError) as exc:
        tag_list(_call(view), limit=2, offset=-1)
    assert exc.value.code == "invalid_params"
    assert exc.value.message == "Invalid integer parameter 'offset': Must be at least 0"


def test_tag_set_caps_new_tag_type_name() -> None:
    view = FakeBinaryView()
    _, tag_set = get_tool("rex_tag_set")
    with pytest.raises(FakeToolError) as exc:
        tag_set(_call(view), 0x4010, "T" * (state._MAX_TAG_TYPE_CHARS + 1), "x")
    assert exc.value.code == "tag_type_too_large"
    assert view.tag_types == {}
    # A long name that already exists is still usable; only creation is capped.
    view.create_tag_type("L" * 100, "\u25c6")
    result = tag_set(_call(view), 0x4010, "L" * 100, "x")
    assert result["tag_type"] == "L" * 100


def test_kv_set_caps_key_length() -> None:
    view = FakeBinaryView()
    _, kv_set = get_tool("rex_kv_set")
    _, kv_get = get_tool("rex_kv_get")
    with pytest.raises(FakeToolError) as exc:
        kv_set(_call(view), "k" * (state._MAX_KV_KEY_CHARS + 1), "value")
    assert exc.value.code == "key_too_large"
    # Nothing was stored under the rejected key.
    with pytest.raises(FakeToolError) as exc:
        kv_get(_call(view), "k" * (state._MAX_KV_KEY_CHARS + 1))
    assert exc.value.code == "not_found"
    # A key of exactly the cap is still accepted.
    boundary_key = "k" * state._MAX_KV_KEY_CHARS
    assert kv_set(_call(view), boundary_key, "value")["key"] == boundary_key
    assert view.query_metadata("rex/" + boundary_key) == "value"


def test_undo_and_redo_round_trip_and_report_stack_depths() -> None:
    metadata = FakeFileMetadata()
    metadata.undo_entries = ["patch bytes", "rename main"]
    view = FakeBinaryView(file=metadata)
    _, undo = get_tool("rex_undo")
    # Depths are the post-operation state: undo_left dropped, redo_left gained the entry.
    assert undo(_call(view)) == {"undone": True, "undo_left": 1, "redo_left": 1}
    assert metadata.undo_entries == ["patch bytes"]
    assert metadata.redo_entries == ["rename main"]
    _, redo = get_tool("rex_redo")
    assert redo(_call(view)) == {"redone": True, "undo_left": 2, "redo_left": 0}
    assert metadata.undo_entries == ["patch bytes", "rename main"]
    assert metadata.redo_entries == []
    # An empty stack is a core-side no-op reported as such, not an error.
    assert undo(_call(FakeBinaryView())) == {"undone": True, "undo_left": 0, "redo_left": 0}
    assert redo(_call(FakeBinaryView())) == {"redone": True, "undo_left": 0, "redo_left": 0}


def test_undo_and_redo_report_core_failures() -> None:
    metadata = FakeFileMetadata()
    metadata.undo_error = RuntimeError("no undo entries")
    view = FakeBinaryView(file=metadata)
    _, undo = get_tool("rex_undo")
    with pytest.raises(FakeToolError) as exc:
        undo(_call(view))
    assert exc.value.code == "undo_failed"
    assert "no undo entries" in exc.value.message
    metadata.redo_error = RuntimeError("no redo entries")
    _, redo = get_tool("rex_redo")
    with pytest.raises(FakeToolError) as exc:
        redo(_call(view))
    assert exc.value.code == "redo_failed"
    assert "no redo entries" in exc.value.message


def test_report_show_renders_the_markdown_report() -> None:
    view = FakeBinaryView()
    _, show = get_tool("rex_report_show")
    markdown = "# Triage\n\n- `main` at 0x1100: recv-then-stack-copy\n[binaryninja://?expr=main]\n"
    result = show(_call(view), title="Triage report", markdown=markdown)
    # The markdown goes to the core whole; the markdown itself doubles as the plaintext
    # fallback, so command-line hosts render the same report instead of nothing.
    assert view.shown_reports == [("Triage report", markdown, markdown)]
    assert result == {
        "title": "Triage report",
        "length": len(markdown),
        "preview": markdown,
        "truncated": False,
    }


def test_report_show_truncates_only_the_echoed_preview() -> None:
    view = FakeBinaryView()
    _, show = get_tool("rex_report_show")
    markdown = "a" * (tools._MAX_CHARS + 88)
    result = show(_call(view), title="r", markdown=markdown)
    assert view.shown_reports == [("r", markdown, markdown)]
    assert result["preview"] == "a" * tools._MAX_CHARS + "... [88 chars truncated]"
    assert result["truncated"] is True
    assert result["length"] == len(markdown)


def test_report_show_rejects_oversized_markdown_without_rendering() -> None:
    view = FakeBinaryView()
    _, show = get_tool("rex_report_show")
    with pytest.raises(FakeToolError) as exc:
        show(_call(view), title="r", markdown="x" * (state._MAX_REPORT_CONTENT_CHARS + 1))
    assert exc.value.code == "content_too_large"
    assert exc.value.message == f"markdown exceeds {state._MAX_REPORT_CONTENT_CHARS} characters"
    assert view.shown_reports == []


def test_report_show_rejects_oversized_title_without_rendering() -> None:
    view = FakeBinaryView()
    _, show = get_tool("rex_report_show")
    with pytest.raises(FakeToolError) as exc:
        show(_call(view), title="t" * (state._MAX_REPORT_TITLE_CHARS + 1), markdown="m")
    assert exc.value.code == "title_too_large"
    assert exc.value.message == f"title exceeds {state._MAX_REPORT_TITLE_CHARS} characters"
    assert view.shown_reports == []


def test_report_show_honors_both_caps_exactly() -> None:
    view = FakeBinaryView()
    _, show = get_tool("rex_report_show")
    title = "t" * state._MAX_REPORT_TITLE_CHARS
    markdown = "m" * state._MAX_REPORT_CONTENT_CHARS
    result = show(_call(view), title=title, markdown=markdown)
    assert view.shown_reports == [(title, markdown, markdown)]
    assert result["length"] == state._MAX_REPORT_CONTENT_CHARS
    assert result["truncated"] is True


def test_report_show_rejects_empty_title_and_markdown() -> None:
    view = FakeBinaryView()
    _, show = get_tool("rex_report_show")
    for kwargs, parameter in (
        ({"title": "", "markdown": "m"}, "title"),
        ({"title": "t", "markdown": ""}, "markdown"),
    ):
        with pytest.raises(FakeToolError) as exc:
            show(_call(view), **kwargs)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == f"{parameter} must not be empty"
    assert view.shown_reports == []


def test_report_show_is_read_only() -> None:
    options, _ = get_tool("rex_report_show")
    assert options == {"read_only": True}
