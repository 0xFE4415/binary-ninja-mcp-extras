from __future__ import annotations

import pytest
from helpers import (
    NO_ALTERNATIVES,
    FakeParsingToolCall,
    FakeToolError,
    _call,
    get_tool,
    plain_gap_message,
)
from helpers_symbol import FakeSymbolBinding, FakeSymbolType
from helpers_view import (
    FakeBinaryView,
    FakeFunction,
    undo_entry,
)

from binja_plugin.tools import annotations as annotations_tools


def _annotate_view() -> FakeBinaryView:
    main = FakeFunction("main", 0x1100, 0x1200)
    helper = FakeFunction("helper", 0x2000, 0x2100)
    return FakeBinaryView(functions=[main, helper])


def test_annotate_many_rename_keeps_symbol_type_binding_namespace_and_ordinal() -> None:
    exported = FakeFunction(
        "dup_mid",
        0x1100,
        0x1200,
        symbol_type="LibraryFunctionSymbol",
        symbol_binding=FakeSymbolBinding.GlobalBinding,
    )
    exported.symbol.namespace = "ns"
    exported.symbol.ordinal = 7
    view = FakeBinaryView(functions=[exported])
    _, annotate = get_tool("rex_annotate_many")
    annotate(FakeParsingToolCall(view), [{"addr": "0x1100", "name": "renamed"}])
    symbol = exported.symbol
    assert (symbol.name, symbol.address) == ("renamed", 0x1100)
    assert symbol.type == FakeSymbolType.LibraryFunctionSymbol
    assert symbol.binding == FakeSymbolBinding.GlobalBinding
    assert symbol.namespace == "ns"
    assert symbol.ordinal == 7


def test_annotate_many_applies_name_comment_and_prototype_in_one_transaction() -> None:
    view = _annotate_view()
    main, helper = view.functions
    _, annotate = get_tool("rex_annotate_many")
    result = annotate(
        FakeParsingToolCall(view),
        [
            {"addr": "0x1150", "name": "read_config", "comment": "parses rc file"},
            {"addr": 0x2000, "prototype": "int helper(int fd)"},
        ],
    )
    # A comment-bearing row echoes the exact address the comment lands on; name and
    # prototype are function-level, so their rows echo the function start. "failed" is
    # this tool's legacy count key; "applied"/"failed_count"/"total" are the uniform
    # batch-summary keys every batch tool now carries.
    assert result == {
        "applied": 2,
        "failed": 0,
        "failed_count": 0,
        "total": 2,
        "results": [
            {
                "addr": "0x1150",
                "ok": True,
                "function": {"start": "0x1100", "name": "read_config", **NO_ALTERNATIVES},
            },
            {
                "addr": "0x2000",
                "ok": True,
                "function": {"start": "0x2000", "name": "helper", **NO_ALTERNATIVES},
            },
        ],
    }
    assert main.name == "read_config"
    # The comment is an addressed comment at the exact address given, not the
    # function-level comment snapped to the start.
    assert main.get_comment_at(0x1150) == "parses rc file"
    assert main.get_comment_at(0x1100) == ""
    assert main.comment == ""
    assert main.user_type is None
    assert helper.name == "helper"
    assert helper.get_comment_at(0x2000) == ""
    assert helper.user_type == "int helper(int fd)"
    # One transaction for the whole batch: a single undo step, committed not reverted.
    assert view.transactions == ["open", "commit"]


def test_annotate_many_reports_a_missing_function_per_item() -> None:
    view = _annotate_view()
    main, _helper = view.functions
    _, annotate = get_tool("rex_annotate_many")
    result = annotate(
        FakeParsingToolCall(view),
        [{"addr": "0x1800", "name": "ghost"}, {"addr": "0x1100", "name": "renamed"}],
    )
    assert result == {
        "applied": 1,
        "failed": 1,
        "failed_count": 1,
        "total": 2,
        "results": [
            {
                "addr": "0x1800",
                "ok": False,
                "error": plain_gap_message("analyzed function", 0x1800),
            },
            {
                "addr": "0x1100",
                "ok": True,
                "function": {"start": "0x1100", "name": "renamed", **NO_ALTERNATIVES},
            },
        ],
    }
    # The batch still applies and commits; only the dead item failed.
    assert main.name == "renamed"
    assert view.transactions == ["open", "commit"]


def test_annotate_many_skips_the_transaction_when_every_item_fails() -> None:
    view = _annotate_view()
    _, annotate = get_tool("rex_annotate_many")
    result = annotate(
        FakeParsingToolCall(view),
        [{"addr": "0x9999", "name": "ghost"}, "not an object"],
    )
    assert result == {
        "applied": 0,
        "failed": 2,
        "failed_count": 2,
        "total": 2,
        "results": [
            {
                "addr": "0x9999",
                "ok": False,
                "error": plain_gap_message("analyzed function", 0x9999),
            },
            {
                "addr": "'not an object'",
                "ok": False,
                "error": "each item must be a JSON object",
            },
        ],
    }
    # Nothing to apply, so no undo step is created at all.
    assert view.transactions == []


def test_annotate_many_reports_item_content_errors_per_item() -> None:
    view = _annotate_view()
    _, annotate = get_tool("rex_annotate_many")
    result = annotate(
        FakeParsingToolCall(view),
        [
            {"comment": "no addr here"},
            {"addr": 1.5, "name": "x"},
            {"addr": True, "name": "x"},
            {"addr": "garbage"},
            {"addr": "0x1100", "name": "ok", "hue": "blue"},
        ],
    )
    (missing, mistyped, boolean, unparsable, unknown) = result["results"]
    assert missing == {
        "addr": "{'comment': 'no addr here'}",
        "ok": False,
        "error": "addr is required",
    }
    assert mistyped == {
        "addr": "1.5",
        "ok": False,
        "error": "addr must be an integer or a string address expression",
    }
    # bool is an int subclass: a JSON true/false address is a caller bug, not an address.
    assert boolean == {
        "addr": "True",
        "ok": False,
        "error": "addr must be an integer or a string address expression",
    }
    assert unparsable == {
        "addr": "garbage",
        "ok": False,
        "error": "bad address expression: unparsable address expression 'garbage'",
    }
    assert unknown == {"addr": "0x1100", "ok": False, "error": "unknown field(s): hue"}
    assert result["applied"] == 0
    assert result["failed"] == 5


def test_annotate_many_rejects_bad_batch_shape_and_size() -> None:
    view = _annotate_view()
    _, annotate = get_tool("rex_annotate_many")
    with pytest.raises(FakeToolError) as exc:
        annotate(FakeParsingToolCall(view), "0x1100")
    assert exc.value.code == "invalid_params"
    assert exc.value.message == "items must be a list of annotation objects"
    for batch in ([], [{"addr": "0x1100"}] * (annotations_tools._MAX_ANNOTATE_ITEMS + 1)):
        with pytest.raises(FakeToolError) as exc:
            annotate(FakeParsingToolCall(view), batch)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == (
            f"items must contain between 1 and {annotations_tools._MAX_ANNOTATE_ITEMS} entries"
        )
    # Exactly the batch cap is accepted.
    at_cap = annotate(
        FakeParsingToolCall(view),
        [{"addr": "0x1100", "name": "same"}] * annotations_tools._MAX_ANNOTATE_ITEMS,
    )
    assert at_cap["applied"] == annotations_tools._MAX_ANNOTATE_ITEMS


def test_annotate_many_rejects_the_removed_type_alias_as_an_unknown_field() -> None:
    view = _annotate_view()
    main, _helper = view.functions
    _, annotate = get_tool("rex_annotate_many")
    # "prototype" is the one user-type path: "type" was its alias before the collapse and
    # is now rejected like any unknown field, so a caller cannot silently half-set a type.
    result = annotate(
        FakeParsingToolCall(view),
        [{"addr": "0x1100", "prototype": "int main(void)", "type": "int main(void)"}],
    )
    assert result == {
        "applied": 0,
        "failed": 1,
        "failed_count": 1,
        "total": 1,
        "results": [{"addr": "0x1100", "ok": False, "error": "unknown field(s): type"}],
    }
    # The rejected item staged nothing: no type applied, no undo step created.
    assert main.user_type is None
    assert view.transactions == []


def test_annotate_many_rejects_an_unparsable_prototype_before_applying_anything() -> None:
    view = _annotate_view()
    main, _helper = view.functions
    view.parse_type_error = SyntaxError("expected ';'")
    _, annotate = get_tool("rex_annotate_many")
    result = annotate(
        FakeParsingToolCall(view),
        [{"addr": "0x1100", "name": "renamed", "prototype": "int main(void)"}],
    )
    assert result == {
        "applied": 0,
        "failed": 1,
        "failed_count": 1,
        "total": 1,
        "results": [{"addr": "0x1100", "ok": False, "error": "bad type: expected ';'"}],
    }
    # An item is atomic: a failing type must not leave the rename half-applied.
    assert main.name == "main"
    assert main.comment == ""
    assert view.transactions == []


def test_annotate_many_rolls_back_when_the_core_fails_mid_apply() -> None:
    view = _annotate_view()
    _main, helper = view.functions
    helper.user_type_error = RuntimeError("core exploded")
    _, annotate = get_tool("rex_annotate_many")
    with pytest.raises(FakeToolError) as exc:
        annotate(
            FakeParsingToolCall(view),
            [
                {"addr": "0x1100", "name": "renamed"},
                {"addr": "0x2000", "prototype": "int helper(int)"},
            ],
        )
    assert exc.value.code == "annotate_failed"
    assert "core exploded" in exc.value.message
    # The fake records the revert marker; the real core reverts the whole batch inside
    # undoable_transaction, which is what the response's "rolled back" wording relies on.
    assert view.transactions == ["open", "revert"]


def test_annotate_many_rejects_oversized_or_mistyped_strings_per_item() -> None:
    view = _annotate_view()
    _, annotate = get_tool("rex_annotate_many")
    result = annotate(
        FakeParsingToolCall(view),
        [
            {"addr": "0x1100", "name": ""},
            {"addr": "0x1100", "name": 7},
            {"addr": "0x1100", "name": "x" * (annotations_tools._MAX_ANNOTATE_NAME_CHARS + 1)},
            {"addr": "0x1100", "comment": 5},
            {
                "addr": "0x1100",
                "comment": "c" * (annotations_tools._MAX_ANNOTATE_COMMENT_CHARS + 1),
            },
            {"addr": "0x1100", "prototype": ""},
            {
                "addr": "0x1100",
                "prototype": "t" * (annotations_tools._MAX_ANNOTATE_PROTOTYPE_CHARS + 1),
            },
        ],
    )
    rows = result["results"]
    assert rows[0]["error"] == "name must be a non-empty string"
    assert rows[1]["error"] == "name must be a non-empty string"
    assert (
        rows[2]["error"] == f"name exceeds {annotations_tools._MAX_ANNOTATE_NAME_CHARS} characters"
    )
    assert rows[3]["error"] == "comment must be a string"
    assert (
        rows[4]["error"]
        == f"comment exceeds {annotations_tools._MAX_ANNOTATE_COMMENT_CHARS} characters"
    )
    assert rows[5]["error"] == "prototype must be a non-empty string"
    assert (
        rows[6]["error"]
        == f"prototype exceeds {annotations_tools._MAX_ANNOTATE_PROTOTYPE_CHARS} characters"
    )
    assert result["applied"] == 0
    assert result["failed"] == 7
    assert view.transactions == []


def test_annotate_many_reports_the_first_bad_field_in_name_comment_prototype_order() -> None:
    view = _annotate_view()
    _, annotate = get_tool("rex_annotate_many")
    result = annotate(
        FakeParsingToolCall(view),
        [
            {"addr": "0x1100", "name": "", "comment": 5, "prototype": ""},
            {"addr": "0x1100", "comment": 5, "prototype": ""},
            {"addr": "0x1100", "prototype": ""},
        ],
    )
    errors = [row["error"] for row in result["results"]]
    assert errors == [
        "name must be a non-empty string",
        "comment must be a string",
        "prototype must be a non-empty string",
    ]


def test_annotate_many_accepts_strings_exactly_at_the_caps() -> None:
    view = _annotate_view()
    main, _helper = view.functions
    _, annotate = get_tool("rex_annotate_many")
    result = annotate(
        FakeParsingToolCall(view),
        [
            {
                "addr": "0x1100",
                "name": "n" * annotations_tools._MAX_ANNOTATE_NAME_CHARS,
                "comment": "c" * annotations_tools._MAX_ANNOTATE_COMMENT_CHARS,
                "prototype": "t" * annotations_tools._MAX_ANNOTATE_PROTOTYPE_CHARS,
            }
        ],
    )
    assert result["applied"] == 1
    assert result["failed"] == 0
    assert main.name == "n" * annotations_tools._MAX_ANNOTATE_NAME_CHARS
    assert main.get_comment_at(0x1100) == "c" * annotations_tools._MAX_ANNOTATE_COMMENT_CHARS
    assert main.comment == ""
    assert main.user_type == "t" * annotations_tools._MAX_ANNOTATE_PROTOTYPE_CHARS


def test_annotate_many_lands_a_comment_at_the_exact_address_given() -> None:
    view = _annotate_view()
    main, _helper = view.functions
    _, annotate = get_tool("rex_annotate_many")
    result = annotate(
        FakeParsingToolCall(view),
        [{"addr": "0x1150", "comment": "mid-function"}],
    )
    assert result["results"] == [
        {
            "addr": "0x1150",
            "ok": True,
            "function": {"start": "0x1100", "name": "main", **NO_ALTERNATIVES},
        }
    ]
    assert main.get_comment_at(0x1150) == "mid-function"
    assert main.get_comment_at(0x1100) == ""
    # The addressed comment never doubles as the function-level comment.
    assert main.comment == ""
    assert view.transactions == ["open", "commit"]


def test_annotate_many_echoes_the_function_start_for_function_level_fields() -> None:
    # name and prototype are function-level properties: annotating an interior address
    # renames or retypes the whole function, so the row echoes the start they landed on.
    view = _annotate_view()
    main, _helper = view.functions
    _, annotate = get_tool("rex_annotate_many")
    result = annotate(
        FakeParsingToolCall(view),
        [{"addr": "0x1150", "name": "renamed"}, {"addr": "0x1150", "prototype": "int main(void)"}],
    )
    assert result["results"] == [
        {
            "addr": "0x1100",
            "ok": True,
            "function": {"start": "0x1100", "name": "renamed", **NO_ALTERNATIVES},
        },
        {
            "addr": "0x1100",
            "ok": True,
            "function": {"start": "0x1100", "name": "renamed", **NO_ALTERNATIVES},
        },
    ]
    assert main.name == "renamed"
    assert main.user_type == "int main(void)"


def test_annotate_many_collapses_repeated_items_onto_one_function_last_write_wins() -> None:
    view = _annotate_view()
    main, _helper = view.functions
    _, annotate = get_tool("rex_annotate_many")
    # Both items resolve to main (0x1150 is mid-function). Comments are per-address, so
    # each address keeps its own; the function-level name collapses last-write-wins.
    result = annotate(
        FakeParsingToolCall(view),
        [
            {"addr": "0x1150", "comment": "first"},
            {"addr": "0x1100", "comment": "second", "name": "final_name"},
        ],
    )
    assert result["applied"] == 2
    assert result["failed_count"] == 0
    assert result["total"] == 2
    assert main.get_comment_at(0x1150) == "first"
    assert main.get_comment_at(0x1100) == "second"
    assert main.name == "final_name"
    # One transaction: the collapsed items are still a single undo step.
    assert view.transactions == ["open", "commit"]


def test_annotate_many_comments_at_the_same_address_last_write_wins() -> None:
    view = _annotate_view()
    main, _helper = view.functions
    _, annotate = get_tool("rex_annotate_many")
    annotate(
        FakeParsingToolCall(view),
        [{"addr": "0x1150", "comment": "first"}, {"addr": "0x1150", "comment": "second"}],
    )
    assert main.get_comment_at(0x1150) == "second"


def test_annotate_batch_leaves_one_undo_entry_that_rex_undo_reverses() -> None:
    view = _annotate_view()
    _, annotate = get_tool("rex_annotate_many")
    _, undo = get_tool("rex_undo")
    # The API documents undoable_transaction as creating an Undo state containing the
    # batch's actions, so the fake models the committed entry (helpers.py). This pins the
    # undo tools' one settled composition claim (see the undo note in
    # binja_plugin/tools/state.py): one batch is one undo step and rex_undo reverses it
    # whole. The tag/metadata/type-library writes the API leaves undocumented push
    # nothing here, so the fake cannot pin those either way.
    annotate(FakeParsingToolCall(view), [{"addr": "0x1100", "name": "renamed"}])
    assert view.file.undo_entries == [undo_entry("rex_annotate_many batch")]
    assert undo(_call(view)) == {
        "undone": True,
        "actions": ["rex_annotate_many batch"],
        "actions_truncated": False,
        "undo_left": 0,
        "redo_left": 1,
    }
    assert view.file.undo_entries == []
    assert view.file.redo_entries == [undo_entry("rex_annotate_many batch")]
    # A batch the core rolls back mid-apply commits nothing, so there is no entry to undo.
    rollback_view = _annotate_view()
    rollback_view.functions[1].user_type_error = RuntimeError("core exploded")
    with pytest.raises(FakeToolError):
        annotate(
            FakeParsingToolCall(rollback_view),
            [
                {"addr": "0x1100", "name": "renamed"},
                {"addr": "0x2000", "prototype": "int helper(int)"},
            ],
        )
    assert rollback_view.file.undo_entries == []


def test_annotate_many_lists_all_unknown_fields() -> None:
    view = _annotate_view()
    _, annotate = get_tool("rex_annotate_many")
    result = annotate(
        FakeParsingToolCall(view),
        [{"addr": "0x1100", "hue": "blue", "tint": "warm"}],
    )
    assert result["results"] == [
        {"addr": "0x1100", "ok": False, "error": "unknown field(s): hue, tint"}
    ]


def test_optional_text_passes_through_strings_and_maps_everything_else_to_none() -> None:
    assert annotations_tools._optional_text("note") == "note"
    # An empty comment is a real value: it must survive, not collapse into None.
    assert annotations_tools._optional_text("") == ""
    assert annotations_tools._optional_text(None) is None
    assert annotations_tools._optional_text(123) is None
    assert annotations_tools._optional_text(["note"]) is None


def test_annotate_many_reports_each_function_as_it_is_after_the_batch() -> None:
    main = FakeFunction("main", 0x1100, 0x1200)
    helper = FakeFunction("helper", 0x2000, 0x2100)
    view = FakeBinaryView(functions=[main, helper])
    _, annotate = get_tool("rex_annotate_many")
    result = annotate(
        FakeParsingToolCall(view),
        [{"addr": 0x1100, "name": "parse_config"}, {"addr": 0x2000, "name": "parse_config"}],
    )
    assert [row["function"] for row in result["results"]] == [
        {
            "start": "0x1100",
            "name": "parse_config",
            "also_containing": [],
            "same_name": [{"start": "0x2000", "name": "parse_config"}],
        },
        {
            "start": "0x2000",
            "name": "parse_config",
            "also_containing": [],
            "same_name": [{"start": "0x1100", "name": "parse_config"}],
        },
    ]
