from __future__ import annotations

import pytest
from helpers import (
    FakeBinaryView,
    FakeFunction,
    FakeToolError,
    _call,
    _view_with_functions,
    get_tool,
)

from binja_plugin import tools
from binja_plugin.tools import functions


def test_function_define_and_undefine() -> None:
    view = FakeBinaryView()
    _, define = get_tool("rex_function_define")
    assert define(_call(view), 0x4000) == {"start": "0x4000", "name": "sub_4000"}
    assert len(view.created_functions) == 1

    _, undefine = get_tool("rex_function_undefine")
    assert undefine(_call(view), 0x4000) == {"start": "0x4000", "name": "sub_4000"}
    assert len(view.removed_functions) == 1

    with pytest.raises(FakeToolError) as exc:
        undefine(_call(view), 0x9999)
    assert exc.value.code == "no_function"


def test_function_define_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    view = FakeBinaryView()
    monkeypatch.setattr(view, "create_user_function", lambda address: None)
    _, define = get_tool("rex_function_define")
    with pytest.raises(FakeToolError) as exc:
        define(_call(view), 0x4000)
    assert exc.value.code == "define_failed"


def test_function_containing_caps_entries_and_truncates_names() -> None:
    inner = FakeFunction("inner", 0x1150, 0x1160)
    outer = FakeFunction("outer", 0x1100, 0x1200)
    layers = [
        FakeFunction("layer" + "x" * 600 if index == 0 else f"layer{index}", 0x1000, 0x2000)
        for index in range(functions._MAX_FUNCTION_ENTRIES + 10)
    ]
    view = FakeBinaryView(functions=[inner, outer, *layers])
    _, containing = get_tool("rex_function_containing")
    result = containing(_call(view), 0x1155)
    assert len(result["functions"]) == functions._MAX_FUNCTION_ENTRIES
    assert result["truncated"] is True
    assert result["functions"][2]["name"].endswith("chars truncated]")
    small = FakeBinaryView(functions=[inner, outer])
    assert containing(_call(small), 0x1155)["truncated"] is False
    with pytest.raises(FakeToolError) as exc:
        containing(_call(small), 0x2000)
    assert exc.value.code == "no_function"


def test_call_paths_finds_caller_and_callee_paths() -> None:
    view = _view_with_functions()
    _, paths = get_tool("rex_call_paths")
    result = paths(_call(view), 0x1100, 0x3000)
    assert result["reachable"] is True
    assert result["truncated"] is False
    assert result["paths"] == [
        [
            {"start": "0x1100", "name": "main"},
            {"start": "0x2000", "name": "handler"},
            {"start": "0x3000", "name": "sink"},
        ]
    ]
    result = paths(_call(view), 0x3000, 0x1100, direction="callees")
    assert [step["name"] for step in result["paths"][0]] == ["sink", "handler", "main"]


def test_call_paths_depth_shortcut_and_errors() -> None:
    view = _view_with_functions()
    _, paths = get_tool("rex_call_paths")
    assert paths(_call(view), 0x1100, 0x3000, max_depth=1)["reachable"] is False
    assert paths(_call(view), 0x1100, 0x1100) == {
        "reachable": True,
        "paths": [[{"start": "0x1100", "name": "main"}]],
        "truncated": False,
        "explored": 1,
    }
    with pytest.raises(FakeToolError) as exc:
        paths(_call(view), 0x7777, 0x3000)
    assert exc.value.code == "no_function"


def test_call_paths_reports_truncation_and_caps_depth() -> None:
    view = _view_with_functions()
    extra = FakeFunction("extra", 0x5000, 0x5100)
    view.functions[0].callers.append(extra)
    _, paths = get_tool("rex_call_paths")
    # The search stops with one path in hand and "extra" still queued.
    result = paths(_call(view), 0x1100, 0x3000, max_paths=1)
    assert result["reachable"] is True
    assert result["truncated"] is True
    assert len(result["paths"]) == 1

    chain = [
        FakeFunction(f"f{index}", 0x1000 + index * 0x10, 0x1010 + index * 0x10)
        for index in range(20)
    ]
    for index in range(19):
        chain[index].callers = [chain[index + 1]]
    chain_view = FakeBinaryView(functions=chain)
    chain_start, chain_end = 0x1000, 0x1000 + 19 * 0x10
    # max_depth exactly at the cap is accepted, and the cap keeps the 20-deep target
    # unreachable; one past the cap is rejected instead of clamped down.
    deep = paths(_call(chain_view), chain_start, chain_end, max_depth=tools._MAX_CALL_PATH_DEPTH)
    assert deep["reachable"] is False
    with pytest.raises(FakeToolError) as exc:
        paths(_call(chain_view), chain_start, chain_end, max_depth=tools._MAX_CALL_PATH_DEPTH + 1)
    assert exc.value.code == "invalid_params"
    assert exc.value.message == (
        f"Invalid integer parameter 'max_depth': Must be at most {tools._MAX_CALL_PATH_DEPTH}"
    )


def test_call_paths_reports_one_path_per_intermediate_and_sorts_neighbors() -> None:
    main = FakeFunction("main", 0x1100, 0x1200)
    x1 = FakeFunction("x1", 0x2000, 0x2010)
    x2 = FakeFunction("x2", 0x2100, 0x2110)
    middle = FakeFunction("middle", 0x3000, 0x3010)
    sink = FakeFunction("sink", 0x4000, 0x4010)
    # "middle" is reachable through two parents; enqueueing it once (the visited set) must
    # keep it to one expansion, so exactly one path exists despite the diamond.
    main.callers = [x1, x2]
    x1.callers = [middle]
    x2.callers = [middle]
    middle.callers = [sink]
    view = FakeBinaryView(functions=[main, x1, x2, middle, sink])
    _, paths = get_tool("rex_call_paths")
    result = paths(_call(view), 0x1100, 0x4000)
    assert result == {
        "reachable": True,
        "paths": [
            [
                {"start": "0x1100", "name": "main"},
                {"start": "0x2000", "name": "x1"},
                {"start": "0x3000", "name": "middle"},
                {"start": "0x4000", "name": "sink"},
            ]
        ],
        "truncated": False,
        "explored": 4,
    }
    # Neighbors are ordered by start address, not insertion order, in both directions.
    late = FakeFunction("late", 0x9000, 0x9010)
    early = FakeFunction("early", 0x5000, 0x5010)
    target = FakeFunction("target", 0x7000, 0x7010)
    root = FakeFunction("root", 0x1100, 0x1200)
    root.callers = [late, early]
    late.callers = [target]
    early.callers = [target]
    caller_view = FakeBinaryView(functions=[root, late, early, target])
    caller_result = paths(_call(caller_view), 0x1100, 0x7000, max_paths=5)
    assert [[step["name"] for step in path] for path in caller_result["paths"]] == [
        ["root", "early", "target"],
        ["root", "late", "target"],
    ]
    root.callees = [late, early]
    late.callees = [target]
    early.callees = [target]
    callee_result = paths(_call(caller_view), 0x1100, 0x7000, direction="callees", max_paths=5)
    assert [[step["name"] for step in path] for path in callee_result["paths"]] == [
        ["root", "early", "target"],
        ["root", "late", "target"],
    ]


def test_call_paths_caps_paths_per_node() -> None:
    main = FakeFunction("main", 0x1100, 0x1200)
    handler = FakeFunction("handler", 0x2000, 0x2100)
    sink = FakeFunction("sink", 0x3000, 0x3100)
    main.callers = [handler]
    # Real BinaryView call-graph properties list one entry per call site, so the target can
    # appear several times in one neighbors list.
    handler.callers = [sink, sink, sink]
    view = FakeBinaryView(functions=[main, handler, sink])
    _, paths = get_tool("rex_call_paths")
    result = paths(_call(view), 0x1100, 0x3000, max_paths=2)
    assert len(result["paths"]) == 2
    assert result["truncated"] is True


def test_call_paths_rejects_out_of_range_bounds() -> None:
    # max_paths/max_depth below 1 or above their caps are rejected, not normalized:
    # each bound is invalid on its face and both bounds are inclusive.
    view = _view_with_functions()
    _, paths = get_tool("rex_call_paths")
    for kwargs, message in (
        ({"max_paths": 0}, "Invalid integer parameter 'max_paths': Must be at least 1"),
        ({"max_paths": -1}, "Invalid integer parameter 'max_paths': Must be at least 1"),
        (
            {"max_paths": tools._MAX_CALL_PATHS + 1},
            f"Invalid integer parameter 'max_paths': Must be at most {tools._MAX_CALL_PATHS}",
        ),
        ({"max_depth": 0}, "Invalid integer parameter 'max_depth': Must be at least 1"),
        (
            {"max_depth": tools._MAX_CALL_PATH_DEPTH + 1},
            f"Invalid integer parameter 'max_depth': Must be at most {tools._MAX_CALL_PATH_DEPTH}",
        ),
    ):
        with pytest.raises(FakeToolError) as exc:
            paths(_call(view), 0x1100, 0x1100, **kwargs)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == message
    # Exactly at both caps (and at the minimum of 1) the search still runs.
    at_cap_paths = paths(_call(view), 0x1100, 0x1100, max_paths=tools._MAX_CALL_PATHS)
    assert at_cap_paths["reachable"] is True
    at_cap_depth = paths(_call(view), 0x1100, 0x1100, max_depth=tools._MAX_CALL_PATH_DEPTH)
    assert at_cap_depth["reachable"] is True
