from __future__ import annotations

import pytest
from helpers import (
    FakeBasicBlock,
    FakeBinaryView,
    FakeFunction,
    FakeParsingToolCall,
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
    assert define(_call(view), 0x4000) == {
        "start": "0x4000",
        "name": "sub_4000",
        "analyzed": True,
        "waited_ms": 0,
    }
    assert len(view.created_functions) == 1

    _, undefine = get_tool("rex_function_undefine")
    assert undefine(_call(view), 0x4000) == {"start": "0x4000", "name": "sub_4000"}
    assert len(view.removed_functions) == 1

    with pytest.raises(FakeToolError) as exc:
        undefine(_call(view), 0x9999)
    assert exc.value.code == "no_function"
    assert exc.value.message == "no function contains 0x9999"


def test_function_define_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    view = FakeBinaryView()
    monkeypatch.setattr(view, "create_user_function", lambda address: None)
    _, define = get_tool("rex_function_define")
    with pytest.raises(FakeToolError) as exc:
        define(_call(view), 0x4000)
    assert exc.value.code == "define_failed"


def test_function_define_wait_reports_unanalyzed_functions() -> None:
    # A view whose created functions never get blocks: the wait returns them as pending
    # instead of hanging, and wait=false skips the wait entirely.
    stalled = FakeBinaryView(create_user_function_analyzes=False)
    _, define = get_tool("rex_function_define")
    result = define(_call(stalled), 0x4000, timeout_ms=0)
    assert result["analyzed"] is False
    assert result["start"] == "0x4000"
    result = define(_call(stalled), 0x4001, wait=False)
    assert result["analyzed"] is False
    assert result["waited_ms"] == 0

    analyzed = FakeBinaryView()
    assert define(_call(analyzed), 0x4000, timeout_ms=0)["analyzed"] is True
    # wait=false reports the function's actual state, not a blanket pending verdict.
    assert define(_call(analyzed), 0x4001, wait=False)["analyzed"] is True


class _DefineWaitClock:
    """Deterministic clock for the define-wait loop; sleep can land the first block."""

    def __init__(self) -> None:
        self.now_ms = 0
        self.sleeps: list[int] = []
        self.landing: FakeFunction | None = None

    def monotonic(self) -> float:
        return self.now_ms / 1000

    def sleep(self, seconds: float) -> None:
        slept_ms = round(seconds * 1000)
        self.sleeps.append(slept_ms)
        self.now_ms += slept_ms
        if self.landing is not None:
            self.landing.basic_blocks = [FakeBasicBlock([(self.landing.start, "push rbp")])]


class _ScriptedWaitClock:
    """Clock whose monotonic readings follow a script; sleep keeps the raw durations.

    The last reading repeats once the script runs out, so a mutant that takes one extra
    poll still terminates against a value past the deadline. More than ``max_sleeps``
    sleeps means the wait loop ignored the scripted deadline and the clock fails the
    test instead of spinning.
    """

    def __init__(self, readings: list[float], max_sleeps: int = 4) -> None:
        self.readings = list(readings)
        self.sleeps: list[float] = []
        self.max_sleeps = max_sleeps

    def monotonic(self) -> float:
        if len(self.readings) > 1:
            return self.readings.pop(0)
        return self.readings[0]

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        if len(self.sleeps) > self.max_sleeps:
            raise AssertionError("wait loop slept past the scripted deadline")


def test_function_define_wait_polls_until_the_first_block_lands(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The first block landing during a wait slice ends the wait one poll later, with the
    # real basic_blocks gate deciding analyzed.
    clock = _DefineWaitClock()
    monkeypatch.setattr("time.sleep", clock.sleep)
    monkeypatch.setattr("time.monotonic", clock.monotonic)
    stalled = FakeBinaryView(create_user_function_analyzes=False)

    def create_pending(address: int) -> FakeFunction | None:
        function = FakeFunction(f"sub_{address:x}", address, address + 1)
        clock.landing = function
        return function

    monkeypatch.setattr(stalled, "create_user_function", create_pending)
    _, define = get_tool("rex_function_define")
    assert define(_call(stalled), 0x4000, timeout_ms=60000) == {
        "start": "0x4000",
        "name": "sub_4000",
        "analyzed": True,
        "waited_ms": 100,
    }
    assert clock.sleeps == [100]


def test_function_define_wait_stops_at_the_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = _DefineWaitClock()
    monkeypatch.setattr("time.sleep", clock.sleep)
    monkeypatch.setattr("time.monotonic", clock.monotonic)
    stalled = FakeBinaryView(create_user_function_analyzes=False)
    _, define = get_tool("rex_function_define")
    result = define(_call(stalled), 0x4000, timeout_ms=350)
    # The hold is bounded by timeout_ms plus one slice: 350 ms of budget, four 100 ms
    # slices because the deadline check happens between slices.
    assert result == {
        "start": "0x4000",
        "name": "sub_4000",
        "analyzed": False,
        "waited_ms": 400,
    }
    assert clock.sleeps == [100, 100, 100, 100]


def test_function_define_wait_polls_just_under_the_full_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A poll taken just under the full timeout_ms budget still runs its slice: the
    # deadline is exactly timeout_ms milliseconds after the wait started, each slice
    # sleeps the full 100 ms, and waited_ms is the elapsed wall time in milliseconds.
    clock = _ScriptedWaitClock([0.0, 0.999999, 10.0])
    monkeypatch.setattr("time.monotonic", clock.monotonic)
    monkeypatch.setattr("time.sleep", clock.sleep)
    stalled = FakeBinaryView(create_user_function_analyzes=False)
    _, define = get_tool("rex_function_define")
    result = define(_call(stalled), 0x4000, timeout_ms=1000)
    assert clock.sleeps == [0.1]
    assert result == {
        "start": "0x4000",
        "name": "sub_4000",
        "analyzed": False,
        "waited_ms": 10000,
    }


def test_function_define_wait_takes_no_slice_at_the_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A poll taken exactly at the deadline stops without another 100 ms slice; the next
    # reading shows the clock running on while the loop decided to return.
    clock = _ScriptedWaitClock([0.0, 0.0, 1.0, 1.1])
    monkeypatch.setattr("time.monotonic", clock.monotonic)
    monkeypatch.setattr("time.sleep", clock.sleep)
    stalled = FakeBinaryView(create_user_function_analyzes=False)
    _, define = get_tool("rex_function_define")
    result = define(_call(stalled), 0x4000, timeout_ms=1000)
    assert clock.sleeps == [0.1]
    assert result == {
        "start": "0x4000",
        "name": "sub_4000",
        "analyzed": False,
        "waited_ms": 1100,
    }


def test_function_define_many_defines_and_waits() -> None:
    view = FakeBinaryView()
    _, define_many = get_tool("rex_function_define_many")
    result = define_many(FakeParsingToolCall(view), ["0x4000", "0x4100"])
    assert result["defined"] == [
        {"start": "0x4000", "name": "sub_4000", "analyzed": True},
        {"start": "0x4100", "name": "sub_4100", "analyzed": True},
    ]
    assert result["failed"] == []
    assert result["pending"] == []
    assert result["waited_ms"] == 0
    assert len(view.created_functions) == 2


def test_function_define_many_is_all_or_nothing_on_parse_errors() -> None:
    view = FakeBinaryView()
    _, define_many = get_tool("rex_function_define_many")
    for addresses, message in (
        (["0x4000", "zzz"], "bad address expression 'zzz': unparsable address expression 'zzz'"),
        (["0x4000", 7], "addresses[1] must be a string address expression"),
    ):
        with pytest.raises(FakeToolError) as exc:
            define_many(FakeParsingToolCall(view), addresses)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == message
        assert view.created_functions == []
    with pytest.raises(FakeToolError) as exc:
        define_many(FakeParsingToolCall(view), [])
    assert exc.value.message == "addresses must contain between 1 and 100 address expressions"
    with pytest.raises(FakeToolError) as exc:
        define_many(FakeParsingToolCall(view), [f"0x{address:x}" for address in range(101)])
    assert exc.value.message == "addresses must contain between 1 and 100 address expressions"


def test_function_define_many_reports_pending_and_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    stalled = FakeBinaryView(create_user_function_analyzes=False)
    _, define_many = get_tool("rex_function_define_many")
    result = define_many(FakeParsingToolCall(stalled), ["0x4000", "0x4100"], timeout_ms=0)
    assert [entry["start"] for entry in result["defined"]] == ["0x4000", "0x4100"]
    assert all(entry["analyzed"] is False for entry in result["defined"])
    assert result["pending"] == ["0x4000", "0x4100"]

    failing = FakeBinaryView()

    def refuse(address: int) -> FakeFunction | None:
        if address == 0x4100:
            return None
        function = FakeFunction(f"sub_{address:x}", address, address + 1)
        function.basic_blocks = [FakeBasicBlock([(address, "push rbp")])]
        return function

    monkeypatch.setattr(failing, "create_user_function", refuse)
    result = define_many(FakeParsingToolCall(failing), ["0x4000", "0x4100"], wait=False)
    assert [entry["start"] for entry in result["defined"]] == ["0x4000"]
    assert result["failed"] == ["0x4100"]
    assert result["pending"] == []


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
