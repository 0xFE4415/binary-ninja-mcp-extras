from __future__ import annotations

import pytest
from helpers import (
    NO_ALTERNATIVES,
    FakeBasicBlock,
    FakeParsingToolCall,
    FakeToolError,
    _call,
    _view_with_functions,
    get_tool,
    plain_gap_message,
)
from helpers_view import (
    FakeBinaryView,
    FakeFunction,
    undo_entry,
)

from binja_plugin import tools
from binja_plugin.tools import functions


def test_function_define_and_undefine(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("time.sleep", _DefineWaitClock().sleep)
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
    assert undefine(_call(view), 0x4000) == {
        "start": "0x4000",
        "name": "sub_4000",
        **NO_ALTERNATIVES,
    }
    assert len(view.removed_functions) == 1

    with pytest.raises(FakeToolError) as exc:
        undefine(_call(view), 0x9999)
    assert exc.value.code == "no_function"
    assert exc.value.message == (
        "no function contains 0x9999; the address is mapped but no function covers it"
    )


def test_function_define_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    view = FakeBinaryView()
    monkeypatch.setattr(view, "create_user_function", lambda address: None)
    _, define = get_tool("rex_function_define")
    with pytest.raises(FakeToolError) as exc:
        define(_call(view), 0x4000)
    assert exc.value.code == "define_failed"


def test_function_define_wait_reports_unanalyzed_functions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A view whose created functions never get blocks: the wait returns them as pending
    # instead of hanging, and wait=false skips the wait entirely.
    monkeypatch.setattr("time.sleep", _DefineWaitClock().sleep)
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
        assert len(self.sleeps) <= 8, "wait loop ignored the deadline"
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


def test_function_define_many_defines_and_waits(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("time.sleep", _DefineWaitClock().sleep)
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
    # One transaction, so one rex_undo reverts the whole batch.
    assert view.transactions == ["open", "commit"]
    assert view.file.undo_entries == [undo_entry("rex_annotate_many batch")]


def test_function_define_many_reverts_its_transaction_when_the_core_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    view = FakeBinaryView()

    def refuse(address: int) -> None:
        raise RuntimeError("core refused")

    monkeypatch.setattr(view, "create_user_function", refuse)
    _, define_many = get_tool("rex_function_define_many")
    with pytest.raises(RuntimeError, match="core refused"):
        define_many(FakeParsingToolCall(view), ["0x4000", "0x4100"], wait=False)
    assert view.transactions == ["open", "revert"]
    assert view.file.undo_entries == []


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
    assert exc.value.message == "addresses must contain between 1 and 128 address expressions"
    with pytest.raises(FakeToolError) as exc:
        define_many(FakeParsingToolCall(view), [f"0x{address:x}" for address in range(129)])
    assert exc.value.message == "addresses must contain between 1 and 128 address expressions"


def test_function_define_many_reports_pending_and_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("time.sleep", _DefineWaitClock().sleep)
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
    assert result["functions"][0]["name"].endswith("chars truncated]")
    small = FakeBinaryView(functions=[inner, outer])
    assert containing(_call(small), 0x1155)["truncated"] is False
    with pytest.raises(FakeToolError) as exc:
        containing(_call(small), 0x2000)
    assert exc.value.code == "no_function"


def test_function_containing_explains_a_containment_miss() -> None:
    view = FakeBinaryView(functions=[FakeFunction("main", 0x1100, 0x1200)])
    _, containing = get_tool("rex_function_containing")
    # The byte after a function's last instruction is outside every function: name the
    # predecessor so the caller can decide whether to define a function there.
    with pytest.raises(FakeToolError) as exc:
        containing(_call(view), 0x1200)
    assert exc.value.code == "no_function"
    assert exc.value.message == (
        "no function contains 0x1200; the address is immediately past the end of main at "
        "0x1100 (highest address 0x11ff); when the last instruction ends the block "
        "(for example int3, ret, or jmp) the next bytes belong to no function, so define "
        "one with rex_function_define(start=0x1200) if execution continues"
    )
    # An address outside the view's mapped range gets the unmapped diagnostic instead.
    with pytest.raises(FakeToolError) as exc:
        containing(_call(view), 0x20000)
    assert (
        exc.value.message
        == "no function contains 0x20000; the address is not mapped by any segment"
    )
    with pytest.raises(FakeToolError) as exc:
        containing(_call(view), 0x1800)
    assert exc.value.message == plain_gap_message("function", 0x1800)


def test_function_containing_names_a_one_byte_predecessor() -> None:
    # A one-byte function leaves no containing range for address - 2, so only the lookup
    # of the preceding byte itself can name it.
    view = FakeBinaryView(functions=[FakeFunction("tiny", 0x11FF, 0x1200)])
    _, containing = get_tool("rex_function_containing")
    with pytest.raises(FakeToolError) as exc:
        containing(_call(view), 0x1200)
    assert exc.value.message.startswith(
        "no function contains 0x1200; the address is immediately past the end of tiny at "
        "0x11ff (highest address 0x11ff)"
    )


def test_function_containing_explains_a_miss_after_a_function_at_zero() -> None:
    view = FakeBinaryView(functions=[FakeFunction("entry", 0, 0x10)])
    _, containing = get_tool("rex_function_containing")
    with pytest.raises(FakeToolError) as exc:
        containing(_call(view), 0x10)
    assert exc.value.message.startswith(
        "no function contains 0x10; the address is immediately past the end of entry at 0x0"
    )


def test_function_containing_names_the_function_that_ends_at_the_miss() -> None:
    # Overlapping ranges: a shorter function starts inside the one that ends at the miss,
    # so the previous-start lookup lands on it, and only a check of every function holding
    # the preceding byte finds the range that actually ends at the miss.
    view = FakeBinaryView(
        functions=[FakeFunction("tail", 0x1000, 0x1100), FakeFunction("inner", 0x1080, 0x10A0)]
    )
    _, containing = get_tool("rex_function_containing")
    with pytest.raises(FakeToolError) as exc:
        containing(_call(view), 0x1100)
    assert exc.value.code == "no_function"
    assert exc.value.message.startswith(
        "no function contains 0x1100; the address is immediately past the end of tail at 0x1000"
    )


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
        "from_function": {"start": "0x1100", "name": "main", **NO_ALTERNATIVES},
        "to_function": {"start": "0x1100", "name": "main", **NO_ALTERNATIVES},
        "reachable": True,
        "paths": [[{"start": "0x1100", "name": "main"}]],
        "truncated": False,
        "depth_limited": False,
        "explored": 1,
    }
    with pytest.raises(FakeToolError) as exc:
        paths(_call(view), 0x7777, 0x3000)
    assert exc.value.code == "no_function"
    assert exc.value.message == plain_gap_message("function", 0x7777)
    with pytest.raises(FakeToolError) as exc:
        paths(_call(view), 0x1100, 0x7777)
    assert exc.value.message == plain_gap_message("function", 0x7777)


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
        "from_function": {"start": "0x1100", "name": "main", **NO_ALTERNATIVES},
        "to_function": {"start": "0x4000", "name": "sink", **NO_ALTERNATIVES},
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
        "depth_limited": False,
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


@pytest.mark.parametrize("direction", ["callers", "callees"])
def test_call_paths_lists_a_path_once_when_call_sites_repeat_the_target(direction: str) -> None:
    main = FakeFunction("main", 0x1100, 0x1200)
    handler = FakeFunction("handler", 0x2000, 0x2100)
    sink = FakeFunction("sink", 0x3000, 0x3100)
    # The core lists one entry per call site, so a repeated callee is a repeated edge.
    setattr(main, direction, [handler, handler])
    setattr(handler, direction, [sink, sink, sink])
    view = FakeBinaryView(functions=[main, handler, sink])
    _, paths = get_tool("rex_call_paths")
    result = paths(_call(view), 0x1100, 0x3000, direction=direction, max_paths=5)
    assert [[step["name"] for step in path] for path in result["paths"]] == [
        ["main", "handler", "sink"]
    ]
    assert result["truncated"] is False
    assert result["explored"] == 2


@pytest.mark.parametrize("direction", ["callers", "callees"])
def test_call_paths_repeated_edges_do_not_use_up_the_path_cap(direction: str) -> None:
    main = FakeFunction("main", 0x1100, 0x1200)
    first = FakeFunction("first", 0x2000, 0x2100)
    second = FakeFunction("second", 0x2200, 0x2300)
    sink = FakeFunction("sink", 0x3000, 0x3100)
    setattr(main, direction, [first, second])
    setattr(first, direction, [sink, sink, sink])
    setattr(second, direction, [sink])
    view = FakeBinaryView(functions=[main, first, second, sink])
    _, paths = get_tool("rex_call_paths")
    result = paths(_call(view), 0x1100, 0x3000, direction=direction, max_paths=3)
    assert [[step["name"] for step in path] for path in result["paths"]] == [
        ["main", "first", "sink"],
        ["main", "second", "sink"],
    ]
    assert result["truncated"] is False


def test_call_paths_stops_at_the_path_cap_and_reports_it() -> None:
    main = FakeFunction("main", 0x1100, 0x1200)
    first = FakeFunction("first", 0x2000, 0x2100)
    second = FakeFunction("second", 0x2200, 0x2300)
    sink = FakeFunction("sink", 0x3000, 0x3100)
    main.callers = [first, second]
    first.callers = [sink]
    second.callers = [sink]
    view = FakeBinaryView(functions=[main, first, second, sink])
    _, paths = get_tool("rex_call_paths")
    result = paths(_call(view), 0x1100, 0x3000, max_paths=1)
    assert [[step["name"] for step in path] for path in result["paths"]] == [
        ["main", "first", "sink"]
    ]
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


def test_function_undefine_misses_keep_the_diagnosis_without_define_advice() -> None:
    view = FakeBinaryView(
        functions=[FakeFunction("main", 0x1000, 0x1100)],
        pending_functions=[FakeFunction("sub_4000", 0x4000, 0x4010)],
    )
    _, undefine = get_tool("rex_function_undefine")
    expected = {
        0x1100: (
            "no function contains 0x1100; the address is immediately past the end of main at "
            "0x1000 (highest address 0x10ff); when the last instruction ends the block "
            "(for example int3, ret, or jmp) the next bytes belong to no function"
        ),
        0x1800: "no function contains 0x1800; the address is mapped but no function covers it",
        0x20000: "no function contains 0x20000; the address is not mapped by any segment",
    }
    for address, message in expected.items():
        with pytest.raises(FakeToolError) as exc:
            undefine(_call(view), address)
        assert exc.value.code == "no_function"
        assert exc.value.message == message
    with pytest.raises(FakeToolError) as exc:
        undefine(_call(view), 0x4000)
    assert exc.value.code == "analysis_pending"
    assert exc.value.message == (
        "function at 0x4000 exists but has not been analyzed yet; wait for analysis "
        "(rex_analysis_wait) or run bn_analysis_update"
    )


def _callee_chain() -> FakeBinaryView:
    root = FakeFunction("root", 0x1000, 0x1010)
    mid = FakeFunction("mid", 0x2000, 0x2010)
    leaf = FakeFunction("leaf", 0x3000, 0x3010)
    far = FakeFunction("far", 0x4000, 0x4010)
    root.callees = [mid]
    mid.callees = [leaf]
    leaf.callees = [far]
    return FakeBinaryView(functions=[root, mid, leaf, far])


def test_call_paths_flags_a_miss_caused_by_max_depth() -> None:
    _, paths = get_tool("rex_call_paths")
    limited = paths(_call(_callee_chain()), 0x1000, 0x4000, direction="callees", max_depth=2)
    assert limited["reachable"] is False
    assert limited["paths"] == []
    assert limited["truncated"] is False
    assert limited["depth_limited"] is True
    deep_enough = paths(_call(_callee_chain()), 0x1000, 0x4000, direction="callees", max_depth=3)
    assert deep_enough["reachable"] is True
    assert deep_enough["depth_limited"] is False


def test_call_paths_clean_miss_is_not_depth_limited() -> None:
    root = FakeFunction("root", 0x1000, 0x1010)
    mid = FakeFunction("mid", 0x2000, 0x2010)
    island = FakeFunction("island", 0x5000, 0x5010)
    root.callees = [mid]
    view = FakeBinaryView(functions=[root, mid, island])
    _, paths = get_tool("rex_call_paths")
    result = paths(_call(view), 0x1000, 0x5000, direction="callees", max_depth=2)
    assert result["reachable"] is False
    assert result["depth_limited"] is False
    shallow = paths(_call(view), 0x1000, 0x5000, direction="callees", max_depth=1)
    assert shallow["reachable"] is False
    assert shallow["depth_limited"] is False


def test_call_paths_depth_limit_needs_an_unvisited_neighbor_or_the_target() -> None:
    root = FakeFunction("root", 0x1000, 0x1010)
    mid = FakeFunction("mid", 0x2000, 0x2010)
    deeper = FakeFunction("deeper", 0x3000, 0x3010)
    target = FakeFunction("target", 0x4000, 0x4010)
    view = FakeBinaryView(functions=[root, mid, deeper, target])
    _, paths = get_tool("rex_call_paths")

    root.callees = [mid]
    mid.callees = [deeper]
    unvisited = paths(_call(view), 0x1000, 0x4000, direction="callees", max_depth=1)
    assert unvisited["depth_limited"] is True

    mid.callees = [root, mid]
    visited_only = paths(_call(view), 0x1000, 0x4000, direction="callees", max_depth=1)
    assert visited_only["reachable"] is False
    assert visited_only["depth_limited"] is False

    mid.callees = [root, target]
    target_next = paths(_call(view), 0x1000, 0x4000, direction="callees", max_depth=1)
    assert target_next["reachable"] is False
    assert target_next["depth_limited"] is True

    mid.callees = []
    root.callees = [mid, deeper]
    deeper.callees = [mid]
    siblings = paths(_call(view), 0x1000, 0x4000, direction="callees", max_depth=1)
    assert siblings["depth_limited"] is False


def test_call_paths_flags_depth_limit_even_when_a_path_was_found() -> None:
    root = FakeFunction("root", 0x1000, 0x1010)
    mid = FakeFunction("mid", 0x2000, 0x2010)
    leaf = FakeFunction("leaf", 0x3000, 0x3010)
    root.callees = [leaf, mid]
    mid.callees = [leaf]
    view = FakeBinaryView(functions=[root, mid, leaf])
    _, paths = get_tool("rex_call_paths")
    shallow = paths(_call(view), 0x1000, 0x3000, direction="callees", max_depth=1, max_paths=5)
    assert [[step["name"] for step in path] for path in shallow["paths"]] == [["root", "leaf"]]
    assert shallow["depth_limited"] is True
    full = paths(_call(view), 0x1000, 0x3000, direction="callees", max_depth=2, max_paths=5)
    assert len(full["paths"]) == 2
    assert full["depth_limited"] is False


def test_call_paths_stops_checking_once_depth_limited() -> None:
    root = FakeFunction("root", 0x1000, 0x1010)
    first = FakeFunction("first", 0x2000, 0x2010)
    second = FakeFunction("second", 0x3000, 0x3010)
    beyond = FakeFunction("beyond", 0x4000, 0x4010)
    target = FakeFunction("target", 0x5000, 0x5010)
    root.callees = [first, second]
    first.callees = [beyond]
    second.callees = [beyond]
    view = FakeBinaryView(functions=[root, first, second, beyond, target])
    _, paths = get_tool("rex_call_paths")
    result = paths(_call(view), 0x1000, 0x5000, direction="callees", max_depth=1)
    assert result["reachable"] is False
    assert result["depth_limited"] is True
    assert result["explored"] == 1
