from __future__ import annotations

import inspect

import pytest
from helpers import FakeBinaryView, FakeToolError, _call, _view_with_functions, get_tool

from binja_plugin.tools import escape


def test_memory_write_validates_and_writes() -> None:
    view = FakeBinaryView()
    _, write = get_tool("rex_memory_write")
    result = write(_call(view), 0x1000, "90 90")
    assert result == {"address": "0x1000", "bytes_written": 2}
    assert view.written == [(0x1000, b"\x90\x90")]
    # Whitespace of any kind separates bytes before validation; whitespace-only input
    # collapses to the empty pattern and is rejected as empty, not passed to fromhex.
    assert write(_call(view), 0x1000, "90\t90\n") == {"address": "0x1000", "bytes_written": 2}
    assert view.written[-1] == (0x1000, b"\x90\x90")
    for bad in ("", " ", "9", "zz", "9z"):
        with pytest.raises(FakeToolError) as exc:
            write(_call(view), 0x1000, bad)
        assert exc.value.code == "invalid_hex"


def test_eval_python_executes_code() -> None:
    view = _view_with_functions()
    _, evaluate = get_tool("rex_eval_python")
    result = evaluate(_call(view), "print('hi')\nresult = len(bv.functions)")
    assert result["stdout"] == "hi\n"
    assert result["stdout_truncated"] is False
    assert result["result"] == "3"
    assert result["result_truncated"] is False
    assert result["error"] is None
    assert result["error_truncated"] is False
    assert evaluate(_call(view), "1 + 1")["result"] is None
    # The exec namespace exposes the view as bv, the call itself, and the bn module alias.
    probe = evaluate(_call(view), "result = (bn is binaryninja) and (call.binary_view is bv)")
    assert probe["result"] == "True"
    assert probe["error"] is None


def test_eval_python_docstring_lists_the_exec_namespace() -> None:
    # The MCP layer serves only the first docstring line, so the bindings the exec
    # namespace provides must be named there or they are undiscoverable without probing.
    _, evaluate = get_tool("rex_eval_python")
    probe = evaluate(_call(_view_with_functions()), "result = sorted(globals())")
    assert probe["result"] == repr(["__builtins__", "binaryninja", "bn", "bv", "call"])
    first_line = inspect.cleandoc(escape.rex_eval_python.__doc__ or "").splitlines()[0]
    assert first_line == "Run Binary Ninja Python; globals: bv, bn, binaryninja, call."


def test_eval_python_truncates_stdout_and_result() -> None:
    view = _view_with_functions()
    _, evaluate = get_tool("rex_eval_python")
    result = evaluate(
        _call(view),
        f"print('x' * {escape._MAX_EVAL_STDOUT_CHARS + 10})\n"
        f"result = 'y' * {escape._MAX_EVAL_RESULT_CHARS + 10}",
    )
    assert result["stdout_truncated"] is True
    assert result["stdout"].startswith("x" * 10)
    assert len(result["stdout"]) == escape._MAX_EVAL_STDOUT_CHARS + len("... [11 chars truncated]")
    assert result["result_truncated"] is True
    # repr() wraps the string in quotes, so the truncated result starts with one.
    assert result["result"].startswith("'" + "y" * 10)
    assert len(result["result"]) == escape._MAX_EVAL_RESULT_CHARS + len("... [12 chars truncated]")
    assert result["error"] is None


def test_eval_python_survives_result_repr_raising() -> None:
    view = _view_with_functions()
    _, evaluate = get_tool("rex_eval_python")
    # An object whose repr() raises must land in the structured error path, not escape the
    # handler; the stdout captured before the failure is still returned.
    result = evaluate(
        _call(view),
        "print('before')\n"
        "class Exploding:\n"
        "    def __repr__(self):\n"
        "        raise RuntimeError('no repr')\n"
        "result = Exploding()",
    )
    assert result["stdout"] == "before\n"
    assert result["result"] is None
    assert result["result_truncated"] is False
    assert result["error"] is not None
    assert "no repr" in result["error"]
    assert result["error_truncated"] is False


def test_eval_python_returns_truncated_error_instead_of_raising() -> None:
    view = _view_with_functions()
    _, evaluate = get_tool("rex_eval_python")
    result = evaluate(_call(view), "print('before')\nraise ValueError('z' * 1000)")
    assert result["stdout"] == "before\n"
    assert result["result"] is None
    assert result["result_truncated"] is False
    assert result["error"] is not None
    assert result["error"].startswith("zzz")
    assert result["error_truncated"] is True
    assert len(result["error"]) == 512 + len("... [488 chars truncated]")


def test_eval_python_spills_oversized_result_for_paging() -> None:
    escape._EVAL_SPILLS.clear()
    view = _view_with_functions()
    _, evaluate = get_tool("rex_eval_python")
    result = evaluate(_call(view), f"result = 'y' * {escape._MAX_EVAL_RESULT_CHARS + 10}")
    assert result["result_truncated"] is True
    # repr() wraps the string in quotes, so the spilled text is two chars longer than the
    # expression produced.
    assert result["result_length"] == escape._MAX_EVAL_RESULT_CHARS + 12
    key = result["result_key"]
    assert key is not None

    _, page = get_tool("rex_eval_result")
    head = page(_call(view), key, offset=0, limit=100)
    assert head["key"] == key
    assert head["total"] == result["result_length"]
    assert head["truncated"] is True
    assert head["next_offset"] == 100
    tail = page(_call(view), key, offset=escape._MAX_EVAL_RESULT_CHARS)
    assert tail["truncated"] is False
    assert tail["next_offset"] is None
    # Paging the spill reassembles the full text exactly.
    assembled: list[str] = []
    offset = 0
    while True:
        chunk = page(_call(view), key, offset=offset, limit=4096)
        assembled.append(chunk["value"])
        if not chunk["truncated"]:
            break
        offset = chunk["next_offset"]  # type: ignore[assignment]
    raw = "".join(assembled)
    assert raw == repr("y" * (escape._MAX_EVAL_RESULT_CHARS + 10))
    # An offset at or past the end answers an empty page, not an error.
    assert page(_call(view), key, offset=result["result_length"])["value"] == ""
    with pytest.raises(FakeToolError) as exc:
        page(_call(view), "result-404")
    assert exc.value.code == "not_found"


def test_eval_python_spills_oversized_stdout() -> None:
    escape._EVAL_SPILLS.clear()
    view = _view_with_functions()
    _, evaluate = get_tool("rex_eval_python")
    result = evaluate(_call(view), f"print('x' * {escape._MAX_EVAL_STDOUT_CHARS + 10})")
    assert result["stdout_truncated"] is True
    assert result["stdout_key"] is not None
    assert result["stdout_length"] == escape._MAX_EVAL_STDOUT_CHARS + 11
    _, page = get_tool("rex_eval_result")
    spilled = page(_call(view), result["stdout_key"], offset=0, limit=10)
    assert spilled["value"] == "x" * 10
    assert spilled["total"] == escape._MAX_EVAL_STDOUT_CHARS + 11


def test_eval_spill_store_evicts_oldest_and_drops_oversized_spills(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    escape._EVAL_SPILLS.clear()
    monkeypatch.setattr(escape, "_MAX_EVAL_SPILLS", 1)
    view = _view_with_functions()
    _, evaluate = get_tool("rex_eval_python")
    first = evaluate(_call(view), f"result = 'a' * {escape._MAX_EVAL_RESULT_CHARS + 10}")
    second = evaluate(_call(view), f"result = 'b' * {escape._MAX_EVAL_RESULT_CHARS + 10}")
    _, page = get_tool("rex_eval_result")
    with pytest.raises(FakeToolError) as exc:
        page(_call(view), first["result_key"])
    assert exc.value.code == "not_found"
    assert page(_call(view), second["result_key"])["total"] > 0

    # A result larger than the per-spill cap is not kept: the clipped echo is the only
    # copy, and the key comes back None so no caller chases an unreadable spill. The
    # dropped spill must not occupy a store slot that could evict a readable spill.
    escape._EVAL_SPILLS.clear()
    monkeypatch.setattr(escape, "_MAX_EVAL_SPILL_CHARS", 8)
    dropped = evaluate(_call(view), f"result = 'c' * {escape._MAX_EVAL_RESULT_CHARS + 10}")
    assert dropped["result_truncated"] is True
    assert dropped["result_key"] is None
    assert dropped["result_length"] == escape._MAX_EVAL_RESULT_CHARS + 12
    assert escape._EVAL_SPILLS == {}


def test_eval_spill_keeps_a_spill_exactly_at_the_per_spill_cap() -> None:
    escape._EVAL_SPILLS.clear()
    view = _view_with_functions()
    _, evaluate = get_tool("rex_eval_python")
    # repr() adds the two quotes, so this result is exactly the per-spill cap long.
    result = evaluate(_call(view), f"result = 'a' * {escape._MAX_EVAL_SPILL_CHARS - 2}")
    assert result["result_key"] is not None
    _, page = get_tool("rex_eval_result")
    tail = page(_call(view), result["result_key"], offset=escape._MAX_EVAL_SPILL_CHARS - 1)
    assert tail["value"] == "'"
    assert tail["truncated"] is False
