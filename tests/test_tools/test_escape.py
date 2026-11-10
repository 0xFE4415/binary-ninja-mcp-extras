from __future__ import annotations

import inspect
from collections.abc import Iterator
from typing import Any

import pytest
from helpers import FakeToolError, _call, _view_with_functions, get_tool
from helpers_view import FakeBinaryView

from binja_plugin.tools import escape


@pytest.fixture(autouse=True)
def clear_eval_spills() -> Iterator[None]:
    escape._EVAL_SPILLS.clear()
    yield
    escape._EVAL_SPILLS.clear()


def test_eval_limits_match_contract() -> None:
    assert escape._MAX_EVAL_STDOUT_CHARS == 65_536
    assert escape._MAX_EVAL_RESULT_CHARS == 16_384
    assert escape._MAX_EVAL_SPILLS == 8
    assert escape._MAX_EVAL_SPILL_CHARS == 4 * 1024 * 1024
    assert escape._MAX_EVAL_RESULT_PAGE_CHARS == 65_536


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
    assert result["error"] == "RuntimeError: no repr"
    assert result["error_truncated"] is False
    assert result["error_location"] == {"line": 4, "text": "raise RuntimeError('no repr')"}


def _failing(code: str) -> dict[str, Any]:
    _, evaluate = get_tool("rex_eval_python")
    return evaluate(_call(_view_with_functions()), code)


@pytest.mark.parametrize(
    ("code", "error"),
    [
        ("d = {}\nd['x']", "KeyError: 'x'"),
        ("raise ValueError()", "ValueError"),
        ("raise ValueError('')", "ValueError"),
        ("raise ValueError('boom')", "ValueError: boom"),
        ("raise ValueError('a', 'b')", "ValueError: ('a', 'b')"),
        ("class Custom(Exception):\n    pass\nraise Custom('x')", "Custom: x"),
        ("import sys\nsys.exit()", "SystemExit: exit status None"),
        ("import sys\nsys.exit(3)", "SystemExit: exit status 3"),
        ("import sys\nsys.exit(0)", "SystemExit: exit status 0"),
        ("import sys\nsys.exit('bye')", "SystemExit: exit status 'bye'"),
        ("raise KeyboardInterrupt", "KeyboardInterrupt"),
        ("raise KeyboardInterrupt('stop')", "KeyboardInterrupt: stop"),
    ],
)
def test_eval_python_errors_lead_with_the_exception_type(code: str, error: str) -> None:
    result = _failing(code)
    assert result["error"] == error
    assert result["error_truncated"] is False
    assert result["result"] is None


@pytest.mark.parametrize(
    ("code", "error"),
    [
        (
            "import json\njson.loads('')",
            "json.decoder.JSONDecodeError: Expecting value: line 1 column 1 (char 0)",
        ),
        ("import zipfile\nraise zipfile.BadZipFile('torn')", "zipfile.BadZipFile: torn"),
        ("raise FileNotFoundError(2, 'No such file')", "FileNotFoundError: [Errno 2] No such file"),
        (
            "class Boom(Exception):\n    __module__ = 'binaryninja.binaryview'\nraise Boom('x')",
            "binaryninja.binaryview.Boom: x",
        ),
        (
            "class Boom(Exception):\n    __module__ = 'binaryninja.binaryview'\nraise Boom()",
            "binaryninja.binaryview.Boom",
        ),
        ("class Boom(Exception):\n    __module__ = '__main__'\nraise Boom('x')", "Boom: x"),
        ("class Boom(Exception):\n    __module__ = 'builtins'\nraise Boom('x')", "Boom: x"),
        (
            "class Boom(Exception):\n    __module__ = '__main__x'\nraise Boom('x')",
            "__main__x.Boom: x",
        ),
        (
            "class Boom(Exception):\n    __module__ = 'xbuiltins'\nraise Boom('x')",
            "xbuiltins.Boom: x",
        ),
        ("class Boom(Exception):\n    __module__ = 'pkg.mod'\nraise Boom('x')", "pkg.mod.Boom: x"),
    ],
)
def test_eval_python_qualifies_exception_types_outside_builtins_and_main(
    code: str, error: str
) -> None:
    assert _failing(code)["error"] == error


@pytest.mark.parametrize(
    ("code", "error"),
    [
        ("class Custom(Exception):\n    pass\nraise Custom('x')", "Custom: x"),
        ("class Quiet(Exception):\n    pass\nraise Quiet()", "Quiet"),
        (
            "def make():\n"
            "    class Inner(Exception):\n"
            "        pass\n"
            "    return Inner\n"
            "raise make()('n')",
            "make.<locals>.Inner: n",
        ),
        (
            "class Outer:\n    class Inner(Exception):\n        pass\nraise Outer.Inner('n')",
            "Outer.Inner: n",
        ),
        (
            "class Outer:\n"
            "    __module__ = 'pkg.mod'\n"
            "    class Inner(Exception):\n"
            "        __module__ = 'pkg.mod'\n"
            "raise Outer.Inner('n')",
            "pkg.mod.Outer.Inner: n",
        ),
    ],
)
def test_eval_python_names_exceptions_defined_in_the_submitted_code(code: str, error: str) -> None:
    assert _failing(code)["error"] == error


def test_eval_python_class_defined_in_the_submitted_code_has_no_module_name() -> None:
    result = _failing(
        "class Custom(Exception):\n    pass\nresult = (Custom.__module__, '__name__' in globals())"
    )
    assert result["result"] == "('builtins', False)"


def test_eval_python_reports_the_outermost_exception_of_a_chain() -> None:
    code = (
        "class Cause(Exception):\n"
        "    __module__ = 'pkg.cause'\n"
        "    def __str__(self):\n"
        "        raise RuntimeError('no str')\n"
        "try:\n"
        "    raise Cause('inner')\n"
        "except Cause as cause:\n"
        "    raise KeyError('outer') from cause"
    )
    assert _failing(code)["error"] == "KeyError: 'outer'"


def test_eval_python_qualifies_the_type_of_an_unrenderable_message_and_system_exit() -> None:
    odd_str = _failing(
        "class Odd(Exception):\n"
        "    __module__ = 'pkg.mod'\n"
        "    def __str__(self):\n"
        "        raise RuntimeError('no str')\n"
        "raise Odd('x')"
    )
    assert odd_str["error"] == "pkg.mod.Odd: <message unavailable>"
    qualified_exit = _failing("class Exit(SystemExit):\n    __module__ = 'pkg.mod'\nraise Exit(3)")
    assert qualified_exit["error"] == "pkg.mod.Exit: exit status 3"


def test_eval_python_reports_system_exit_in_band_with_captured_stdout() -> None:
    result = _failing("import sys\nprint('before')\nresult = 1\nsys.exit(3)")
    assert result["stdout"] == "before\n"
    assert result["result"] is None
    assert result["error"] == "SystemExit: exit status 3"


def test_eval_python_reports_keyboard_interrupt_in_band_with_captured_stdout() -> None:
    result = _failing("print('before')\nraise KeyboardInterrupt('stop')")
    assert result["stdout"] == "before\n"
    assert result["result"] is None
    assert result["error"] == "KeyboardInterrupt: stop"


def test_eval_python_survives_an_exception_whose_message_cannot_render() -> None:
    result = _failing(
        "class Odd(Exception):\n"
        "    def __str__(self):\n"
        "        raise RuntimeError('no str')\n"
        "raise Odd('x')"
    )
    assert result["error"] == "Odd: <message unavailable>"


def test_eval_python_survives_a_system_exit_code_whose_repr_cannot_render() -> None:
    result = _failing(
        "class Odd:\n"
        "    def __repr__(self):\n"
        "        raise RuntimeError('no repr')\n"
        "raise SystemExit(Odd())"
    )
    assert result["error"] == "SystemExit: <message unavailable>"


@pytest.mark.parametrize(
    ("message_length", "truncated"),
    [(499, False), (500, False), (501, True)],
)
def test_eval_python_truncates_the_error_at_the_echo_cap(
    message_length: int, truncated: bool
) -> None:
    result = _failing(f"print('before')\nraise ValueError('z' * {message_length})")
    full = "ValueError: " + "z" * message_length
    assert result["stdout"] == "before\n"
    assert result["error_truncated"] is truncated
    if truncated:
        assert result["error"] == full[:512] + "... [1 chars truncated]"
    else:
        assert result["error"] == full


def test_eval_python_truncation_cuts_the_message_never_the_exception_type() -> None:
    result = _failing("raise ValueError('z' * 1000)")
    assert result["error"] == "ValueError: " + "z" * 500 + "... [500 chars truncated]"
    assert result["error_truncated"] is True


def test_eval_python_locates_the_failing_line_of_the_callers_code() -> None:
    result = _failing("print('before')\nd = {}\n    \nd['x']  ")
    assert result["error_location"] == {"line": 4, "text": "d['x']"}


def test_eval_python_locates_the_innermost_line_of_the_callers_code() -> None:
    result = _failing(
        "def inner():\n    return int('x')\n\ndef outer():\n    return inner()\n\nouter()"
    )
    assert result["error"] == "ValueError: invalid literal for int() with base 10: 'x'"
    assert result["error_location"] == {"line": 2, "text": "return int('x')"}


def test_eval_python_counts_carriage_return_line_breaks() -> None:
    assert _failing("a = 1\r\nb = 2\rraise ValueError('x')")["error_location"] == {
        "line": 3,
        "text": "raise ValueError('x')",
    }


def test_eval_python_counts_only_python_line_breaks() -> None:
    result = _failing("s = '\u2028\x0c\x1c\x85'\nraise ValueError('x')")
    assert result["error_location"] == {"line": 2, "text": "raise ValueError('x')"}


@pytest.mark.parametrize("text_length", [199, 200, 201])
def test_eval_python_bounds_the_located_line(text_length: int) -> None:
    line = "1 / 0  # " + "q" * (text_length - len("1 / 0  # "))
    expected = line if text_length <= 200 else line[:200] + "... [1 chars truncated]"
    result = _failing(line)
    assert result["error"] == "ZeroDivisionError: division by zero"
    assert result["error_location"] == {"line": 1, "text": expected}


def test_eval_python_reports_a_syntax_error_without_a_location() -> None:
    result = _failing("x = (")
    assert result["error"] is not None
    assert result["error"].startswith("SyntaxError: ")
    assert "<rex_eval_python>, line 1" in result["error"]
    assert result["error_location"] is None


def test_eval_python_has_no_location_on_success() -> None:
    result = _failing("result = 1")
    assert result["error"] is None
    assert result["error_location"] is None


def test_eval_python_keeps_text_exactly_at_the_echo_cap_unclipped() -> None:
    escape._EVAL_SPILLS.clear()
    view = _view_with_functions()
    _, evaluate = get_tool("rex_eval_python")
    # repr() adds the two quotes, so this result is exactly the echo cap long: it must
    # come back whole with no truncation flag and no spill key, not clipped by one char
    # with a "... [0 chars truncated]" suffix.
    result = evaluate(_call(view), f"result = 'a' * {escape._MAX_EVAL_RESULT_CHARS - 2}")
    assert result["result"] == "'" + "a" * (escape._MAX_EVAL_RESULT_CHARS - 2) + "'"
    assert result["result_truncated"] is False
    assert result["result_key"] is None
    assert result["result_length"] == escape._MAX_EVAL_RESULT_CHARS
    # The same boundary on the stdout path: exactly cap characters echo whole, unspilled.
    stdout = evaluate(_call(view), f"print('b' * {escape._MAX_EVAL_STDOUT_CHARS - 1})")
    assert stdout["stdout"] == "b" * (escape._MAX_EVAL_STDOUT_CHARS - 1) + "\n"
    assert stdout["stdout_truncated"] is False
    assert stdout["stdout_key"] is None
    assert stdout["stdout_length"] == escape._MAX_EVAL_STDOUT_CHARS


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


def test_eval_python_uses_two_spill_slots_when_stdout_and_result_overflow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    escape._EVAL_SPILLS.clear()
    monkeypatch.setattr(escape, "_MAX_EVAL_SPILLS", 2)
    view = _view_with_functions()
    _, evaluate = get_tool("rex_eval_python")
    _, page = get_tool("rex_eval_result")
    both = evaluate(
        _call(view),
        f"print('s' * {escape._MAX_EVAL_STDOUT_CHARS})\n"
        f"result = 'r' * {escape._MAX_EVAL_RESULT_CHARS}",
    )
    stdout_key = both["stdout_key"]
    result_key = both["result_key"]
    assert stdout_key is not None
    assert result_key is not None
    assert len(escape._EVAL_SPILLS) == 2

    newer = evaluate(_call(view), f"result = 'n' * {escape._MAX_EVAL_RESULT_CHARS}")
    assert newer["result_key"] is not None
    with pytest.raises(FakeToolError) as exc:
        page(_call(view), stdout_key)
    assert exc.value.code == "not_found"
    assert page(_call(view), result_key)["value"].startswith("'r")
    assert page(_call(view), newer["result_key"])["value"].startswith("'n")
    escape._EVAL_SPILLS.clear()


def test_eval_result_validates_page_bounds() -> None:
    escape._EVAL_SPILLS.clear()
    view = _view_with_functions()
    _, evaluate = get_tool("rex_eval_python")
    _, page = get_tool("rex_eval_result")
    result = evaluate(_call(view), f"result = 'x' * {escape._MAX_EVAL_RESULT_CHARS + 1}")
    key = result["result_key"]
    assert key is not None

    for kwargs in (
        {"limit": 0},
        {"limit": escape._MAX_EVAL_RESULT_PAGE_CHARS + 1},
        {"offset": -1},
    ):
        with pytest.raises(FakeToolError) as exc:
            page(_call(view), key, **kwargs)
        assert exc.value.code == "invalid_params"

    assert len(page(_call(view), key, limit=1)["value"]) == 1
    assert page(_call(view), key, limit=escape._MAX_EVAL_RESULT_PAGE_CHARS)["value"] == repr(
        "x" * (escape._MAX_EVAL_RESULT_CHARS + 1)
    )
    escape._EVAL_SPILLS.clear()


def test_eval_spill_store_evicts_exactly_the_oldest_when_the_cap_is_exceeded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    escape._EVAL_SPILLS.clear()
    monkeypatch.setattr(escape, "_MAX_EVAL_SPILLS", 2)
    view = _view_with_functions()
    _, evaluate = get_tool("rex_eval_python")
    _, page = get_tool("rex_eval_result")
    keys = [
        evaluate(_call(view), f"result = '{letter}' * {escape._MAX_EVAL_RESULT_CHARS + 10}")[
            "result_key"
        ]
        for letter in "abc"
    ]
    # Three spills against a two-slot store evict exactly the oldest key; the two most
    # recent spills stay pageable.
    with pytest.raises(FakeToolError) as exc:
        page(_call(view), keys[0])
    assert exc.value.code == "not_found"
    assert page(_call(view), keys[1])["value"].startswith("'b")
    assert page(_call(view), keys[2])["value"].startswith("'c")


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
    readable = evaluate(_call(view), f"result = 'd' * {escape._MAX_EVAL_RESULT_CHARS + 10}")
    readable_key = readable["result_key"]
    assert readable_key is not None
    monkeypatch.setattr(escape, "_MAX_EVAL_SPILL_CHARS", 8)
    dropped = evaluate(_call(view), f"result = 'c' * {escape._MAX_EVAL_RESULT_CHARS + 10}")
    assert dropped["result_truncated"] is True
    assert dropped["result_key"] is None
    assert dropped["result_length"] == escape._MAX_EVAL_RESULT_CHARS + 12
    assert list(escape._EVAL_SPILLS) == [readable_key]
    assert page(_call(view), readable_key)["value"].startswith("'d")


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
