from __future__ import annotations

from pathlib import Path

import pytest
from helpers import (
    FakeBinaryView,
    FakeSymbol,
    FakeToolError,
    _call,
    _disasm_view,
    _use_export_root,
    get_tool,
)

from binja_plugin import tools
from binja_plugin.tools import exports


def test_export_disasm_writes_the_window_to_a_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _use_export_root(monkeypatch, tmp_path)
    view = _disasm_view()
    _, export = get_tool("rex_export_disasm")
    result = export(_call(view), 0x1104, filename="main.txt")
    expected = "push rbp\nmov rbp, rsp\nsub rsp, 0x20\nmov eax, 1\nleave\nret\n"
    assert result == {
        "path": str((root / "main.txt").resolve()),
        "bytes_written": len(expected.encode("utf-8")),
        "lines": 6,
        "truncated": False,
    }
    # Byte-exact read: read_bytes also proves the LF endings (no \r\n translation).
    assert (root / "main.txt").read_bytes() == expected.encode("utf-8")


def test_export_disasm_creates_nested_export_root(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = tmp_path / "nested" / "exports"
    monkeypatch.setattr(tools, "_EXPORT_ROOT", root)
    _, export = get_tool("rex_export_disasm")
    result = export(_call(_disasm_view()), 0x1104, filename="main.txt")
    assert Path(result["path"]) == root / "main.txt"
    assert (root / "main.txt").read_bytes() == (
        b"push rbp\nmov rbp, rsp\nsub rsp, 0x20\nmov eax, 1\nleave\nret\n"
    )


def test_export_disasm_caps_the_window_at_max_lines(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _use_export_root(monkeypatch, tmp_path)
    view = _disasm_view()
    _, export = get_tool("rex_export_disasm")
    # Window of 3 lines (anchor 0x1101, before=2, after=1) clipped to 2 by max_lines.
    clipped = export(_call(view), 0x1101, before=2, after=1, max_lines=2, filename="clip.txt")
    assert clipped["lines"] == 2
    assert clipped["truncated"] is True
    assert (root / "clip.txt").read_bytes() == b"push rbp\nmov rbp, rsp\n"
    # Exactly at max_lines nothing is reported as truncated.
    exact = export(_call(view), 0x1104, max_lines=6, filename="full.txt")
    assert exact["lines"] == 6
    assert exact["truncated"] is False
    # A window clipped at a function edge also leaves rendered lines out of the file,
    # so the truncation flag fires even though no cap was hit.
    edge = export(_call(view), 0x110E, before=1, after=8, filename="edge.txt")
    assert edge["lines"] == 2
    assert edge["truncated"] is True


def test_fit_to_export_cap_keeps_the_largest_fitting_prefix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def serialize(selected: list[str]) -> str:
        return "".join(selected)

    rows = ["x" * 10, "y" * 10, "z" * 10, "w" * 10]
    monkeypatch.setattr(tools, "_MAX_EXPORT_FILE_BYTES", 21)
    window = list(rows)
    text, dropped = tools._fit_to_export_cap(serialize, window)
    assert text == rows[0] + rows[1]
    assert dropped is True
    assert window == [rows[0], rows[1]]

    monkeypatch.setattr(tools, "_MAX_EXPORT_FILE_BYTES", 40)
    window = list(rows)
    assert tools._fit_to_export_cap(serialize, window) == (serialize(rows), False)
    assert window == rows

    # A prefix serializing to exactly cap + 1 bytes is over the cap and must be dropped.
    exact_over = ["a" * 10, "b" * 11, "c" * 10]
    monkeypatch.setattr(tools, "_MAX_EXPORT_FILE_BYTES", 20)
    window = list(exact_over)
    text, dropped = tools._fit_to_export_cap(serialize, window)
    assert text == exact_over[0]
    assert dropped is True
    assert window == [exact_over[0]]


def test_fit_to_export_cap_search_converges_on_a_false_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def serialize(selected: list[str]) -> str:
        nonlocal calls
        calls += 1
        if calls > 100:
            raise RuntimeError("cap search did not converge")
        return "".join(selected)

    rows = ["x" * 10, "y" * 10, "z" * 10, "w" * 10, "v" * 10]
    monkeypatch.setattr(tools, "_MAX_EXPORT_FILE_BYTES", 25)
    window = list(rows)
    text, dropped = tools._fit_to_export_cap(serialize, window)
    assert text == rows[0] + rows[1]
    assert dropped is True
    assert window == rows[:2]


def test_write_export_file_pins_utf8_lf_semantics(monkeypatch: pytest.MonkeyPatch) -> None:
    opened: dict[str, object] = {}

    class FakeHandle:
        def __enter__(self) -> FakeHandle:
            return self

        def __exit__(self, *args: object) -> bool:
            return False

        def write(self, text: str) -> None:
            opened["written"] = text

    def fake_open(path: object, mode: str = "r", **kwargs: object) -> FakeHandle:
        opened["mode"] = mode
        opened.update(kwargs)
        return FakeHandle()

    monkeypatch.setattr("builtins.open", fake_open)
    text = "héllo\n"
    assert tools._write_export_file(Path("x.txt"), text) == len(text.encode("utf-8"))
    assert opened == {
        "mode": "w",
        "encoding": "utf-8",
        "newline": "",
        "written": text,
    }


def test_export_disasm_shrinks_to_the_byte_cap(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _use_export_root(monkeypatch, tmp_path)
    # 36 bytes hold exactly the first three lines; the fourth ("mov eax, 1\n") would
    # push the file to 47 bytes, so it and everything after it are dropped.
    monkeypatch.setattr(tools, "_MAX_EXPORT_FILE_BYTES", 36)
    view = _disasm_view()
    _, export = get_tool("rex_export_disasm")
    result = export(_call(view), 0x1104, filename="shrink.txt")
    expected = b"push rbp\nmov rbp, rsp\nsub rsp, 0x20\n"
    assert result["lines"] == 3
    assert result["truncated"] is True
    assert result["bytes_written"] == len(expected)
    assert (root / "shrink.txt").read_bytes() == expected

    monkeypatch.setattr(tools, "_MAX_EXPORT_FILE_BYTES", len(b"push rbp\n"))
    exact = export(_call(view), 0x1104, filename="exact.txt")
    assert exact["lines"] == 1
    assert exact["bytes_written"] == len(b"push rbp\n")
    assert exact["truncated"] is True
    assert (root / "exact.txt").read_bytes() == b"push rbp\n"


def test_export_disasm_rejects_a_single_line_over_the_cap(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _use_export_root(monkeypatch, tmp_path)
    # Even the first line ("push rbp\n" is 9 bytes) cannot fit under an 8-byte cap, so
    # shrinking from the end could never produce a file: reject instead of writing one.
    monkeypatch.setattr(tools, "_MAX_EXPORT_FILE_BYTES", 8)
    view = _disasm_view()
    _, export = get_tool("rex_export_disasm")
    with pytest.raises(FakeToolError) as exc:
        export(_call(view), 0x1104, filename="tiny.txt")
    assert exc.value.code == "export_failed"
    assert exc.value.message == "first entry exceeds the export byte cap"
    # The rejection happens before any filesystem work: not even the root was created.
    assert not root.exists()


def test_export_disasm_rejects_out_of_function_addresses_and_ranges() -> None:
    view = _disasm_view()
    _, export = get_tool("rex_export_disasm")
    # Same rejection as rex_disasm_at: never snapped to a neighboring function.
    with pytest.raises(FakeToolError) as exc:
        export(_call(view), 0x1800, filename="gap.txt")
    assert exc.value.code == "invalid_params"
    assert exc.value.message == "no analyzed function contains 0x1800"
    for kwargs, message in (
        ({"before": -1}, "Invalid integer parameter 'before': Must be at least 0"),
        ({"after": -1}, "Invalid integer parameter 'after': Must be at least 0"),
        (
            {"before": tools._MAX_DISASM_CONTEXT + 1},
            f"Invalid integer parameter 'before': Must be at most {tools._MAX_DISASM_CONTEXT}",
        ),
        (
            {"after": tools._MAX_DISASM_CONTEXT + 1},
            f"Invalid integer parameter 'after': Must be at most {tools._MAX_DISASM_CONTEXT}",
        ),
        ({"max_lines": 0}, "Invalid integer parameter 'max_lines': Must be at least 1"),
        (
            {"max_lines": exports._MAX_EXPORT_DISASM_LINES + 1},
            f"Invalid integer parameter 'max_lines': Must be at most "
            f"{exports._MAX_EXPORT_DISASM_LINES}",
        ),
    ):
        with pytest.raises(FakeToolError) as exc:
            export(_call(view), 0x1104, filename="x.txt", **kwargs)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == message
    # Both bounds are inclusive on every size parameter.
    at_caps = export(
        _call(view),
        0x1104,
        before=tools._MAX_DISASM_CONTEXT,
        after=tools._MAX_DISASM_CONTEXT,
        max_lines=exports._MAX_EXPORT_DISASM_LINES,
        filename="caps.txt",
    )
    assert at_caps["lines"] == 6
    # Range errors are checked before the address lookup, like rex_disasm_at.
    with pytest.raises(FakeToolError) as exc:
        export(_call(FakeBinaryView()), 0x1104, before=-1, filename="x.txt")
    assert exc.value.message == "Invalid integer parameter 'before': Must be at least 0"


def test_export_disasm_reports_export_failed_when_the_write_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = tmp_path / "exports"
    root.mkdir()
    # A directory sitting where the file would go makes open() raise IsADirectoryError;
    # the handler must turn that into export_failed, not leak the OSError.
    (root / "occupied.txt").mkdir()
    monkeypatch.setattr(tools, "_EXPORT_ROOT", root)
    view = _disasm_view()
    _, export = get_tool("rex_export_disasm")
    with pytest.raises(FakeToolError) as exc:
        export(_call(view), 0x1104, filename="occupied.txt")
    assert exc.value.code == "export_failed"
    # The OSError text is appended, so the message stays explainable to the caller.
    assert exc.value.message.startswith("could not write export file: ")


def test_export_symbols_reports_export_failed_when_the_root_cannot_be_created(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # A regular file where the export root would go makes mkdir() raise
    # NotADirectoryError; the handler must turn that into export_failed, not leak it.
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory")
    monkeypatch.setattr(tools, "_EXPORT_ROOT", blocker / "exports")
    _, export = get_tool("rex_export_symbols")
    with pytest.raises(FakeToolError) as exc:
        export(_call(_symbol_view()), 0x1000, 0x4000, filename="syms.csv")
    assert exc.value.code == "export_failed"
    assert "could not prepare export path" in exc.value.message


def test_export_disasm_fails_nested_filenames_at_the_write(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _use_export_root(monkeypatch, tmp_path)
    view = _disasm_view()
    _, export = get_tool("rex_export_disasm")
    # Lexical validation allows a nested relative name, but only the fixed root itself is
    # ever created on demand, so the write fails into export_failed instead of silently
    # growing a tree under the root.
    with pytest.raises(FakeToolError) as exc:
        export(_call(view), 0x1104, filename="sub/out.txt")
    assert exc.value.code == "export_failed"
    assert not (root / "sub").exists()


def test_export_disasm_accepts_a_component_at_the_name_max_bound(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _use_export_root(monkeypatch, tmp_path)
    filename = "y" * 251 + ".txt"  # exactly 255 bytes, the NAME_MAX bound
    view = _disasm_view()
    _, export = get_tool("rex_export_disasm")
    result = export(_call(view), 0x1104, filename=filename)
    assert result["path"] == str((root / filename).resolve())
    assert (root / filename).exists()


def test_export_disasm_rejects_a_symlink_escaping_the_export_root(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _use_export_root(monkeypatch, tmp_path)
    root.mkdir(parents=True)
    outside = tmp_path / "outside.txt"
    outside.write_text("untouched")
    # A symlink planted inside the root passes the purely lexical filename validation;
    # only the containment check after resolve() can see where the write would land.
    (root / "link.txt").symlink_to(outside)
    view = _disasm_view()
    _, export = get_tool("rex_export_disasm")
    with pytest.raises(FakeToolError) as exc:
        export(_call(view), 0x1104, filename="link.txt")
    assert exc.value.code == "path_escape"
    assert str(outside) in exc.value.message
    assert outside.read_text() == "untouched"
    # resolve() follows intermediate components too, so a symlinked directory inside
    # the root cannot smuggle a write out either.
    (root / "sub").mkdir()
    (root / "sub" / "link.txt").symlink_to(outside)
    with pytest.raises(FakeToolError) as exc:
        export(_call(view), 0x1104, filename="sub/link.txt")
    assert exc.value.code == "path_escape"
    assert outside.read_text() == "untouched"


@pytest.mark.parametrize(
    "filename",
    [
        "/abs/path.txt",
        "up/../down.txt",
        "back\\slash.txt",
        "nul\x00byte.txt",
        "x" * 256,
        "",
    ],
)
def test_export_tools_reject_unsafe_filenames(
    filename: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _use_export_root(monkeypatch, tmp_path)
    _, export_disasm = get_tool("rex_export_disasm")
    with pytest.raises(FakeToolError) as exc:
        export_disasm(_call(_disasm_view()), 0x1104, filename=filename)
    assert exc.value.code == "invalid_params"
    _, export_symbols = get_tool("rex_export_symbols")
    with pytest.raises(FakeToolError) as exc:
        export_symbols(_call(_symbol_view()), 0x1000, 0x4000, filename=filename)
    assert exc.value.code == "invalid_params"


def test_validate_export_path_rejects_each_violation_with_a_clear_message() -> None:
    cases = [
        ("", "filename must not be empty"),
        ("/etc/passwd", "filename must be a plain file name, not an absolute path"),
        ("back\\slash.txt", "filename must not contain backslashes"),
        ("nul\x00byte.txt", "filename must not contain NUL bytes"),
        ("up/../down.txt", "filename must not contain '..' path components"),
        ("x" * 256, f"filename component exceeds {tools._MAX_EXPORT_COMPONENT_BYTES} bytes"),
    ]
    for filename, message in cases:
        with pytest.raises(FakeToolError) as exc:
            tools._validate_export_path(filename)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == message
    # Plain names and a component exactly at the NAME_MAX bound pass the pure validator.
    tools._validate_export_path("plain.txt")
    tools._validate_export_path("y" * 251 + ".txt")
    tools._validate_export_path("sub/plain.txt")


def _symbol_view() -> FakeBinaryView:
    # Deliberately unsorted, with symbols below and above the queried range and a name
    # containing a comma to pin the CSV quoting.
    return FakeBinaryView(
        symbols=[
            FakeSymbol(0x3000, "FunctionSymbol", "late"),
            FakeSymbol(0x5000, "DataSymbol", "outside"),
            FakeSymbol(0x1000, "FunctionSymbol", "main"),
            FakeSymbol(0x0500, "DataSymbol", "early"),
            FakeSymbol(0x2000, "DataSymbol", "msg, with comma"),
        ]
    )


def test_export_symbols_writes_a_sorted_csv_window(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _use_export_root(monkeypatch, tmp_path)
    _, export = get_tool("rex_export_symbols")
    result = export(_call(_symbol_view()), 0x1000, 0x4000, filename="syms.csv")
    expected = (
        "symbol_address,symbol_type,name\n"
        "0x1000,FunctionSymbol,main\n"
        '0x2000,DataSymbol,"msg, with comma"\n'
        "0x3000,FunctionSymbol,late\n"
    )
    assert result == {
        "path": str((root / "syms.csv").resolve()),
        "bytes_written": len(expected.encode("utf-8")),
        "rows": 3,
        "truncated": False,
        "total": 3,
    }
    assert (root / "syms.csv").read_bytes() == expected.encode("utf-8")


def test_export_symbols_offset_limit_and_truncation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _use_export_root(monkeypatch, tmp_path)
    _, export = get_tool("rex_export_symbols")
    view = _symbol_view()
    header = b"symbol_address,symbol_type,name\n"
    # The window is a slice of the address-sorted list, and pagination past the end
    # reports the true total with an empty window.
    limited = export(_call(view), 0x1000, 0x4000, limit=2, filename="page1.csv")
    assert limited["rows"] == 2
    assert limited["total"] == 3
    assert limited["truncated"] is True
    paged = export(_call(view), 0x1000, 0x4000, limit=2, offset=1, filename="page2.csv")
    assert paged["rows"] == 2
    assert paged["truncated"] is False
    assert (root / "page2.csv").read_bytes() == (
        header + b'0x2000,DataSymbol,"msg, with comma"\n' + b"0x3000,FunctionSymbol,late\n"
    )
    at_end = export(_call(view), 0x1000, 0x4000, offset=3, filename="tail.csv")
    assert at_end["rows"] == 0
    assert at_end["total"] == 3
    assert at_end["truncated"] is False
    assert (root / "tail.csv").read_bytes() == header
    # limit=0 pages nothing out but still reports that more symbols existed.
    zero = export(_call(view), 0x1000, 0x4000, limit=0, filename="empty.csv")
    assert zero["rows"] == 0
    assert zero["total"] == 3
    assert zero["truncated"] is True


def test_export_symbols_writes_json(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    root = _use_export_root(monkeypatch, tmp_path)
    _, export = get_tool("rex_export_symbols")
    result = export(_call(_symbol_view()), 0x1000, 0x4000, format="json", filename="syms.json")
    expected = """[
  {
    "symbol_address": "0x1000",
    "symbol_type": "FunctionSymbol",
    "name": "main"
  },
  {
    "symbol_address": "0x2000",
    "symbol_type": "DataSymbol",
    "name": "msg, with comma"
  },
  {
    "symbol_address": "0x3000",
    "symbol_type": "FunctionSymbol",
    "name": "late"
  }
]"""
    assert result["bytes_written"] == len(expected.encode("utf-8"))
    assert result["rows"] == 3
    assert result["total"] == 3
    assert result["truncated"] is False
    # Byte-exact: indented JSON, closing bracket included, no trailing newline.
    assert (root / "syms.json").read_bytes() == expected.encode("utf-8")


def test_export_symbols_shrinks_to_the_byte_cap(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _use_export_root(monkeypatch, tmp_path)
    two_rows = (
        "symbol_address,symbol_type,name\n"
        "0x1000,FunctionSymbol,main\n"
        '0x2000,DataSymbol,"msg, with comma"\n'
    )
    monkeypatch.setattr(tools, "_MAX_EXPORT_FILE_BYTES", len(two_rows.encode("utf-8")))
    _, export = get_tool("rex_export_symbols")
    result = export(_call(_symbol_view()), 0x1000, 0x4000, filename="capped.csv")
    # No pagination happened (the window held all three symbols), so the truncated flag
    # must come from the size drop alone.
    assert result["rows"] == 2
    assert result["total"] == 3
    assert result["truncated"] is True
    assert (root / "capped.csv").read_bytes() == two_rows.encode("utf-8")


def test_export_symbols_rejects_a_single_row_over_the_cap(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _use_export_root(monkeypatch, tmp_path)
    # The 32-byte header plus the first row can never fit under a 16-byte cap.
    monkeypatch.setattr(tools, "_MAX_EXPORT_FILE_BYTES", 16)
    _, export = get_tool("rex_export_symbols")
    with pytest.raises(FakeToolError) as exc:
        export(_call(_symbol_view()), 0x1000, 0x4000, filename="tiny.csv")
    assert exc.value.code == "export_failed"
    assert exc.value.message == "first entry exceeds the export byte cap"
    assert not root.exists()


def test_export_symbols_writes_a_header_only_file_for_an_empty_range(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _use_export_root(monkeypatch, tmp_path)
    _, export = get_tool("rex_export_symbols")
    result = export(_call(_symbol_view()), 0x8000, 0x9000, filename="none.csv")
    assert result == {
        "path": str((root / "none.csv").resolve()),
        "bytes_written": 32,
        "rows": 0,
        "truncated": False,
        "total": 0,
    }
    assert (root / "none.csv").read_bytes() == b"symbol_address,symbol_type,name\n"


def test_export_symbols_rejects_invalid_ranges_limits_and_format() -> None:
    view = _symbol_view()
    _, export = get_tool("rex_export_symbols")
    for kwargs, message in (
        ({"start": 0x1000, "end": 0x1000}, "end must be greater than start"),
        ({"start": 0x4000, "end": 0x1000}, "end must be greater than start"),
        ({"start": -1, "end": 0x4000}, "Invalid integer parameter 'start': Must be at least 0"),
    ):
        with pytest.raises(FakeToolError) as exc:
            export(_call(view), filename="x.csv", **kwargs)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == message
    for kwargs, message in (
        ({"limit": -1}, "Invalid integer parameter 'limit': Must be at least 0"),
        (
            {"limit": tools._MAX_EXPORT_SYMBOLS + 1},
            f"Invalid integer parameter 'limit': Must be at most {tools._MAX_EXPORT_SYMBOLS}",
        ),
        ({"offset": -1}, "Invalid integer parameter 'offset': Must be at least 0"),
        ({"format": "xml"}, "format must be 'csv' or 'json', not 'xml'"),
    ):
        with pytest.raises(FakeToolError) as exc:
            export(_call(view), 0x1000, 0x4000, filename="x.csv", **kwargs)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == message
    # Exactly at the limit cap the export still runs.
    at_cap = export(
        _call(view), 0x1000, 0x4000, limit=tools._MAX_EXPORT_SYMBOLS, filename="cap.csv"
    )
    assert at_cap["rows"] == 3
