from __future__ import annotations

import pytest

from binja_plugin.hexpattern import (
    HexPatternError,
    _parse_byte_token,
    compile_hex_pattern,
    parse_hex_pattern,
)

# Must equal SEPARATOR_CODE_POINTS in native/src/hexpattern.rs and the set in CONTRACTS.md.
PYTHON_SEPARATORS = [
    *(0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20, 0x85, 0xA0, 0x1680),
    *range(0x2000, 0x200B),
    *(0x2028, 0x2029, 0x202F, 0x205F, 0x3000),
]


def test_separators_are_exactly_the_pinned_set() -> None:
    accepted = []
    for code_point in range(0x110000):
        try:
            parse_hex_pattern(f"48{chr(code_point)}8b")
        except HexPatternError:
            continue
        accepted.append(code_point)
    assert accepted == PYTHON_SEPARATORS
    assert len(PYTHON_SEPARATORS) == 25


@pytest.mark.parametrize(
    "pattern,expected_message",
    [
        ("", "empty hex pattern"),
        ("   ", "empty hex pattern"),
        ("4", "hex pattern must contain whole bytes"),
        ("48 8", "hex pattern must contain whole bytes"),
        ("zz", "invalid hex byte token 'zz'"),
        ("48 8z", "invalid hex byte token '8z'"),
        ("48 8\nz", "hex pattern must contain whole bytes"),
        ("9 0", "hex pattern must contain whole bytes"),
        ("48 9 0", "hex pattern must contain whole bytes"),
        ("4 8 8b", "hex pattern must contain whole bytes"),
        ("48\x1c8b", "invalid separator U+001C"),
        ("48\x1d8b", "invalid separator U+001D"),
        ("48\x1e8b", "invalid separator U+001E"),
        ("\x1f", "invalid separator U+001F"),
    ],
)
def test_parse_rejects_invalid_patterns(pattern: str, expected_message: str) -> None:
    with pytest.raises(HexPatternError) as exc:
        parse_hex_pattern(pattern)
    assert str(exc.value) == expected_message


@pytest.mark.parametrize(
    "pattern,bad_token",
    [
        ("+f", "+f"),
        ("-1", "-1"),
        ("48 +f", "+f"),
        ("-f 48", "-f"),
        ("f_", "f_"),
        ("_f", "_f"),
        ("1_ 48", "1_"),
        ("0x", "0x"),
        ("0X", "0X"),
        ("x0", "x0"),
        ("g0", "g0"),
        ("0g", "0g"),
        ("G0", "G0"),
        ("0G", "0G"),
        ("/0", "/0"),
        ("0/", "0/"),
        (":0", ":0"),
        ("0:", "0:"),
        ("@0", "@0"),
        ("0@", "0@"),
        ("`0", "`0"),
        ("0`", "0`"),
        ("?5", "?5"),
        ("5?", "5?"),
        ("\u0664\u0668", "\u0664\u0668"),
        ("4\u0668", "4\u0668"),
        ("\u06648", "\u06648"),
        ("\uff14\uff18", "\uff14\uff18"),
        ("\uff21f", "\uff21f"),
        ("\u00bd0", "\u00bd0"),
    ],
)
def test_parse_rejects_lenient_int_forms(pattern: str, bad_token: str) -> None:
    with pytest.raises(HexPatternError) as exc:
        parse_hex_pattern(pattern)
    assert str(exc.value) == f"invalid hex byte token '{bad_token}'"


@pytest.mark.parametrize(
    "token",
    [" f", "f ", " ff", "\tf", "f\n", "\u00a0f", "\u2003f", "f\u00a0", "+f", "-1", "\u0664\u0668"],
)
def test_byte_token_rejects_whitespace_and_signs(token: str) -> None:
    with pytest.raises(HexPatternError) as exc:
        _parse_byte_token(token)
    assert str(exc.value) == f"invalid hex byte token '{token}'"


def test_parse_accepts_every_byte_in_both_cases() -> None:
    for value in range(256):
        assert parse_hex_pattern(f"{value:02x}") == [value]
        assert parse_hex_pattern(f"{value:02X}") == [value]


@pytest.mark.parametrize(
    "token,expected",
    [
        ("00", 0),
        ("09", 9),
        ("0a", 10),
        ("0F", 15),
        ("a0", 160),
        ("Fa", 250),
        ("ff", 255),
        ("??", None),
    ],
)
def test_byte_token_values(token: str, expected: int | None) -> None:
    assert _parse_byte_token(token) == expected


@pytest.mark.parametrize(
    "pattern,expected",
    [
        ("488b", [0x48, 0x8B]),
        ("48 8b", [0x48, 0x8B]),
        ("48 8B", [0x48, 0x8B]),
        ("??", [None]),
        ("a5 ?? 05", [0xA5, None, 0x05]),
        ("?? ??", [None, None]),
        ("??a5", [None, 0xA5]),
        ("Ab cD eF", [0xAB, 0xCD, 0xEF]),
        # Any whitespace is a separator, including trailing newlines from copy-pasted patterns.
        ("48 8b\n", [0x48, 0x8B]),
        ("48\n\t8b\r", [0x48, 0x8B]),
    ],
)
def test_parse_accepts_valid_patterns(pattern: str, expected: list[int | None]) -> None:
    assert parse_hex_pattern(pattern) == expected


def test_compile_matches_literal_and_wildcards() -> None:
    matcher, length = compile_hex_pattern("48 ?? 05")
    assert length == 3
    blob = b"H\x00\x05H\x99\x05"
    assert [match.start() for match in matcher.finditer(blob)] == [0, 3]


def test_compile_reports_overlapping_matches() -> None:
    matcher, length = compile_hex_pattern("90 90")
    assert length == 2
    assert [match.start() for match in matcher.finditer(b"\x90\x90\x90")] == [0, 1]


def test_compile_wildcard_matches_newline() -> None:
    matcher, length = compile_hex_pattern("??")
    assert length == 1
    assert [match.start() for match in matcher.finditer(b"\n")] == [0]
