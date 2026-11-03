from __future__ import annotations

import pytest

from binja_plugin.hexpattern import HexPatternError, compile_hex_pattern, parse_hex_pattern


@pytest.mark.parametrize(
    "pattern,expected_message",
    [
        ("", "empty hex pattern"),
        ("   ", "empty hex pattern"),
        ("4", "hex pattern must contain whole bytes"),
        ("48 8", "hex pattern must contain whole bytes"),
        ("zz", "invalid hex byte token 'zz'"),
        ("48 8z", "invalid hex byte token '8z'"),
        ("48 8\nz", "invalid hex byte token '8z'"),
    ],
)
def test_parse_rejects_invalid_patterns(pattern: str, expected_message: str) -> None:
    with pytest.raises(HexPatternError) as exc:
        parse_hex_pattern(pattern)
    assert str(exc.value) == expected_message


@pytest.mark.parametrize(
    "pattern,expected",
    [
        ("488b", [0x48, 0x8B]),
        ("48 8b", [0x48, 0x8B]),
        ("48 8B", [0x48, 0x8B]),
        ("??", [None]),
        ("a5 ?? 05", [0xA5, None, 0x05]),
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
