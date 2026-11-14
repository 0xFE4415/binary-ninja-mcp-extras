"""Compile hex byte patterns with wildcards into binary regular expressions."""

from __future__ import annotations

import re
import string
from itertools import batched

_REJECTED_SEPARATORS = "\x1c\x1d\x1e\x1f"


class HexPatternError(ValueError):
    """Raised when a hex pattern cannot be parsed."""


def parse_hex_pattern(pattern: str) -> list[int | None]:
    """Parse a hex byte pattern into byte values, using None for wildcards.

    Whitespace separates tokens; each token holds whole bytes, each exactly two ASCII hex
    digits or "??". U+001C to U+001F are not separators.

    :param pattern: Hex pattern string, e.g. "48 8b ?? 05".
    :returns: One entry per byte; None marks a wildcard byte.
    :raises HexPatternError: The pattern is empty, truncated, or has non-hex tokens.
    """
    for character in pattern:
        if character in _REJECTED_SEPARATORS:
            raise HexPatternError(f"invalid separator U+{ord(character):04X}")
    tokens = pattern.split()
    if not tokens:
        raise HexPatternError("empty hex pattern")
    if any(len(token) % 2 != 0 for token in tokens):
        raise HexPatternError("hex pattern must contain whole bytes")
    cleaned = "".join(tokens)
    return [_parse_byte_token("".join(token)) for token in batched(cleaned, 2)]


def _parse_byte_token(token: str) -> int | None:
    if token == "??":
        return None
    if not all(character in string.hexdigits for character in token):
        raise HexPatternError(f"invalid hex byte token '{token}'")
    return int(token, 16)


def compile_hex_pattern(pattern: str) -> tuple[re.Pattern[bytes], int]:
    """Compile a hex byte pattern into a binary regex plus its byte length.

    The regex uses a lookahead so overlapping matches are all reported.

    :param pattern: Hex pattern string, e.g. "48 8b ?? 05".
    :returns: Tuple of the compiled pattern and its length in bytes.
    :raises HexPatternError: The pattern cannot be parsed.
    """
    values = parse_hex_pattern(pattern)
    body = b"".join(b"." if value is None else re.escape(bytes([value])) for value in values)
    return re.compile(b"(?=(" + body + b"))", re.DOTALL), len(values)
