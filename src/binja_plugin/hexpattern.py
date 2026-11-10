"""Compile hex byte patterns with wildcards into binary regular expressions."""

from __future__ import annotations

import re
from itertools import batched


class HexPatternError(ValueError):
    """Raised when a hex pattern cannot be parsed."""


def parse_hex_pattern(pattern: str) -> list[int | None]:
    """Parse a hex byte pattern into byte values, using None for wildcards.

    Accepts optional whitespace between byte tokens and "AS ?? 05" style wildcards.

    :param pattern: Hex pattern string, e.g. "48 8b ?? 05".
    :returns: One entry per byte; None marks a wildcard byte.
    :raises HexPatternError: The pattern is empty, truncated, or has non-hex tokens.
    """
    cleaned = "".join(pattern.split())
    if not cleaned:
        raise HexPatternError("empty hex pattern")
    if len(cleaned) % 2 != 0:
        raise HexPatternError("hex pattern must contain whole bytes")
    return [_parse_byte_token("".join(token)) for token in batched(cleaned, 2)]


def _parse_byte_token(token: str) -> int | None:
    if token == "??":
        return None
    try:
        return int(token, 16)
    except ValueError:
        raise HexPatternError(f"invalid hex byte token '{token}'") from None


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
