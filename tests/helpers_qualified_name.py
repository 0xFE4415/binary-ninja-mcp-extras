"""Fake QualifiedName and the name a C function prototype carries, as parse_type_string reports."""

from __future__ import annotations

import re
from typing import Any, override

_PROTOTYPE_NAME = re.compile(r"^[\w\s*]+?[\s*](\w+)\s*\(")


class FakeQualifiedName:
    """Mirrors QualifiedName: empty is falsy through __len__, str joins the parts with '::'."""

    def __init__(self, *parts: str) -> None:
        self.name = list(parts)

    def __len__(self) -> int:
        return len(self.name)

    @override
    def __str__(self) -> str:
        return "::".join(self.name)


ParseOutcome = tuple[Any, FakeQualifiedName] | Exception


def prototype_name(text: str) -> FakeQualifiedName:
    match = _PROTOTYPE_NAME.match(text)
    if match is None:
        return FakeQualifiedName()
    return FakeQualifiedName(match.group(1))
