"""Type-system enum fakes: a leaf module so helpers_view and helpers can both import it."""

from __future__ import annotations

import enum


class FakeStructureVariant(enum.IntEnum):
    """Mirrors binaryninja.enums.StructureVariant."""

    ClassStructureType = 0
    StructStructureType = 1
    UnionStructureType = 2
