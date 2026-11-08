"""UIDF fakes for exercising the rex_uidf_* tools: variables, MLIL definitions, values.

A leaf module by design: helpers imports it, so it must not import helpers back.
"""

from __future__ import annotations

import enum
from typing import Any, override


class FakeRegisterValueType(enum.IntEnum):
    """Mirrors binaryninja.enums.RegisterValueType."""

    UndeterminedValue = 0
    EntryValue = 1
    ConstantValue = 2
    ConstantPointerValue = 3
    ExternalPointerValue = 4
    StackFrameOffset = 5
    ReturnAddressValue = 6
    ImportedAddressValue = 7
    ResultPointerValue = 8
    ParameterPointerValue = 9
    SignedRangeValue = 10
    UnsignedRangeValue = 11
    LookupTableValue = 12
    InSetOfValues = 13
    NotInSetOfValues = 14
    ConstantDataValue = 32768
    ConstantDataZeroExtendValue = 32769
    ConstantDataSignExtendValue = 32770
    ConstantDataAggregateValue = 32771


class FakeVariable:
    """Mirrors binaryninja.variable.Variable for the name and storage surface the tools read."""

    storage: int = 0
    source_type: Any = None

    def __init__(self, name: str) -> None:
        self.name = name


class FakeMLILDefinition:
    """Mirrors a MediumLevelILInstruction as a definition site: its address."""

    def __init__(self, address: int) -> None:
        self.address = address


class FakeMediumLevelIL:
    """Mirrors MediumLevelILFunction.get_var_definitions: defs keyed per variable object."""

    def __init__(self, definitions: dict[FakeVariable, list[int]]) -> None:
        self._definitions = {
            variable: [FakeMLILDefinition(address) for address in sites]
            for variable, sites in definitions.items()
        }

    def get_var_definitions(self, variable: FakeVariable) -> list[FakeMLILDefinition]:
        return list(self._definitions.get(variable, []))


class FakePossibleValueSet:
    """Mirrors binaryninja.variable.PossibleValueSet: str() renders, .type names the state."""

    def __init__(self, state: FakeRegisterValueType, rendered: str) -> None:
        self.type = state
        self._rendered = rendered

    @override
    def __str__(self) -> str:
        return self._rendered


def parse_possible_value_set(
    value: str, state: FakeRegisterValueType, here: int
) -> FakePossibleValueSet:
    """Model BinaryView.parse_possiblevalueset's documented grammar for the states the
    uidf tools accept: hex-by-default constants, "start:end:step" ranges, and value sets,
    with "$here" resolving to the here argument. States with no documented string grammar
    are rejected like the real parser rejects an unparsable spec."""
    text = value.replace("$here", hex(here))
    if state in (FakeRegisterValueType.SignedRangeValue, FakeRegisterValueType.UnsignedRangeValue):
        ranges = []
        for part in text.split(","):
            bounds = part.split(":")
            if len(bounds) != 3:
                raise ValueError("Did not find all expected elements")
            start, end, step = int(bounds[0], 16), int(bounds[1], 16), int(bounds[2], 16)
            ranges.append((start, end, step))
        rendered = ", ".join(
            f"<range: {start:#x} to {end:#x}>" + (f", step {step:#x}" if step != 1 else "")
            for start, end, step in ranges
        )
        label = "signed" if state is FakeRegisterValueType.SignedRangeValue else "unsigned"
        return FakePossibleValueSet(state, f"<{label} ranges: [{rendered}]>")
    if state in (FakeRegisterValueType.InSetOfValues, FakeRegisterValueType.NotInSetOfValues):
        values = [int(part, 16) for part in text.split(",")]
        label = "in set" if state is FakeRegisterValueType.InSetOfValues else "not in set"
        rendered = ", ".join(f"{item:#x}" for item in values)
        return FakePossibleValueSet(state, f"<{label}([{rendered}])>")
    return FakePossibleValueSet(state, f"<const {int(text, 16):#x}>")
