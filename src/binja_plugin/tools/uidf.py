"""User-informed data flow tools: inform variable values, clear them, and list them.

The definition site is the address of the MLIL instruction that defines the variable, the
same (arch, address) pair the core stores per informed value; resolving it from the
variable's name is what keeps rex_uidf_set and rex_uidf_clear inside the core's contract
that a user value always attaches to a real definition site.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from dataclasses import dataclass
from typing import TYPE_CHECKING, Annotated, Final, Literal, NotRequired, TypedDict

from binaryninja import mcp
from binaryninja.binaryview import BinaryView
from binaryninja.enums import AnalysisState, RegisterValueType
from binaryninja.function import Function
from binaryninja.mediumlevelil import MediumLevelILInstruction
from binaryninja.variable import Variable

from binja_plugin.tools import (
    _MAX_DECOMPILE_LINES,
    _MAX_LIMIT,
    _MAX_NAME_CANDIDATES,
    _function_entry,
    _FunctionEntry,
    _is_json_object,
    _ItemError,
    _missing_il_error,
    _paginate,
    _render_hlil_lines,
    _require_analyzed_function,
    _ResolvedFunction,
    _truncate,
    _validate_range,
)

if TYPE_CHECKING:
    from binaryninja.variable import PossibleValueSet

# rex_uidf_set settles the reanalysis an informed value schedules before rendering HLIL,
# polling like rex_analysis_wait; the deadline bounds one call's hold on the server thread.
_UIDF_ANALYSIS_SLICE_MS: Final = 100
_MAX_UIDF_ANALYSIS_WAIT_MS: Final = 10000
_MAX_UIDF_BATCH: Final = 128

_UIDF_ITEMS_SCHEMA: Final[dict[str, object]] = {
    "type": "object",
    "properties": {
        "variable": {"type": "string", "minLength": 1},
        "value": {"type": "string", "minLength": 1},
        "def_address": {
            "type": ["integer", "string"],
            "description": "Definition site; required when the variable has multiple definitions.",
        },
        "state": {
            "type": "string",
            "enum": [
                "ConstantValue",
                "ConstantPointerValue",
                "StackFrameOffset",
                "SignedRangeValue",
                "UnsignedRangeValue",
                "InSetOfValues",
                "NotInSetOfValues",
            ],
        },
    },
    "required": ["variable", "value"],
}

# The states BinaryView.parse_possiblevalueset documents a string grammar for; the schema
# advertises exactly these, so a state with no documented syntax is never offered.
_VALUE_STATES: Final[dict[str, RegisterValueType]] = {
    "ConstantValue": RegisterValueType.ConstantValue,
    "ConstantPointerValue": RegisterValueType.ConstantPointerValue,
    "StackFrameOffset": RegisterValueType.StackFrameOffset,
    "SignedRangeValue": RegisterValueType.SignedRangeValue,
    "UnsignedRangeValue": RegisterValueType.UnsignedRangeValue,
    "InSetOfValues": RegisterValueType.InSetOfValues,
    "NotInSetOfValues": RegisterValueType.NotInSetOfValues,
}

ValueState = Literal[
    "ConstantValue",
    "ConstantPointerValue",
    "StackFrameOffset",
    "SignedRangeValue",
    "UnsignedRangeValue",
    "InSetOfValues",
    "NotInSetOfValues",
]


class _ValueDescription(TypedDict):
    state: str
    rendered: str


class _UidfRow(TypedDict):
    index: int
    variable: str
    definition_site: NotRequired[str]
    value: NotRequired[_ValueDescription]
    ok: bool
    error: NotRequired[_ItemError]


class _UidfEntry(TypedDict):
    function: _FunctionEntry
    variable: str
    definition_site: str
    architecture: str
    state: str
    value: str


class _UidfSetResult(TypedDict):
    function: _ResolvedFunction
    variable: str
    definition_site: str
    value: _ValueDescription
    analysis_complete: bool
    lines: list[str]
    truncated: bool


class _UidfSetManyResult(TypedDict):
    function: _ResolvedFunction
    applied: int
    failed: int
    total: int
    results: list[_UidfRow]
    analysis_complete: bool
    lines: list[str]
    truncated: bool


class _UidfClearAllResult(TypedDict):
    function: _ResolvedFunction
    variable: None
    cleared: int


class _UidfClearVariableResult(TypedDict):
    function: _ResolvedFunction
    variable: str
    cleared: int
    definition_sites: int


class _UidfListResult(TypedDict):
    function: _ResolvedFunction | None
    total: int
    truncated: bool
    values: list[_UidfEntry]


def _describe_value(value: PossibleValueSet) -> _ValueDescription:
    return {"state": value.type.name, "rendered": _truncate(str(value))}


def _parse_uidf_value(
    bv: BinaryView, value: str, state: str, site: MediumLevelILInstruction
) -> PossibleValueSet:
    value_state = _require_value_state(state)
    try:
        return bv.parse_possiblevalueset(value, value_state, here=site.address)
    except Exception as error:
        raise mcp.ToolError("invalid_params", f"Invalid value parameter 'value': {error}") from None


@dataclass(frozen=True, slots=True)
class _UIDFSetPlan:
    index: int
    variable_name: str
    variable: Variable
    site: MediumLevelILInstruction
    value: PossibleValueSet
    description: _ValueDescription

    def applied_row(self) -> _UidfRow:
        return {
            "index": self.index,
            "variable": _truncate(self.variable_name),
            "definition_site": hex(self.site.address),
            "value": self.description,
            "ok": True,
        }

    def set_failed_row(self, error: Exception) -> _UidfRow:
        return {
            "index": self.index,
            "variable": _truncate(self.variable_name),
            "definition_site": hex(self.site.address),
            "value": self.description,
            "ok": False,
            "error": {
                "code": "set_failed",
                "message": f"could not inform '{_truncate(self.variable_name)}': {error}",
            },
        }


def _uidf_item_def_address(call: mcp.ToolCall, raw_site: object) -> int | None:
    """Parse an optional batch definition address, rejecting bool-as-int inputs."""
    if raw_site is None:
        return None
    if not isinstance(raw_site, (int, str)) or isinstance(raw_site, bool):
        raise mcp.ToolError("invalid_params", "def_address must be an integer or string")
    if isinstance(raw_site, int):
        # Raw ints pass through untouched: an int expression is already an address.
        return raw_site
    try:
        return call.parse_address(raw_site)
    except Exception as error:
        raise mcp.ToolError("invalid_params", f"bad definition address: {error}") from None


def _stage_uidf_item(
    call: mcp.ToolCall,
    bv: BinaryView,
    target: Function,
    index: int,
    item: object,
) -> _UIDFSetPlan | _UidfRow:
    """Validate and parse one batch item without mutating the function."""
    if not _is_json_object(item):
        return {
            "index": index,
            "variable": _truncate(repr(item)),
            "ok": False,
            "error": {"code": "invalid_params", "message": "each item must be a JSON object"},
        }
    label = str(item.get("variable", "<invalid item>"))
    try:
        allowed = {"variable", "value", "def_address", "state"}
        unknown = sorted(str(key) for key in item if key not in allowed)
        if unknown:
            raise mcp.ToolError("invalid_params", f"unknown field(s): {', '.join(unknown)}")
        variable_name = item.get("variable")
        value = item.get("value")
        if not isinstance(variable_name, str) or not variable_name:
            raise mcp.ToolError("invalid_params", "variable must be a non-empty string")
        if not isinstance(value, str) or not value:
            raise mcp.ToolError("invalid_params", "value must be a non-empty string")
        def_address = _uidf_item_def_address(call, item.get("def_address"))
        state = item.get("state", "ConstantValue")
        if not isinstance(state, str):
            raise mcp.ToolError("invalid_params", "state must be a string")
        site_variable, site = _select_definition_site(target, variable_name, def_address)
        parsed = _parse_uidf_value(bv, value, state, site)
        return _UIDFSetPlan(
            index, variable_name, site_variable, site, parsed, _describe_value(parsed)
        )
    except mcp.ToolError as error:
        return {
            "index": index,
            "variable": _truncate(label),
            "ok": False,
            "error": {"code": error.code, "message": error.message},
        }


def _apply_plan(target: Function, plan: _UIDFSetPlan) -> _UidfRow:
    try:
        target.set_user_var_value(plan.variable, plan.site.address, plan.value, after=True)
    except Exception as error:
        return plan.set_failed_row(error)
    return plan.applied_row()


def _wait_analysis_settled(bv: BinaryView) -> bool:
    """Wait, bounded, for the view's analysis queue to drain; False when the deadline passes."""
    deadline = time.monotonic() + _MAX_UIDF_ANALYSIS_WAIT_MS / 1000
    state = bv.analysis_progress.state
    while state != AnalysisState.IdleState and time.monotonic() < deadline:
        time.sleep(_UIDF_ANALYSIS_SLICE_MS / 1000)
        state = bv.analysis_progress.state
    return state == AnalysisState.IdleState


def _require_value_state(state: str) -> RegisterValueType:
    value_state = _VALUE_STATES.get(state)
    if value_state is None:
        raise mcp.ToolError(
            "invalid_params",
            f"Invalid state parameter 'state': must be one of {', '.join(_VALUE_STATES)}",
        )
    return value_state


def _collect_mlil_definitions(
    target: Function, name: str
) -> list[tuple[Variable, MediumLevelILInstruction]]:
    """Return every (variable, definition) pair whose variable name matches ``name``."""
    mlil = target.mlil
    if mlil is None:
        raise _missing_il_error(target, "MediumLevelIL", "no_mlil")
    matches = [
        (variable, definition)
        for variable in target.vars
        if variable.name == name
        for definition in mlil.get_var_definitions(variable)
    ]
    if not matches:
        if any(variable.name == name for variable in target.vars):
            raise mcp.ToolError(
                "no_variable",
                f"MLIL variable '{_truncate(name)}' in {_truncate(target.name)} has no "
                "MediumLevelIL definition sites; stack-passed arguments cannot be informed, "
                "inform the register that loads the value",
            )
        names = sorted({variable.name for variable in target.vars})
        shown = ", ".join(_truncate(candidate, 64) for candidate in names[:_MAX_NAME_CANDIDATES])
        more = (
            f" (+{len(names) - _MAX_NAME_CANDIDATES} more)"
            if len(names) > _MAX_NAME_CANDIDATES
            else ""
        )
        raise mcp.ToolError(
            "no_variable",
            f"no MLIL variable named '{_truncate(name)}' in {_truncate(target.name)}; "
            f"variables: {shown}{more}; use bn_variable_list for the full list. "
            "Register-allocated parameters are named by their register (for example r14), "
            "not by their argument name",
        )
    return matches


def _iter_uidf_entries(targets: list[Function]) -> Iterator[_UidfEntry]:
    return (
        {
            "function": _function_entry(target),
            "variable": _truncate(stored.name),
            "definition_site": hex(site.addr),
            "architecture": site.arch.name,
            "state": value.type.name,
            "value": _truncate(str(value)),
        }
        for target in targets
        for stored, sites in sorted(
            target.get_all_user_var_values().items(), key=lambda item: item[0].name
        )
        for site, value in sorted(sites.items(), key=lambda item: item[0].addr)
    )


def _select_definition_site(
    target: Function, name: str, def_address: int | None
) -> tuple[Variable, MediumLevelILInstruction]:
    """Resolve exactly one definition site for ``name``, rejecting ambiguity."""
    matches = _collect_mlil_definitions(target, name)
    if def_address is not None:
        known = sorted({site.address for _, site in matches})
        matches = [(variable, site) for variable, site in matches if site.address == def_address]
        if not matches:
            raise mcp.ToolError(
                "definition_not_found",
                f"variable '{_truncate(name)}' has no definition at {def_address:#x}; "
                f"definitions: {', '.join(f'{site:#x}' for site in known)}",
            )
    if len(matches) > 1:
        sites = sorted({site.address for _, site in matches})
        suffix = "; pass def_address to choose one" if def_address is None else ""
        raise mcp.ToolError(
            "ambiguous_definition",
            f"variable '{_truncate(name)}' matches {len(matches)} definitions at "
            f"{', '.join(f'{site:#x}' for site in sites)}{suffix}",
        )
    return matches[0]


@mcp.tool(destructive=True)
def rex_uidf_set(
    call: mcp.ToolCall,
    function: mcp.Address,
    variable: Annotated[str, mcp.NonEmpty()],
    value: Annotated[str, mcp.NonEmpty()],
    def_address: mcp.Address | None = None,
    state: ValueState = "ConstantValue",
    max_lines: Annotated[int, mcp.Minimum(1), mcp.Maximum(_MAX_DECOMPILE_LINES)] = 200,
) -> _UidfSetResult:
    """Inform an MLIL value; a key-table base pointer as ConstantPointerValue folds its byte checks.

    :param function: Address expression inside the target function.
    :param variable: MLIL variable name, as listed by bn_variable_list.
    :param value: Value spec: "0x10" constant (hex default), "start:end:step" range, "1,2,3" set.
    :param def_address: Definition site to inform when the variable has several.
    :param state: Grammar of the value spec; "$here" inside it resolves to the definition site.
    :param max_lines: HLIL lines rendered after the reanalysis settles.
    """
    bv = call.binary_view
    max_lines = _validate_range("max_lines", max_lines, 1, _MAX_DECOMPILE_LINES)
    resolution = _require_analyzed_function(bv, function)
    target = resolution.function
    site_variable, site = _select_definition_site(target, variable, def_address)
    parsed = _parse_uidf_value(bv, value, state, site)
    description = _describe_value(parsed)
    try:
        target.set_user_var_value(site_variable, site.address, parsed, after=True)
    except Exception as error:
        raise mcp.ToolError(
            "set_failed", f"could not inform '{_truncate(variable)}': {error}"
        ) from None
    bv.update_analysis()
    analysis_complete = _wait_analysis_settled(bv)
    lines, truncated = _render_hlil_lines(target.hlil, max_lines)
    return {
        "function": resolution.entry,
        "variable": _truncate(variable),
        "definition_site": hex(site.address),
        "value": description,
        "analysis_complete": analysis_complete,
        "lines": lines,
        "truncated": truncated,
    }


@mcp.tool(destructive=True)
def rex_uidf_set_many(
    call: mcp.ToolCall,
    function: mcp.Address,
    items: list[Annotated[object, mcp.Schema(_UIDF_ITEMS_SCHEMA)]],
    max_lines: Annotated[int, mcp.Minimum(1), mcp.Maximum(_MAX_DECOMPILE_LINES)] = 200,
) -> _UidfSetManyResult:
    """Inform several MLIL values in one reanalysis: a byte-check family's operands all at once.

    :param function: Address expression inside the target function.
    :param items: 1 to 128 objects with variable, value, optional def_address and state.
    :param max_lines: HLIL lines rendered after the batch settles.
    """
    bv = call.binary_view
    max_lines = _validate_range("max_lines", max_lines, 1, _MAX_DECOMPILE_LINES)
    resolution = _require_analyzed_function(bv, function)
    target = resolution.function
    if not isinstance(items, list):
        raise mcp.ToolError("invalid_params", "items must be a list of uidf item objects")
    if not 1 <= len(items) <= _MAX_UIDF_BATCH:
        raise mcp.ToolError(
            "invalid_params", f"items must contain between 1 and {_MAX_UIDF_BATCH} entries"
        )
    staged = [_stage_uidf_item(call, bv, target, index, item) for index, item in enumerate(items)]
    results = [
        _apply_plan(target, outcome) if isinstance(outcome, _UIDFSetPlan) else outcome
        for outcome in staged
    ]
    applied = sum(1 for row in results if row["ok"])
    analysis_complete = True
    if applied:
        bv.update_analysis()
        analysis_complete = _wait_analysis_settled(bv)
    lines, truncated = _render_hlil_lines(target.hlil, max_lines)
    failed = len(results) - applied
    return {
        "function": resolution.entry,
        "applied": applied,
        "failed": failed,
        "total": len(results),
        "results": results,
        "analysis_complete": analysis_complete,
        "lines": lines,
        "truncated": truncated,
    }


@mcp.tool(destructive=True)
def rex_uidf_clear(
    call: mcp.ToolCall,
    function: mcp.Address,
    variable: Annotated[str, mcp.NonEmpty()] | None = None,
) -> _UidfClearAllResult | _UidfClearVariableResult:
    """Clear user variable values: one MLIL variable's sites, or all of a function's.

    :param function: Address expression inside the target function.
    :param variable: Variable whose user values clear at every definition site; omit for all.
    """
    bv = call.binary_view
    resolution = _require_analyzed_function(bv, function)
    target = resolution.function
    if variable is None:
        cleared = sum(len(sites) for sites in target.get_all_user_var_values().values())
        try:
            target.clear_all_user_var_values()
        except Exception as error:
            raise mcp.ToolError(
                "clear_failed", f"could not clear user variable values: {error}"
            ) from None
        bv.update_analysis()
        return {"function": resolution.entry, "variable": None, "cleared": cleared}
    matches = _collect_mlil_definitions(target, variable)
    informed_sites = {
        site.addr
        for stored, sites in target.get_all_user_var_values().items()
        if stored.name == variable
        for site in sites
    }
    cleared = 0
    for site_variable, definition in matches:
        try:
            target.clear_user_var_value(site_variable, definition.address, after=True)
        except Exception as error:
            raise mcp.ToolError(
                "clear_failed",
                f"could not clear '{_truncate(variable)}' at {definition.address:#x}: {error}",
            ) from None
        if definition.address in informed_sites:
            cleared += 1
    bv.update_analysis()
    return {
        "function": resolution.entry,
        "variable": _truncate(variable),
        "cleared": cleared,
        "definition_sites": len(matches),
    }


@mcp.tool(read_only=True)
def rex_uidf_list(
    call: mcp.ToolCall,
    function: mcp.Address | None = None,
    limit: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_LIMIT)] = 100,
    offset: Annotated[int, mcp.Minimum(0)] = 0,
) -> _UidfListResult:
    """List informed user variable values for one function or the whole view.

    :param function: Address expression inside the function to list; omit for every function.
    :param limit: Maximum informed values to return.
    :param offset: Informed values to skip before collecting results.
    """
    bv = call.binary_view
    limit = _validate_range("limit", limit, 0, _MAX_LIMIT)
    offset = _validate_range("offset", offset, 0)
    resolution = _require_analyzed_function(bv, function) if function is not None else None
    targets = (
        [resolution.function]
        if resolution is not None
        else sorted(bv.functions, key=lambda entry: entry.start)
    )
    page, total, truncated = _paginate(_iter_uidf_entries(targets), offset, limit)
    return {
        "function": resolution.entry if resolution is not None else None,
        "total": total,
        "truncated": truncated,
        "values": page,
    }
