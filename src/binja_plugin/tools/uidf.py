"""User-informed data flow tools: inform variable values, clear them, and list them.

The definition site is the address of the MLIL instruction that defines the variable, the
same (arch, address) pair the core stores per informed value; resolving it from the
variable's name is what keeps rex_uidf_set and rex_uidf_clear inside the core's contract
that a user value always attaches to a real definition site.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from typing import Annotated, Literal

from binaryninja import mcp
from binaryninja.binaryview import BinaryView
from binaryninja.enums import AnalysisState, RegisterValueType
from binaryninja.function import Function
from binaryninja.mediumlevelil import MediumLevelILInstruction
from binaryninja.variable import Variable

from binja_plugin.tools import (
    _MAX_DECOMPILE_LINES,
    _MAX_LIMIT,
    _function_entry,
    _paginate,
    _render_hlil_lines,
    _require_analyzed_function,
    _truncate,
    _validate_range,
)

# rex_uidf_set settles the reanalysis an informed value schedules before rendering HLIL,
# polling like rex_analysis_wait; the deadline bounds one call's hold on the server thread.
_UIDF_ANALYSIS_SLICE_MS = 100
_MAX_UIDF_ANALYSIS_WAIT_MS = 10000

# The states BinaryView.parse_possiblevalueset documents a string grammar for; the schema
# advertises exactly these, so a state with no documented syntax is never offered.
_VALUE_STATES: dict[str, RegisterValueType] = {
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
        raise mcp.ToolError(
            "no_mlil", f"function {_truncate(target.name)} has no MediumLevelIL yet"
        )
    matches = [
        (variable, definition)
        for variable in target.vars
        if variable.name == name
        for definition in mlil.get_var_definitions(variable)
    ]
    if not matches:
        raise mcp.ToolError(
            "no_variable",
            f"no MLIL variable named '{_truncate(name)}' in {_truncate(target.name)}; "
            "variable names come from bn_variable_list",
        )
    return matches


def _iter_uidf_entries(targets: list[Function]) -> Iterator[dict[str, object]]:
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
) -> dict[str, object]:
    """Inform a value for an MLIL variable at one definition site; returns the settled HLIL.

    :param function: Address expression inside the target function.
    :param variable: MLIL variable name, as listed by bn_variable_list.
    :param value: Value spec: "0x10" constant (hex default), "start:end:step" range, "1,2,3" set.
    :param def_address: Definition site to inform when the variable has several.
    :param state: Grammar of the value spec; "$here" inside it resolves to the definition site.
    :param max_lines: HLIL lines rendered after the reanalysis settles.
    """
    bv = call.binary_view
    max_lines = _validate_range("max_lines", max_lines, 1, _MAX_DECOMPILE_LINES)
    target = _require_analyzed_function(bv, function)
    site_variable, site = _select_definition_site(target, variable, def_address)
    value_state = _require_value_state(state)
    try:
        parsed = bv.parse_possiblevalueset(value, value_state, here=site.address)
    except Exception as error:
        raise mcp.ToolError("invalid_params", f"Invalid value parameter 'value': {error}") from None
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
        "function": _function_entry(target),
        "variable": _truncate(variable),
        "definition_site": hex(site.address),
        "value": {"state": parsed.type.name, "rendered": _truncate(str(parsed))},
        "analysis_complete": analysis_complete,
        "lines": lines,
        "truncated": truncated,
    }


@mcp.tool(destructive=True)
def rex_uidf_clear(
    call: mcp.ToolCall,
    function: mcp.Address,
    variable: Annotated[str, mcp.NonEmpty()] | None = None,
) -> dict[str, object]:
    """Clear user variable values: one MLIL variable's sites, or all of a function's.

    :param function: Address expression inside the target function.
    :param variable: Variable whose user values clear at every definition site; omit for all.
    """
    bv = call.binary_view
    target = _require_analyzed_function(bv, function)
    if variable is None:
        cleared = sum(len(sites) for sites in target.get_all_user_var_values().values())
        try:
            target.clear_all_user_var_values()
        except Exception as error:
            raise mcp.ToolError(
                "clear_failed", f"could not clear user variable values: {error}"
            ) from None
        bv.update_analysis()
        return {"function": _function_entry(target), "variable": None, "cleared": cleared}
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
        "function": _function_entry(target),
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
) -> dict[str, object]:
    """List informed user variable values for one function or the whole view.

    :param function: Address expression inside the function to list; omit for every function.
    :param limit: Maximum informed values to return.
    :param offset: Informed values to skip before collecting results.
    """
    bv = call.binary_view
    limit = _validate_range("limit", limit, 0, _MAX_LIMIT)
    offset = _validate_range("offset", offset, 0)
    targets = (
        [_require_analyzed_function(bv, function)]
        if function is not None
        else sorted(bv.functions, key=lambda entry: entry.start)
    )
    page, total, truncated = _paginate(_iter_uidf_entries(targets), offset, limit)
    return {"total": total, "truncated": truncated, "values": page}
