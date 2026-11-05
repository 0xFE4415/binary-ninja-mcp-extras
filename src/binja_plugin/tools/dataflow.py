"""Dataflow tools: branch constraints, addressed HLIL statements, and uses of a definition.

Each tool answers a question the text renderings cannot: which input bytes a function
compares against which constants, which IL statement lives at an address, and where a
defined variable is read. Operations are matched by name, so a tool reports only what
the IL states and never a rendering of it.
"""

from __future__ import annotations

from typing import Annotated, Any

from binaryninja import mcp

from binja_plugin.tools import (
    _MAX_LIMIT,
    _MAX_NAME_CANDIDATES,
    _function_entry,
    _require_analyzed_function,
    _truncate,
    _validate_range,
)

_MAX_STATEMENT_LIMIT = 1000
_MAX_DEFINITION_SITES = 10
_COMPARISON_OPERATORS = {"MLIL_CMP_E": "==", "MLIL_CMP_NE": "!="}
_EXTENSIONS = ("MLIL_SX", "MLIL_ZX")
_CONSTANTS = ("MLIL_CONST", "MLIL_CONST_PTR")
_DEFINITIONS = ("MLIL_SET_VAR", "MLIL_SET_VAR_SSA")
_WRITES = _DEFINITIONS + (
    "MLIL_SET_VAR_FIELD",
    "MLIL_SET_VAR_SSA_FIELD",
    "MLIL_SET_VAR_ALIASED",
    "MLIL_SET_VAR_ALIASED_FIELD",
    "MLIL_SET_VAR_SPLIT",
    "MLIL_SET_VAR_SPLIT_SSA",
)


def _operation(instruction: Any) -> str:
    name = getattr(instruction.operation, "name", None)
    return name if isinstance(name, str) else str(instruction.operation)


def _strip_extension(expression: Any) -> Any:
    while _operation(expression) in _EXTENSIONS:
        expression = expression.src
    return expression


def _constant(expression: Any) -> int | None:
    expression = _strip_extension(expression)
    if _operation(expression) in _CONSTANTS:
        return int(expression.constant)
    return None


def _describe_load(expression: Any) -> dict[str, object] | None:
    """Describe a memory load as its base variable plus a constant offset, or None."""
    expression = _strip_extension(expression)
    if _operation(expression) != "MLIL_LOAD":
        return None
    address = _strip_extension(expression.src)
    constant = _constant(address)
    if constant is not None:
        return {"kind": "load", "base": None, "offset": hex(constant)}
    base, offset = address, 0
    if _operation(address) == "MLIL_ADD":
        base, offset = _strip_extension(address.left), _constant(address.right)
    if _operation(base) == "MLIL_VAR" and offset is not None:
        return {"kind": "load", "base": _truncate(base.src.name), "offset": hex(offset)}
    return {"kind": "load", "base": None, "offset": None, "text": _truncate(str(address))}


def _definition_load(target_mlil: Any, variable: Any) -> dict[str, object] | None:
    """The load behind a variable when its only definition is a memory load, else None."""
    definitions = target_mlil.get_var_definitions(variable)
    if len(definitions) != 1 or _operation(definitions[0]) not in _DEFINITIONS:
        return None
    load = _describe_load(definitions[0].src)
    if load is None:
        return None
    return {"address": hex(definitions[0].address), "load": load}


def _describe_subject(target_mlil: Any, expression: Any) -> dict[str, object]:
    """Describe the non-constant side of a comparison as structured data."""
    expression = _strip_extension(expression)
    load = _describe_load(expression)
    if load is not None:
        return load
    if _operation(expression) == "MLIL_VAR":
        described: dict[str, object] = {
            "kind": "variable",
            "variable": _truncate(expression.src.name),
        }
        definition = _definition_load(target_mlil, expression.src)
        if definition is not None:
            described["definition"] = definition
        return described
    return {"kind": "expression", "text": _truncate(str(expression))}


def _iter_branch_constraints(target_mlil: Any) -> list[dict[str, object]]:
    """Every conditional that compares an expression against a constant, in address order."""
    rows: list[dict[str, object]] = []
    for instruction in target_mlil.instructions:
        if _operation(instruction) != "MLIL_IF":
            continue
        condition = instruction.condition
        operator = _COMPARISON_OPERATORS.get(_operation(condition))
        if operator is None:
            continue
        left, right = _constant(condition.left), _constant(condition.right)
        if left is not None and right is None:
            constant, subject = left, condition.right
        elif right is not None and left is None:
            constant, subject = right, condition.left
        else:
            # Both sides constant folds away, and neither constant is a comparison.
            continue
        rows.append(
            {
                "address": hex(instruction.address),
                "operator": operator,
                "constant": hex(constant),
                "char": chr(constant) if 0x20 <= constant < 0x7F else None,
                "subject": _describe_subject(target_mlil, subject),
                "subject_text": _truncate(str(subject)),
            }
        )
    rows.sort(key=lambda row: int(str(row["address"]), 16))
    return rows


@mcp.tool(read_only=True)
def rex_function_constraints(
    call: mcp.ToolCall,
    function: mcp.Address,
    limit: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_LIMIT)] = 100,
    offset: Annotated[int, mcp.Minimum(0)] = 0,
) -> dict[str, object]:
    """List constant branch comparisons; inform their variable with rex_uidf_set to fold them.

    :param function: Address expression inside the target function.
    :param limit: Maximum constraints to return.
    :param offset: Constraints to skip before collecting results.
    """
    bv = call.binary_view
    limit = _validate_range("limit", limit, 0, _MAX_LIMIT)
    offset = _validate_range("offset", offset, 0)
    target = _require_analyzed_function(bv, function)
    target_mlil = target.mlil
    if target_mlil is None:
        raise mcp.ToolError(
            "no_mlil",
            f"function {_truncate(target.name)} has no MediumLevelIL yet; "
            "run bn_analysis_update_and_wait (or rex_analysis_wait with a bound) and retry",
        )
    rows = _iter_branch_constraints(target_mlil)
    return {
        "function": _function_entry(target),
        "total": len(rows),
        "truncated": offset + limit < len(rows),
        "constraints": rows[offset : offset + limit],
    }


@mcp.tool(read_only=True)
def rex_hlil_statements(
    call: mcp.ToolCall,
    function: mcp.Address,
    limit: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_STATEMENT_LIMIT)] = 200,
    offset: Annotated[int, mcp.Minimum(0)] = 0,
) -> dict[str, object]:
    """List HLIL statements in block order, each tagged with its source address.

    :param function: Address expression inside the target function.
    :param limit: Maximum statements to return.
    :param offset: Statements to skip before collecting results.
    """
    bv = call.binary_view
    limit = _validate_range("limit", limit, 0, _MAX_STATEMENT_LIMIT)
    offset = _validate_range("offset", offset, 0)
    target = _require_analyzed_function(bv, function)
    hlil = target.hlil
    if hlil is None:
        raise mcp.ToolError(
            "no_hlil",
            f"function {_truncate(target.name)} has no HLIL yet; "
            "run bn_analysis_update_and_wait (or rex_analysis_wait with a bound) and retry",
        )
    rows = [
        {
            "address": hex(instruction.address),
            "index": instruction.instr_index,
            "text": _truncate(str(instruction)),
        }
        for block in hlil.basic_blocks
        for instruction in block
    ]
    return {
        "function": _function_entry(target),
        "total": len(rows),
        "truncated": offset + limit < len(rows),
        "statements": rows[offset : offset + limit],
    }


@mcp.tool(read_only=True)
def rex_mlil_uses(
    call: mcp.ToolCall,
    function: mcp.Address,
    address: mcp.Address,
    limit: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_LIMIT)] = 100,
    offset: Annotated[int, mcp.Minimum(0)] = 0,
) -> dict[str, object]:
    """List every read of the MLIL variable assigned at an address, plus its definitions.

    :param function: Address expression inside the target function.
    :param address: Address of the MLIL instruction that assigns the variable.
    :param limit: Maximum use sites to return.
    :param offset: Use sites to skip before collecting results.
    """
    bv = call.binary_view
    limit = _validate_range("limit", limit, 0, _MAX_LIMIT)
    offset = _validate_range("offset", offset, 0)
    target = _require_analyzed_function(bv, function)
    target_mlil = target.mlil
    if target_mlil is None:
        raise mcp.ToolError(
            "no_mlil",
            f"function {_truncate(target.name)} has no MediumLevelIL yet; "
            "run bn_analysis_update_and_wait (or rex_analysis_wait with a bound) and retry",
        )
    defining = [
        instruction
        for instruction in target_mlil.instructions
        if instruction.address == address and _operation(instruction) in _WRITES
    ]
    if not defining:
        sites = sorted(
            {
                instruction.address
                for instruction in target_mlil.instructions
                if _operation(instruction) in _WRITES
            }
        )
        shown = ", ".join(hex(site) for site in sites[:_MAX_DEFINITION_SITES])
        more = (
            f" (+{len(sites) - _MAX_DEFINITION_SITES} more)"
            if len(sites) > _MAX_DEFINITION_SITES
            else ""
        )
        raise mcp.ToolError(
            "no_definition",
            f"no MLIL variable definition at {address:#x} in {_truncate(target.name)}; "
            f"variables are defined at: {shown}{more}; "
            "use rex_hlil_statements or bn_function_il to match an address to its variable",
        )
    # A split write defines a high:low pair at one site and has no dest; report the high half.
    variable = getattr(defining[0], "dest", None)
    if variable is None:
        variable = defining[0].high
    uses = sorted(target_mlil.get_var_uses(variable), key=lambda use: use.address)
    rows = [
        {
            "address": hex(use.address),
            "operation": _operation(use),
            "text": _truncate(str(use)),
        }
        for use in uses
    ]
    return {
        "function": _function_entry(target),
        "variable": _truncate(variable.name),
        "definition_site": hex(address),
        "definitions": [
            hex(definition.address) for definition in target_mlil.get_var_definitions(variable)
        ],
        "total": len(rows),
        "truncated": offset + limit < len(rows),
        "uses": rows[offset : offset + limit],
    }


def _storage_description(variable: Any) -> dict[str, object]:
    source = getattr(variable, "source_type", None)
    return {
        "source": getattr(source, "name", None) or str(source),
        "storage": getattr(variable, "storage", None),
    }


def _parameter_carriers(target_mlil: Any, parameter: str) -> list[dict[str, object]]:
    """Definitions whose value is a plain copy of a variable named ``parameter``."""
    carriers: list[dict[str, object]] = []
    for instruction in target_mlil.instructions:
        if _operation(instruction) not in _DEFINITIONS:
            continue
        source = _strip_extension(instruction.src)
        if _operation(source) != "MLIL_VAR" or source.src.name != parameter:
            continue
        carriers.append(
            {
                "variable": _truncate(instruction.dest.name),
                "address": hex(instruction.address),
                "text": _truncate(str(instruction)),
            }
        )
    carriers.sort(key=lambda row: int(str(row["address"]), 16))
    return carriers


@mcp.tool(read_only=True)
def rex_parameter_variables(
    call: mcp.ToolCall,
    function: mcp.Address,
    parameter: Annotated[str, mcp.NonEmpty()],
) -> dict[str, object]:
    """Map a parameter to its storage, the MLIL variables for it, and the copies carrying it.

    :param function: Address expression inside the target function.
    :param parameter: Argument name as bn_variable_list reports it, such as arg2.
    """
    bv = call.binary_view
    target = _require_analyzed_function(bv, function)
    target_mlil = target.mlil
    if target_mlil is None:
        raise mcp.ToolError(
            "no_mlil",
            f"function {_truncate(target.name)} has no MediumLevelIL yet; "
            "run bn_analysis_update_and_wait (or rex_analysis_wait with a bound) and retry",
        )
    matches = [variable for variable in target.vars if variable.name == parameter]
    if not matches:
        names = sorted({variable.name for variable in target.vars})
        shown = ", ".join(_truncate(name, 64) for name in names[:_MAX_NAME_CANDIDATES])
        more = (
            f" (+{len(names) - _MAX_NAME_CANDIDATES} more)"
            if len(names) > _MAX_NAME_CANDIDATES
            else ""
        )
        raise mcp.ToolError(
            "no_variable",
            f"no MLIL variable named '{_truncate(parameter)}' in {_truncate(target.name)}; "
            f"variables: {shown}{more}; use bn_variable_list for the full list. "
            "Register-allocated parameters are named by their register (for example r14), "
            "not by their argument name",
        )
    return {
        "function": _function_entry(target),
        "parameter": _truncate(parameter),
        "storage": [_storage_description(variable) for variable in matches],
        "definitions": [
            hex(definition.address)
            for variable in matches
            for definition in target_mlil.get_var_definitions(variable)
        ],
        "carriers": _parameter_carriers(target_mlil, parameter),
    }
