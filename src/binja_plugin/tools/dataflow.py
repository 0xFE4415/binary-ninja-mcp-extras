"""Dataflow tools: branch constraints, addressed HLIL statements, and uses of a definition.

Each tool answers a question the text renderings cannot: which input bytes a function
compares against which constants, which IL statement lives at an address, and where a
defined variable is read. Operations are matched by name, so a tool reports only what
the IL states and never a rendering of it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any, Final, TypedDict

from binaryninja import mcp

from binja_plugin.tools import (
    _MAX_LIMIT,
    _MAX_NAME_CANDIDATES,
    _function_entry,
    _require_analyzed_function,
    _truncate,
    _validate_range,
)

if TYPE_CHECKING:
    from binaryninja.mediumlevelil import MediumLevelILFunction, MediumLevelILInstruction
    from binaryninja.variable import Variable

_MAX_STATEMENT_LIMIT: Final = 1000
_MAX_DEFINITION_SITES: Final = 10
_COMPARISON_OPERATORS: Final = {"MLIL_CMP_E": "==", "MLIL_CMP_NE": "!="}
_EXTENSIONS: Final = ("MLIL_SX", "MLIL_ZX")
_CONSTANTS: Final = ("MLIL_CONST", "MLIL_CONST_PTR")
_DEFINITIONS: Final = ("MLIL_SET_VAR", "MLIL_SET_VAR_SSA")


class _VariableUse(TypedDict):
    address: str
    operation: str
    text: str


class _ParameterCarrier(TypedDict):
    variable: str
    address: str
    text: str


def _operation(instruction: Any) -> str:
    name = getattr(instruction.operation, "name", None)
    return name if isinstance(name, str) else str(instruction.operation)


def _definitions_by_instruction(
    target_mlil: MediumLevelILFunction,
) -> dict[int, list[Variable]]:
    """Every variable the core records a definition for, keyed by defining instruction index."""
    defined: dict[int, list[Variable]] = {}
    for variable in target_mlil.vars:
        for definition in target_mlil.get_var_definitions(variable):
            defined.setdefault(definition.instr_index, []).append(variable)
    return defined


def _defined_variables(
    instruction: MediumLevelILInstruction, defined: dict[int, list[Variable]]
) -> list[Variable]:
    """The variables the core defines at an instruction, in operand order where it states one."""
    recorded = defined.get(instruction.instr_index, [])
    written = list(instruction.vars_written)
    return [variable for variable in written if variable in recorded] + [
        variable for variable in recorded if variable not in written
    ]


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


def _definition_load(
    target_mlil: MediumLevelILFunction, variable: Variable
) -> dict[str, object] | None:
    """The load behind a variable when its only definition is a memory load, else None."""
    definitions: list[Any] = target_mlil.get_var_definitions(variable)
    if len(definitions) != 1 or _operation(definitions[0]) not in _DEFINITIONS:
        return None
    load = _describe_load(definitions[0].src)
    if load is None:
        return None
    return {"address": hex(definitions[0].address), "load": load}


def _describe_subject(target_mlil: MediumLevelILFunction, expression: Any) -> dict[str, object]:
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


def _iter_branch_constraints(target_mlil: MediumLevelILFunction) -> list[dict[str, object]]:
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


def _variable_report(
    target_mlil: MediumLevelILFunction, variable: Variable, limit: int, offset: int
) -> dict[str, object]:
    uses = sorted(target_mlil.get_var_uses(variable), key=lambda use: use.address)
    rows = [
        _VariableUse(address=hex(use.address), operation=_operation(use), text=_truncate(str(use)))
        for use in uses
    ]
    return {
        "variable": _truncate(variable.name),
        "definitions": [
            hex(definition.address) for definition in target_mlil.get_var_definitions(variable)
        ],
        "total": len(rows),
        "truncated": offset + limit < len(rows),
        "uses": rows[offset : offset + limit],
    }


@mcp.tool(read_only=True)
def rex_mlil_uses(
    call: mcp.ToolCall,
    function: mcp.Address,
    address: mcp.Address,
    variable: Annotated[str, mcp.NonEmpty()] | None = None,
    limit: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_LIMIT)] = 100,
    offset: Annotated[int, mcp.Minimum(0)] = 0,
) -> dict[str, object]:
    """List every read of each MLIL variable the core defines at an address, with its definitions.

    :param function: Address expression inside the target function.
    :param address: Address of an MLIL instruction that defines variables.
    :param variable: Report only the defined variable with this name.
    :param limit: Maximum use sites to return per variable.
    :param offset: Use sites to skip per variable before collecting results.
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
    definitions = _definitions_by_instruction(target_mlil)
    defined_at: dict[int, list[Variable]] = {}
    for instruction in target_mlil.instructions:
        variables = _defined_variables(instruction, definitions)
        if variables:
            defined_at.setdefault(instruction.address, []).extend(variables)
    if address not in defined_at:
        shown = ", ".join(hex(site) for site in sorted(defined_at)[:_MAX_DEFINITION_SITES])
        more = (
            f" (+{len(defined_at) - _MAX_DEFINITION_SITES} more)"
            if len(defined_at) > _MAX_DEFINITION_SITES
            else ""
        )
        raise mcp.ToolError(
            "no_definition",
            f"no MLIL variable definition at {address:#x} in {_truncate(target.name)}; "
            f"variables are defined at: {shown}{more}; "
            "use rex_hlil_statements or bn_function_il to match an address to its variable",
        )
    at_address = list(dict.fromkeys(defined_at[address]))
    selected = [defined for defined in at_address if variable in (None, defined.name)]
    if not selected:
        names = ", ".join(_truncate(defined.name, 64) for defined in at_address)
        raise mcp.ToolError(
            "no_variable",
            f"no variable named '{_truncate(str(variable))}' is defined at {address:#x} "
            f"in {_truncate(target.name)}; defined there: {names}",
        )
    return {
        "function": _function_entry(target),
        "definition_site": hex(address),
        "variables": [
            _variable_report(target_mlil, defined, limit, offset) for defined in selected
        ],
    }


def _storage_description(variable: Variable) -> dict[str, object]:
    source = getattr(variable, "source_type", None)
    return {
        "source": getattr(source, "name", None) or str(source),
        "storage": getattr(variable, "storage", None),
    }


def _is_copy_of_parameter(instruction: Any, parameter: str) -> bool:
    if _operation(instruction) not in _DEFINITIONS:
        return False
    source = _strip_extension(instruction.src)
    if _operation(source) != "MLIL_VAR":
        return False
    return bool(source.src.name == parameter)


def _parameter_carriers(
    target_mlil: MediumLevelILFunction, parameter: str
) -> list[_ParameterCarrier]:
    """Definitions whose value is a plain copy of a variable named ``parameter``."""
    copies = [
        instruction
        for instruction in target_mlil.instructions
        if _is_copy_of_parameter(instruction, parameter)
    ]
    return [
        _ParameterCarrier(
            variable=_truncate(instruction.dest.name),
            address=hex(instruction.address),
            text=_truncate(str(instruction)),
        )
        for instruction in sorted(copies, key=lambda instruction: instruction.address)
    ]


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
