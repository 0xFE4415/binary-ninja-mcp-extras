"""Dataflow tools: branch constraints, addressed HLIL statements, and uses of a definition.

Each tool answers a question the text renderings cannot: which input bytes a function
compares against which constants, which IL statement lives at an address, and where a
defined variable is read. Operations and values come from the core, so a tool reports
only what the IL states and never a rendering of it.
"""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING, Annotated, Any, Literal, TypedDict

from binaryninja import mcp
from binaryninja.enums import MediumLevelILOperation, RegisterValueType, VariableSourceType

from binja_plugin.tools import (
    _MAX_LIMIT,
    _missing_il_error,
    _require_analyzed_function,
    _show_nul,
    _truncate,
    _unknown_variable_error,
)

if TYPE_CHECKING:
    from binaryninja.architecture import Architecture
    from binaryninja.mediumlevelil import (
        MediumLevelILFunction,
        MediumLevelILInstruction,
        SSAVariable,
    )
    from binaryninja.variable import Variable

_MAX_STATEMENT_LIMIT = 1000
_MAX_DEFINITION_SITES = 10
_EQUALITY_OPERATORS = {
    MediumLevelILOperation.MLIL_CMP_E: "==",
    MediumLevelILOperation.MLIL_CMP_NE: "!=",
    MediumLevelILOperation.MLIL_FCMP_E: "f==",
    MediumLevelILOperation.MLIL_FCMP_NE: "f!=",
}
# Each ordered comparison as (operator, operator with the operands swapped).
_ORDERED_OPERATORS = {
    MediumLevelILOperation.MLIL_CMP_SLT: ("s<", "s>"),
    MediumLevelILOperation.MLIL_CMP_ULT: ("u<", "u>"),
    MediumLevelILOperation.MLIL_CMP_SLE: ("s<=", "s>="),
    MediumLevelILOperation.MLIL_CMP_ULE: ("u<=", "u>="),
    MediumLevelILOperation.MLIL_CMP_SGE: ("s>=", "s<="),
    MediumLevelILOperation.MLIL_CMP_UGE: ("u>=", "u<="),
    MediumLevelILOperation.MLIL_CMP_SGT: ("s>", "s<"),
    MediumLevelILOperation.MLIL_CMP_UGT: ("u>", "u<"),
    MediumLevelILOperation.MLIL_FCMP_LT: ("f<", "f>"),
    MediumLevelILOperation.MLIL_FCMP_LE: ("f<=", "f>="),
    MediumLevelILOperation.MLIL_FCMP_GE: ("f>=", "f<="),
    MediumLevelILOperation.MLIL_FCMP_GT: ("f>", "f<"),
}
_SIGNED_OPERATORS = frozenset(
    {
        MediumLevelILOperation.MLIL_CMP_SLT,
        MediumLevelILOperation.MLIL_CMP_SLE,
        MediumLevelILOperation.MLIL_CMP_SGE,
        MediumLevelILOperation.MLIL_CMP_SGT,
    }
)
_FLOAT_OPERATORS = frozenset(
    {
        MediumLevelILOperation.MLIL_FCMP_E,
        MediumLevelILOperation.MLIL_FCMP_NE,
        MediumLevelILOperation.MLIL_FCMP_LT,
        MediumLevelILOperation.MLIL_FCMP_LE,
        MediumLevelILOperation.MLIL_FCMP_GE,
        MediumLevelILOperation.MLIL_FCMP_GT,
    }
)
_FLOAT_FORMATS = {4: "<f", 8: "<d"}
_OPERATOR_SETS = ("equality", "all")
_EXTENSIONS = frozenset({MediumLevelILOperation.MLIL_SX, MediumLevelILOperation.MLIL_ZX})
_NARROWINGS = _EXTENSIONS | {MediumLevelILOperation.MLIL_LOW_PART}
_LOADS = frozenset({MediumLevelILOperation.MLIL_LOAD, MediumLevelILOperation.MLIL_LOAD_STRUCT})
_CONSTANT_STATES = frozenset(
    {RegisterValueType.ConstantValue, RegisterValueType.ConstantPointerValue}
)
_TEMP_FLAG_BIT = 0x80000000
_TEMP_FLAG_INDEX_MASK = 0x7FFFFFFF


class _VariableUse(TypedDict):
    address: str
    operation: str
    text: str


class _RegisterStorage(TypedDict):
    source: Literal["register"]
    register: str


class _StackStorage(TypedDict):
    source: Literal["stack"]
    stack_offset: int


class _FlagStorage(TypedDict):
    source: Literal["flag"]
    flag: str


class _CompositeStorage(TypedDict):
    source: Literal["composite_return_value", "composite_parameter"]
    storage: int


_VariableStorage = _RegisterStorage | _StackStorage | _FlagStorage | _CompositeStorage


class _VariableReport(TypedDict):
    variable: str
    storage: _VariableStorage
    type: str
    definitions: list[str]
    total: int
    truncated: bool
    uses: list[_VariableUse]


class _ParameterCarrier(TypedDict):
    variable: str
    address: str
    text: str


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


def _strip(expression: Any, operations: frozenset[MediumLevelILOperation]) -> Any:
    while expression.operation in operations:
        expression = expression.src
    return expression


def _unsigned_at(value: int, size: int) -> int:
    if size == 0:
        return value
    return value & ((1 << (8 * size)) - 1)


def _constant(expression: Any) -> tuple[int, int] | None:
    """The constant the core states for an expression as (value at its width, size), or None."""
    value = expression.value
    if value.type not in _CONSTANT_STATES:
        return None
    size = int(expression.size)
    return _unsigned_at(int(value.value), size), size


def _as_signed(value: int, size: int) -> int:
    if size == 0:
        return value
    return int.from_bytes(value.to_bytes(size, "little"), "little", signed=True)


def _float_text(value: int, size: int) -> str | None:
    layout = _FLOAT_FORMATS.get(size)
    if layout is None:
        return None
    return repr(struct.unpack(layout, value.to_bytes(size, "little"))[0])


def _describe_load(expression: Any) -> dict[str, object] | None:
    """Describe a memory load as its base variable plus a constant offset, or None."""
    expression = _strip(expression, _NARROWINGS)
    operation = expression.operation
    if operation not in _LOADS:
        return None
    field = expression.offset if operation == MediumLevelILOperation.MLIL_LOAD_STRUCT else 0
    absolute = _constant(expression.src)
    if absolute is not None:
        address, size = absolute
        return {"kind": "load", "base": None, "offset": hex(_unsigned_at(address + field, size))}
    address = _strip(expression.src, _EXTENSIONS)
    base, displacement = address, 0
    if address.operation == MediumLevelILOperation.MLIL_ADD:
        base = _strip(address.left, _EXTENSIONS)
        stated = _constant(address.right)
        displacement = None if stated is None else _as_signed(*stated)
    if base.operation == MediumLevelILOperation.MLIL_VAR and displacement is not None:
        return {
            "kind": "load",
            "base": _truncate(base.src.name),
            "offset": hex(displacement + field),
        }
    return {"kind": "load", "base": None, "offset": None, "text": _truncate(str(address))}


def _definition_load(
    target_mlil: MediumLevelILFunction, variable: Variable
) -> dict[str, object] | None:
    """The load behind a variable when its only definition is a memory load, else None."""
    definitions: list[Any] = target_mlil.get_var_definitions(variable)
    if len(definitions) != 1 or definitions[0].operation != MediumLevelILOperation.MLIL_SET_VAR:
        return None
    load = _describe_load(definitions[0].src)
    if load is None:
        return None
    return {"address": hex(definitions[0].address), "load": load}


def _describe_subject(target_mlil: MediumLevelILFunction, expression: Any) -> dict[str, object]:
    """Describe the non-constant side of a comparison as structured data."""
    expression = _strip(expression, _NARROWINGS)
    load = _describe_load(expression)
    if load is not None:
        return load
    if expression.operation == MediumLevelILOperation.MLIL_VAR:
        described: dict[str, object] = {
            "kind": "variable",
            "variable": _truncate(expression.src.name),
        }
        definition = _definition_load(target_mlil, expression.src)
        if definition is not None:
            described["definition"] = definition
        return described
    if expression.operation == MediumLevelILOperation.MLIL_IMPORT:
        return {
            "kind": "import",
            "address": hex(expression.constant),
            "text": _truncate(str(expression)),
        }
    return {"kind": "expression", "text": _truncate(str(expression))}


def _comparison_operators(
    operation: MediumLevelILOperation, include_ordered: bool
) -> tuple[str, str] | None:
    """The operator as (subject on the left, constant on the left), or None if not reported."""
    equality = _EQUALITY_OPERATORS.get(operation)
    if equality is not None:
        return equality, equality
    if not include_ordered:
        return None
    return _ORDERED_OPERATORS.get(operation)


def _iter_branch_constraints(
    target_mlil: MediumLevelILFunction, include_ordered: bool
) -> list[dict[str, object]]:
    """Every conditional that compares an expression against a constant, in address order."""
    located: list[tuple[int, dict[str, object]]] = []
    for instruction in target_mlil.instructions:
        if instruction.operation != MediumLevelILOperation.MLIL_IF:
            continue
        condition = instruction.condition
        operation = condition.operation
        operators = _comparison_operators(operation, include_ordered)
        if operators is None:
            continue
        left = _constant(condition.left)
        right = _constant(condition.right)
        if left is not None and right is None:
            (constant, size), subject, operator = left, condition.right, operators[1]
        elif right is not None and left is None:
            (constant, size), subject, operator = right, condition.left, operators[0]
        else:
            # Both sides constant folds away, and neither constant is a comparison.
            continue
        row: dict[str, object] = {
            "address": hex(instruction.address),
            "operator": operator,
            "constant": hex(constant),
            "char": chr(constant) if 0x20 <= constant < 0x7F else None,
            "subject": _describe_subject(target_mlil, subject),
            "subject_text": _truncate(str(subject)),
        }
        if operation in _SIGNED_OPERATORS:
            row["signed_constant"] = hex(_as_signed(constant, size))
        if operation in _FLOAT_OPERATORS:
            row["float_constant"] = _float_text(constant, size)
        located.append((instruction.address, row))
    located.sort(key=lambda entry: entry[0])
    return [row for _, row in located]


@mcp.tool(read_only=True)
def rex_function_constraints(
    call: mcp.ToolCall,
    function: mcp.Address,
    limit: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_LIMIT)] = 100,
    offset: Annotated[int, mcp.Minimum(0)] = 0,
    operators: Literal["equality", "all"] = "equality",
) -> dict[str, object]:
    """List constant branch comparisons; inform their variable with rex_uidf_set to fold them.

    :param function: Address expression inside the target function.
    :param limit: Maximum constraints to return.
    :param offset: Constraints to skip before collecting results.
    :param operators: Comparisons to report: equality (== and !=) or all (adds s<, u>=, ...).
    """
    bv = call.binary_view
    requested: str = operators
    if requested not in _OPERATOR_SETS:
        raise mcp.ToolError(
            "invalid_params",
            f"operators must be 'equality' or 'all', not '{_show_nul(_truncate(requested))}'",
        )
    resolution = _require_analyzed_function(bv, function)
    target = resolution.function
    target_mlil = target.mlil
    if target_mlil is None:
        raise _missing_il_error(target, "MediumLevelIL", "no_mlil")
    rows = _iter_branch_constraints(target_mlil, include_ordered=requested == "all")
    return {
        "function": resolution.entry,
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
    resolution = _require_analyzed_function(bv, function)
    target = resolution.function
    hlil = target.hlil
    if hlil is None:
        raise _missing_il_error(target, "HLIL", "no_hlil")
    rows: list[dict[str, object]] = []
    for block in hlil.basic_blocks:
        for instruction in block:
            rows.append(
                {
                    "address": hex(instruction.address),
                    "index": instruction.instr_index,
                    "text": _truncate(str(instruction)),
                }
            )
    return {
        "function": resolution.entry,
        "total": len(rows),
        "truncated": offset + limit < len(rows),
        "statements": rows[offset : offset + limit],
    }


def _variable_storage(architecture: Architecture, variable: Variable) -> _VariableStorage:
    match variable.source_type:
        case VariableSourceType.RegisterVariableSourceType:
            return {"source": "register", "register": architecture.get_reg_name(variable.storage)}
        case VariableSourceType.StackVariableSourceType:
            return {"source": "stack", "stack_offset": variable.storage}
        case VariableSourceType.FlagVariableSourceType:
            if variable.storage & _TEMP_FLAG_BIT:
                return {
                    "source": "flag",
                    "flag": f"temp flag {variable.storage & _TEMP_FLAG_INDEX_MASK}",
                }
            return {"source": "flag", "flag": architecture.get_flag_name(variable.storage)}
        case VariableSourceType.CompositeReturnValueSourceType:
            return {"source": "composite_return_value", "storage": variable.storage}
        case VariableSourceType.CompositeParameterSourceType:
            return {"source": "composite_parameter", "storage": variable.storage}
        case unknown:
            raise ValueError(f"unknown variable source type {unknown!r}")


def _storage_text(storage: _VariableStorage) -> str:
    if storage["source"] == "register":
        return storage["register"]
    if storage["source"] == "stack":
        return f"stack {storage['stack_offset']:+#x}"
    if storage["source"] == "flag":
        return storage["flag"]
    return f"{storage['source']} {storage['storage']}"


def _variable_text(architecture: Architecture, variable: Variable) -> str:
    storage = _storage_text(_variable_storage(architecture, variable))
    return f"{_truncate(variable.name, 64)} ({storage})"


def _variable_report(
    architecture: Architecture,
    target_mlil: MediumLevelILFunction,
    variable: Variable,
    limit: int,
    offset: int,
) -> _VariableReport:
    uses = sorted(target_mlil.get_var_uses(variable), key=lambda use: use.address)
    rows = [
        _VariableUse(
            address=hex(use.address), operation=use.operation.name, text=_truncate(str(use))
        )
        for use in uses
    ]
    definition_addresses = sorted(
        definition.address for definition in target_mlil.get_var_definitions(variable)
    )
    return {
        "variable": _truncate(variable.name),
        "storage": _variable_storage(architecture, variable),
        "type": _truncate(str(variable.type)),
        "definitions": [hex(address) for address in definition_addresses],
        "total": len(rows),
        "truncated": offset + limit < len(rows),
        "uses": rows[offset : offset + limit],
    }


@mcp.tool(read_only=True)
def rex_mlil_uses(
    call: mcp.ToolCall,
    function: mcp.Address | None,
    address: mcp.Address,
    variable: Annotated[str, mcp.NonEmpty()] | None = None,
    limit: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_LIMIT)] = 100,
    offset: Annotated[int, mcp.Minimum(0)] = 0,
) -> dict[str, object]:
    """List every read of each MLIL variable defined at an address; entries show storage.

    :param function: Address expression inside the target function; omit to use address.
    :param address: Address of an MLIL instruction that defines variables, or the function start.
    :param variable: Report only defined variables with this name (all same-named ones).
    :param limit: Maximum use sites to return per variable.
    :param offset: Use sites to skip per variable before collecting results.
    """
    bv = call.binary_view
    resolution = _require_analyzed_function(bv, address if function is None else function)
    target = resolution.function
    target_mlil = target.mlil
    if target_mlil is None:
        raise _missing_il_error(target, "MediumLevelIL", "no_mlil")
    definitions = _definitions_by_instruction(target_mlil)
    defined_at: dict[int, list[Variable]] = {}
    for instruction in target_mlil.instructions:
        variables = _defined_variables(instruction, definitions)
        if variables:
            defined_at.setdefault(instruction.address, []).extend(variables)
    for parameter in target.parameter_vars:
        if not target_mlil.get_var_definitions(parameter):
            defined_at.setdefault(target.start, []).append(parameter)
    if not defined_at:
        raise mcp.ToolError(
            "no_definition",
            f"no MLIL variable definition at {address:#x} in {_truncate(target.name)}; "
            "the function defines no MLIL variables",
        )
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
        names = ", ".join(_variable_text(target.arch, defined) for defined in at_address)
        raise mcp.ToolError(
            "no_variable",
            f"no variable named '{_show_nul(_truncate(str(variable)))}' is defined at {address:#x} "
            f"in {_truncate(target.name)}; defined there: {names}",
        )
    return {
        "function": resolution.entry,
        "definition_site": hex(address),
        "variables": [
            _variable_report(target.arch, target_mlil, defined, limit, offset)
            for defined in selected
        ],
    }


def _copies_carried_value(use: Any, carried: set[SSAVariable]) -> bool:
    """Whether a use of a carried variable copies its whole value into the use's dest."""
    if use.operation == MediumLevelILOperation.MLIL_VAR_PHI:
        return all(source in carried for source in use.src)
    if use.operation != MediumLevelILOperation.MLIL_SET_VAR_SSA:
        return False
    source = _strip(use.src, _EXTENSIONS)
    return bool(source.operation == MediumLevelILOperation.MLIL_VAR_SSA)


def _parameter_carriers(
    ssa: MediumLevelILFunction, parameters: list[Variable]
) -> list[_ParameterCarrier]:
    """Copies of a parameter's entry value, followed through SSA copies and agreeing phis."""
    entries = [
        version
        for version in ssa.ssa_vars
        if version.var in parameters and ssa.get_ssa_var_definition(version) is None
    ]
    carried = set(entries)
    worklist = list(entries)
    copies: list[Any] = []
    for current in worklist:
        uses: list[Any] = ssa.get_ssa_var_uses(current)
        for use in uses:
            if not _copies_carried_value(use, carried) or use.dest in carried:
                continue
            carried.add(use.dest)
            worklist.append(use.dest)
            if use.operation == MediumLevelILOperation.MLIL_SET_VAR_SSA:
                copies.append(use)
    copies.sort(key=lambda copy: (copy.address, copy.instr_index))
    return [
        _ParameterCarrier(
            variable=_truncate(copy.dest.var.name),
            address=hex(copy.address),
            text=_truncate(str(copy.non_ssa_form)),
        )
        for copy in copies
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
    resolution = _require_analyzed_function(bv, function)
    target = resolution.function
    target_mlil = target.mlil
    if target_mlil is None:
        raise _missing_il_error(target, "MediumLevelIL", "no_mlil")
    matches = [variable for variable in target.vars if variable.name == parameter]
    if not matches:
        raise _unknown_variable_error(target, parameter)
    ssa = target_mlil.ssa_form
    if ssa is None:
        raise _missing_il_error(target, "MediumLevelIL", "no_mlil")
    definition_addresses: list[int] = []
    for variable in matches:
        for definition in target_mlil.get_var_definitions(variable):
            definition_addresses.append(definition.address)
    return {
        "function": resolution.entry,
        "parameter": _truncate(parameter),
        "storage": [_variable_storage(target.arch, variable) for variable in matches],
        "definitions": [hex(address) for address in sorted(definition_addresses)],
        "carriers": _parameter_carriers(ssa, matches),
    }
