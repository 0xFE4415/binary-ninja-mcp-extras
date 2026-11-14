"""Fake of the argument handling binaryninja.mcp.tool wraps around every registered handler.

Mirrors the installed binaryninja/mcp.py (`tool`'s `handler`, `_parameters`, `_describe`,
`_describe_limited_int`). Direct handler calls skip all of it, so a test that needs the
layer's rejection or conversion goes through `invoke_tool`. The copy can drift from the
real module; the live playbook under tests/live is the check against the real layer.
"""

from __future__ import annotations

import enum
import inspect
import sys
import typing
from collections.abc import Callable
from typing import Any

_Convert = Callable[[Any, Any, dict[str, Any]], Any]
_Described = tuple[str, _Convert]


def _mcp() -> Any:
    return sys.modules["binaryninja.mcp"]


def _is_integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _expect(
    kind: str, name: str, check: Callable[[Any], bool], convert: Callable[[Any], Any]
) -> _Convert:
    def run(call: Any, value: Any, converted: dict[str, Any]) -> Any:
        if not check(value):
            raise _mcp().ToolError("invalid_params", f"Expected {kind} parameter '{name}'")
        return convert(value)

    return run


def _optional_inner(annotation: object) -> object | None:
    origin = typing.get_origin(annotation)
    if origin is typing.Union or origin is type(int | None):
        arguments = [
            argument for argument in typing.get_args(annotation) if argument is not type(None)
        ]
        if len(arguments) == 1 and len(typing.get_args(annotation)) == 2:
            return arguments[0]
    return None


def _limit_bounds(limits: list[Any]) -> tuple[Any, Any, bool]:
    mcp = _mcp()
    minimum: Any = None
    maximum: Any = None
    clamp = False
    for limit in limits:
        if isinstance(limit, mcp.Minimum):
            minimum = limit.value
        elif isinstance(limit, mcp.Maximum):
            maximum = limit.value
        else:
            minimum, maximum, clamp = limit.minimum, limit.maximum, True
    return minimum, maximum, clamp


def _limited_int(base: object, name: str, limits: list[Any]) -> _Described:
    if base is not int:
        raise TypeError(f"Parameter '{name}': Minimum, Maximum and ClampTo only apply to int")
    minimum, maximum, clamp = _limit_bounds(limits)

    def convert(call: Any, value: Any, converted: dict[str, Any]) -> Any:
        if not _is_integer(value):
            raise _mcp().ToolError("invalid_params", f"Expected integer parameter '{name}'")
        if minimum is not None and value < minimum:
            if clamp:
                return minimum
            raise _mcp().ToolError(
                "invalid_params", f"Invalid integer parameter '{name}': Must be at least {minimum}"
            )
        if maximum is not None and value > maximum:
            if clamp:
                return maximum
            raise _mcp().ToolError(
                "invalid_params", f"Invalid integer parameter '{name}': Must be at most {maximum}"
            )
        return value

    return "integer", convert


def _annotated(arguments: tuple[Any, ...], name: str) -> _Described:
    mcp = _mcp()
    base, *metadata = arguments
    for item in metadata:
        if isinstance(item, mcp.Schema):
            return "JSON", lambda call, value, converted: value
    limits = [
        item for item in metadata if isinstance(item, (mcp.Minimum, mcp.Maximum, mcp.ClampTo))
    ]
    if limits:
        return _limited_int(base, name, limits)
    if any(isinstance(item, mcp.NonEmpty) for item in metadata):
        if base is not str:
            raise TypeError(f"Parameter '{name}': NonEmpty only applies to str")
        return "non-empty string", _expect(
            "non-empty string",
            name,
            lambda value: isinstance(value, str) and value != "",
            lambda value: value,
        )
    return _describe(base, name)


def _describe_address(name: str) -> _Described:
    def address(call: Any, value: Any, converted: dict[str, Any]) -> Any:
        try:
            return call.parse_address(value)
        except ValueError as error:
            raise _mcp().ToolError(
                "invalid_params", f"Invalid address expression parameter '{name}': {error}"
            )

    return "address expression", address


def _describe_integer_expression(name: str) -> _Described:
    def integer(call: Any, value: Any, converted: dict[str, Any]) -> Any:
        try:
            return call.parse_integer(value, 0)
        except ValueError as error:
            raise _mcp().ToolError(
                "invalid_params", f"Invalid unsigned integer parameter '{name}': {error}"
            )

    return "unsigned integer", integer


def _describe_scalar(annotation: object, name: str) -> _Described | None:
    if annotation is str:
        return "string", _expect(
            "string", name, lambda value: isinstance(value, str), lambda value: value
        )
    if annotation is bool:
        return "boolean", _expect(
            "boolean", name, lambda value: isinstance(value, bool), lambda value: value
        )
    if annotation is int:
        return "integer", _expect("integer", name, _is_integer, lambda value: value)
    if annotation is float:
        return "number", _expect(
            "number", name, lambda value: _is_integer(value) or isinstance(value, float), float
        )
    return None


def _describe_choice(names: list[Any], name: str, resolve: Callable[[str], Any]) -> _Described:
    def choice(call: Any, value: Any, converted: dict[str, Any]) -> Any:
        if not isinstance(value, str):
            raise _mcp().ToolError("invalid_params", f"Expected string parameter '{name}'")
        if value not in names:
            raise _mcp().ToolError("invalid_params", f"Invalid enum value for parameter '{name}'")
        return resolve(value)

    return "string", choice


def _describe_list(item_annotation: object, name: str) -> _Described:
    item_kind, item_convert = _describe(item_annotation, name)

    def items(call: Any, value: Any, converted: dict[str, Any]) -> list[Any]:
        if not isinstance(value, list):
            raise _mcp().ToolError(
                "invalid_params", f"Expected {item_kind} array parameter '{name}'"
            )
        return [item_convert(call, item, converted) for item in value]

    return f"{item_kind} array", items


def _describe(annotation: object, name: str) -> _Described:
    """Returns the kind named in error messages and the conversion for one annotation."""
    mcp = _mcp()
    if annotation is mcp.Address:
        return _describe_address(name)
    if annotation is mcp.IntegerExpression:
        return _describe_integer_expression(name)
    scalar = _describe_scalar(annotation, name)
    if scalar is not None:
        return scalar
    if inspect.isclass(annotation) and issubclass(annotation, enum.Enum):
        return _describe_choice(
            [member.name for member in annotation], name, annotation.__getitem__
        )
    origin = typing.get_origin(annotation)
    arguments = typing.get_args(annotation)
    if origin is typing.Literal:
        return _describe_choice(list(arguments), name, lambda value: value)
    if origin is list:
        return _describe_list(arguments[0] if arguments else str, name)
    if origin is typing.Annotated:
        return _annotated(arguments, name)
    raise TypeError(f"Parameter '{name}': unsupported annotation {annotation!r}")


def invoke_tool(
    function: Callable[..., Any], call: Any, /, *positional: Any, **raw_arguments: Any
) -> Any:
    """Runs ``function`` like the real handler; positionals fill parameters in order."""
    names = list(inspect.signature(function).parameters)[1:]
    arguments = dict(zip(names, positional, strict=False))
    arguments.update(raw_arguments)
    return invoke_arguments(function, call, arguments)


def invoke_arguments(function: Callable[..., Any], call: Any, arguments: Any) -> Any:
    """Runs ``function`` the way the real tool() handler does for a raw arguments object."""
    mcp = _mcp()
    hints = typing.get_type_hints(function, include_extras=True)
    parameters = list(inspect.signature(function).parameters.values())[1:]
    if not isinstance(arguments, dict):
        raise mcp.ToolError("invalid_params", "Expected object arguments")
    declared = {parameter.name for parameter in parameters}
    for argument in arguments:
        if argument not in declared:
            raise mcp.ToolError("invalid_params", f"Unexpected parameter '{argument}'")
    values: dict[str, Any] = {}
    for parameter in parameters:
        annotation = hints[parameter.name]
        inner = _optional_inner(annotation)
        kind, convert = _describe(inner if inner is not None else annotation, parameter.name)
        has_default = parameter.default is not inspect.Parameter.empty
        required = inner is None and not has_default
        default = parameter.default if has_default else None
        if parameter.name in arguments and (required or arguments[parameter.name] is not None):
            values[parameter.name] = convert(call, arguments[parameter.name], values)
        elif required:
            raise mcp.ToolError("invalid_params", f"Expected {kind} parameter '{parameter.name}'")
        else:
            values[parameter.name] = default
    return function(call, **values)
