"""Fakes for exercising binja_plugin without a Binary Ninja installation."""

from __future__ import annotations

import builtins
import enum
import inspect
import re
import sys
import types
import typing
from pathlib import Path
from typing import Any

import pytest

# The UIDF and view fakes live in leaf modules: they hold only self-contained fakes so
# this module's top-level import of them cannot cycle.
from helpers_uidf import FakeRegisterValueType, FakeVariableSourceType
from helpers_view import (
    TYPE_LIBRARIES_ON_DISK,
    FakeAnalysisSkipReason,
    FakeAnalysisState,
    FakeBasicBlock,
    FakeBinaryView,
    FakeFunction,
    FakeInstructionTextTokenType,
    FakeSymbolType,
    FakeType,
    FakeTypeClass,
    FakeTypeLibrary,
    RenderableText,
)

NO_ALTERNATIVES = types.MappingProxyType({"also_containing": [], "same_name": []})


class FakeHighLevelILConstPtr:
    def __init__(self, constant: int) -> None:
        self.constant = constant


class FakeHighLevelILConst:
    def __init__(self, constant: int) -> None:
        self.constant = constant


class FakeHighLevelILImport:
    def __init__(self, constant: int) -> None:
        self.constant = constant


class FakeHighLevelILVar:
    pass


class FakeHighLevelILTailcall:
    def __init__(self, dest: object, params: tuple[object, ...] = ()) -> None:
        self.dest = dest
        self.params = list(params)


def _fake_highlevelil_module() -> types.ModuleType:
    module = types.ModuleType("binaryninja.highlevelil")
    setattr(module, "HighLevelILTailcall", FakeHighLevelILTailcall)
    setattr(module, "HighLevelILConstPtr", FakeHighLevelILConstPtr)
    setattr(module, "HighLevelILConst", FakeHighLevelILConst)
    setattr(module, "HighLevelILImport", FakeHighLevelILImport)
    setattr(module, "HighLevelILVar", FakeHighLevelILVar)
    return module


REGISTERED_TOOLS: list[tuple[str, dict[str, object], Any]] = []


class FakeToolError(Exception):
    def __init__(self, code: str, message: str, details: object = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details


def _fake_tool(name: str | None = None, **options: object):
    def decorate(function: Any) -> Any:
        tool_name = name or function.__name__
        # The real binaryninja.mcp.tool refuses to register a tool whose docstring has no
        # leading paragraph or whose parameters lack :param: lines, raising these same
        # TypeErrors at decoration time (installed mcp.py). Mirroring both checks keeps a
        # docstring strip that would kill real registration from passing these gates
        # against the fake.
        text = inspect.cleandoc(function.__doc__ or "")
        summary = re.split(r"\n\s*\n|\n(?=:)", text, maxsplit=1)[0]
        if not " ".join(line.strip() for line in summary.splitlines()):
            raise TypeError(f"MCP tool '{tool_name}' needs a docstring describing it")
        described = {
            match.group(1) for match in re.finditer(r"^:param\s+(\w+):", text, re.MULTILINE)
        }
        for parameter in list(inspect.signature(function).parameters)[1:]:
            if parameter not in described:
                raise TypeError(
                    f"MCP tool '{function.__name__}': parameter '{parameter}' "
                    f"needs a ':param {parameter}:' description"
                )
        REGISTERED_TOOLS.append((tool_name, options, function))
        return function

    return decorate


class FakeSchema:
    """Mirrors binaryninja.mcp.Schema; the fake decorator does not apply rejection."""

    def __init__(self, schema: dict[str, object]) -> None:
        self.schema = schema


def _fake_optional_inner(annotation: object) -> object | None:
    """Mirrors binaryninja.mcp._optional_inner: T for Optional[T] or T | None, else None."""
    origin = typing.get_origin(annotation)
    if origin is typing.Union or origin is types.UnionType:
        arguments = typing.get_args(annotation)
        inner = [argument for argument in arguments if argument is not type(None)]  # noqa: E711
        if len(inner) == 1 and len(arguments) == 2:
            return inner[0]
    return None


def _fake_describe_plain(annotation: object) -> dict[str, object] | None:
    """Mirrors binaryninja.mcp._describe's leaf annotations, or None when structural."""
    if annotation is FakeAddress:
        return {"type": "string"}
    if annotation is FakeIntegerExpression:
        return {"type": ["integer", "string"], "minimum": 0}
    if annotation is str:
        return {"type": "string"}
    if annotation is bool:
        return {"type": "boolean"}
    if annotation is int:
        return {"type": "integer"}
    if annotation is float:
        return {"type": "number"}
    return None


def _fake_describe_annotated(metadata: list[object], base: object) -> dict[str, object]:
    """Mirrors binaryninja.mcp._describe's Annotated handling for the metadata in use."""
    schemas = [item.schema for item in metadata if isinstance(item, FakeSchema)]
    if schemas:
        return dict(schemas[0])
    limits = [item for item in metadata if isinstance(item, (FakeMinimum, FakeMaximum))]
    if limits:
        schema: dict[str, object] = {"type": "integer"}
        for limit in limits:
            if isinstance(limit, FakeMinimum):
                schema["minimum"] = limit.value
            else:
                schema["maximum"] = limit.value
        return schema
    if any(isinstance(item, FakeNonEmpty) for item in metadata):
        return {"type": "string", "minLength": 1}
    return _fake_describe(base)


def _fake_describe(annotation: object) -> dict[str, object]:
    """Mirrors binaryninja.mcp._describe for the annotations the plugin's tools use.

    The real mcp layer builds each tool's input schema at registration; rex_help serves
    that schema from the registry, so the fake has to produce the same JSON for the
    annotations that appear on registered parameters. An annotation outside this set
    raises instead of describing loosely, so a new tool parameter fails loudly here
    rather than serving rex_help a schema the real registry would not.
    """
    plain = _fake_describe_plain(annotation)
    if plain is not None:
        return plain
    origin = typing.get_origin(annotation)
    arguments = typing.get_args(annotation)
    if origin is typing.Literal:
        return {"type": "string", "enum": list(arguments)}
    if origin is list:
        return {"type": "array", "items": _fake_describe(arguments[0])}
    if origin is typing.Annotated:
        base, *metadata = arguments
        return _fake_describe_annotated(metadata, base)
    raise TypeError(f"unsupported annotation {annotation!r}")


def _fake_input_schema(function: Any) -> dict[str, Any]:
    """Mirrors the input schema binaryninja.mcp.tool registers for ``function``."""
    signature = inspect.signature(function)
    hints = typing.get_type_hints(function, include_extras=True)
    text = inspect.cleandoc(function.__doc__ or "")
    descriptions = {
        match.group(1): " ".join(part.strip() for part in match.group(2).splitlines())
        for match in re.finditer(r"^:param\s+(\w+):\s*(.*(?:\n[ \t]+\S.*)*)", text, re.MULTILINE)
    }
    properties: dict[str, object] = {}
    required: list[str] = []
    for parameter in list(signature.parameters.values())[1:]:
        annotation = hints[parameter.name]
        inner = _fake_optional_inner(annotation)
        schema = _fake_describe(inner if inner is not None else annotation)
        schema["description"] = descriptions[parameter.name]
        has_default = parameter.default is not inspect.Parameter.empty
        if has_default and parameter.default is not None:
            schema["default"] = parameter.default
        if inner is None and not has_default:
            required.append(parameter.name)
        properties[parameter.name] = schema
    input_schema: dict[str, object] = {"type": "object", "properties": properties}
    if required:
        input_schema["required"] = required
    input_schema["additionalProperties"] = False
    return input_schema


class FakeTool:
    """Mirrors binaryninja.mcp.Tool: the registry queries rex_help serves from."""

    def __init__(self, name: str, options: dict[str, object], function: Any) -> None:
        self._name = name
        self._options = options
        self._function = function

    @property
    def name(self) -> str:
        return self._name

    @property
    def description(self) -> str:
        text = inspect.cleandoc(self._function.__doc__ or "")
        summary = re.split(r"\n\s*\n|\n(?=:)", text, maxsplit=1)[0]
        return " ".join(line.strip() for line in summary.splitlines())

    @property
    def input_schema(self) -> dict[str, Any]:
        return _fake_input_schema(self._function)

    @staticmethod
    def list() -> builtins.list[FakeTool]:
        return [FakeTool(name, options, function) for name, options, function in REGISTERED_TOOLS]


class FakeAddress(int):
    pass


class FakeIntegerExpression(int):
    pass


class FakeMinimum:
    """Mirrors binaryninja.mcp.Minimum; the fake decorator does not apply rejection."""

    def __init__(self, value: int) -> None:
        self.value = value


class FakeMaximum:
    """Mirrors binaryninja.mcp.Maximum; the fake decorator does not apply rejection."""

    def __init__(self, value: int) -> None:
        self.value = value


class FakeNonEmpty:
    """Mirrors binaryninja.mcp.NonEmpty; the fake decorator does not apply rejection."""

    def __init__(self) -> None:
        pass


class FakeToolCallBase:
    pass


def install_fake_binaryninja() -> None:
    """Create the fake binaryninja package in sys.modules when it is absent."""
    if "binaryninja" in sys.modules:
        return
    mcp_module = types.ModuleType("binaryninja.mcp")
    setattr(mcp_module, "tool", _fake_tool)
    setattr(mcp_module, "Address", FakeAddress)
    setattr(mcp_module, "IntegerExpression", FakeIntegerExpression)
    setattr(mcp_module, "ToolCall", FakeToolCallBase)
    setattr(mcp_module, "ToolError", FakeToolError)
    setattr(mcp_module, "Minimum", FakeMinimum)
    setattr(mcp_module, "Maximum", FakeMaximum)
    setattr(mcp_module, "NonEmpty", FakeNonEmpty)
    setattr(mcp_module, "Schema", FakeSchema)
    setattr(mcp_module, "Tool", FakeTool)
    setattr(
        mcp_module,
        "McpToolScope",
        enum.IntEnum("McpToolScope", {"GlobalScope": 0, "BinaryViewScope": 1}),
    )
    setattr(
        mcp_module,
        "McpToolAnnotation",
        enum.IntFlag(
            "McpToolAnnotation",
            {"ReadOnlyHint": 1, "DestructiveHint": 2, "IdempotentHint": 4, "OpenWorldHint": 8},
        ),
    )

    bv_module = types.ModuleType("binaryninja.binaryview")

    class FakeBinaryViewBase:
        pass

    setattr(bv_module, "BinaryView", FakeBinaryViewBase)

    fn_module = types.ModuleType("binaryninja.function")

    class FakeFunctionBase:
        pass

    setattr(fn_module, "Function", FakeFunctionBase)

    enums_module = types.ModuleType("binaryninja.enums")
    setattr(enums_module, "AnalysisState", FakeAnalysisState)
    setattr(enums_module, "AnalysisSkipReason", FakeAnalysisSkipReason)
    setattr(enums_module, "RegisterValueType", FakeRegisterValueType)
    setattr(enums_module, "TypeClass", FakeTypeClass)
    setattr(enums_module, "InstructionTextTokenType", FakeInstructionTextTokenType)
    setattr(enums_module, "SymbolType", FakeSymbolType)
    setattr(enums_module, "VariableSourceType", FakeVariableSourceType)
    setattr(
        enums_module,
        "LowLevelILOperation",
        enum.IntEnum(
            "LowLevelILOperation",
            {"LLIL_CALL": 56, "LLIL_TAILCALL": 58, "LLIL_LOAD": 8},
        ),
    )

    variable_module = types.ModuleType("binaryninja.variable")

    class FakeVariableBase:
        pass

    setattr(variable_module, "Variable", FakeVariableBase)

    mlil_module = types.ModuleType("binaryninja.mediumlevelil")

    class FakeMediumLevelILInstructionBase:
        pass

    setattr(mlil_module, "MediumLevelILInstruction", FakeMediumLevelILInstructionBase)

    hlil_module = _fake_highlevelil_module()

    package = types.ModuleType("binaryninja")
    setattr(package, "mcp", mcp_module)
    setattr(package, "binaryview", bv_module)
    setattr(package, "function", fn_module)
    setattr(package, "enums", enums_module)
    setattr(package, "variable", variable_module)
    setattr(package, "mediumlevelil", mlil_module)
    setattr(package, "highlevelil", hlil_module)
    setattr(package, "Type", FakeType)
    setattr(package, "TypeLibrary", FakeTypeLibrary)

    for name, module in (
        ("binaryninja", package),
        ("binaryninja.mcp", mcp_module),
        ("binaryninja.binaryview", bv_module),
        ("binaryninja.function", fn_module),
        ("binaryninja.enums", enums_module),
        ("binaryninja.variable", variable_module),
        ("binaryninja.mediumlevelil", mlil_module),
        ("binaryninja.highlevelil", hlil_module),
    ):
        sys.modules[name] = module
    REGISTERED_TOOLS.clear()
    TYPE_LIBRARIES_ON_DISK.clear()


class FakeToolCall:
    def __init__(self, binary_view: FakeBinaryView) -> None:
        self.binary_view = binary_view


def get_tool(name: str) -> tuple[dict[str, object], Any]:
    for tool_name, options, function in REGISTERED_TOOLS:
        if tool_name == name:
            return options, function
    raise KeyError(name)


# --- view builders and tool-call fakes shared by the per-category tool test modules ----------


def _call(view: FakeBinaryView) -> FakeToolCall:
    return FakeToolCall(view)


def _view_with_functions() -> FakeBinaryView:
    main = FakeFunction(
        "main",
        0x1100,
        0x1200,
        hlil=RenderableText("void main() {\n    if (recv(fd, buf, n) <= 0)\n        return 1;\n}"),
    )
    handler = FakeFunction("handler", 0x2000, 0x2100)
    sink = FakeFunction("sink", 0x3000, 0x3100)
    main.callers = [handler]
    handler.callers = [sink]
    sink.callees = [handler]
    handler.callees = [main]
    return FakeBinaryView(functions=[main, handler, sink])


class FakeDisasmFunction(FakeFunction):
    """FakeFunction with the basic_blocks attribute rex_disasm_at reads."""

    def __init__(
        self,
        name: str,
        start: int,
        end: int,
        blocks: list[FakeBasicBlock],
        hlil: object = None,
    ) -> None:
        super().__init__(name, start, end, hlil=hlil)
        self.basic_blocks = blocks


def _disasm_view() -> FakeBinaryView:
    main = FakeDisasmFunction(
        "main",
        0x1100,
        0x1200,
        blocks=[
            FakeBasicBlock(
                [
                    (0x1100, "push rbp"),
                    (0x1101, "mov rbp, rsp"),
                    (0x1104, "sub rsp, 0x20"),
                    (0x1108, "mov eax, 1"),
                    (0x110D, "leave"),
                    (0x110E, "ret"),
                ]
            )
        ],
    )
    handler = FakeDisasmFunction(
        "handler", 0x2000, 0x2100, blocks=[FakeBasicBlock([(0x2000, "push rbp"), (0x2001, "ret")])]
    )
    return FakeBinaryView(functions=[main, handler])


class FakeParsingToolCall(FakeToolCall):
    """FakeToolCall with the parse_address surface rex_decompile_many/rex_quick_main read.

    Deliberately raises a plain ValueError for unparsable input instead of a ToolError:
    the handler owns the conversion of expression-parse failures to invalid_params, so
    the fake must not hand it an error to pass through. ``data_<hex>`` tokens resolve the
    way the core's address-expression parser was observed to resolve them live.
    """

    def parse_address(self, value: object, here: int = 0) -> int:
        text = value if isinstance(value, str) else str(value)
        try:
            return int(text, 16) if text.lower().startswith("0x") else int(text, 10)
        except ValueError:
            pass
        if text.startswith("data_"):
            return int(text[5:], 16)
        raise ValueError(f"unparsable address expression '{text}'") from None


def _use_export_root(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Point the export tools at a per-test root so nothing lands in the real home."""
    # Deferred: helpers is imported before the fake binaryninja is installed, so a
    # module-level binja_plugin import here would pull in the real (absent) package.
    from binja_plugin import tools

    root = tmp_path / "exports"
    monkeypatch.setattr(tools, "_EXPORT_ROOT", root)
    return root
