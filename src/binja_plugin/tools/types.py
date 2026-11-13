"""Type-system tools: structure inference from offset accesses and type-library import/export."""

from __future__ import annotations

import contextlib
import enum
from typing import Literal, NamedTuple, TypedDict

from binaryninja import Type, TypeLibrary, mcp
from binaryninja.binaryview import BinaryView
from binaryninja.enums import SymbolType, TypeClass
from binaryninja.types import StructureType

from binja_plugin.tools import (
    _MAX_EXPORT_FILE_BYTES,
    _reject_nul,
    _reject_unusable_export_target,
    _resolve_export_path,
    _show_nul,
    _truncate,
    _validate_export_path,
    _validate_text,
)

# QualifiedNames have no core-side length bound and persist, so each name is capped.
_MAX_TYPE_LIBRARY_NAMES = 128
_MAX_TYPE_NAME_CHARS = 255
ExportKind = Literal["types", "objects"]
ImportKind = Literal["types", "objects"]
_MAX_STRUCT_MEMBERS = 128


class _StructMember(TypedDict):
    offset: int
    name: str
    type: str


class _StructFromAccessResult(TypedDict):
    name: str
    registered: str
    width: int
    member_count: int
    members: list[_StructMember]
    truncated: bool


class _ExportedType(TypedDict):
    name: str
    type: str


class _ObjectAlternative(TypedDict):
    address: str
    type: str


class _ExportedObject(TypedDict):
    name: str
    type: str
    address: str
    alternatives: list[_ObjectAlternative]


class _UnresolvedName(TypedDict):
    requested: str
    reason: str


class _ImportedType(TypedDict):
    requested: str
    resolved: str


class _ImportedObject(TypedDict):
    requested: str
    type: str


class _TypeLibraryExportResult(TypedDict):
    path: str
    bytes_written: int
    library: str
    exported: list[_ExportedType | _ExportedObject]
    failed: list[_UnresolvedName]
    applied: int
    failed_count: int
    total: int


class _TypeLibraryImportResult(TypedDict):
    library: str | None
    imported: list[_ImportedType | _ImportedObject]
    failed: list[_UnresolvedName]
    applied: int
    failed_count: int
    total: int


def _validate_type_names(names: list[str]) -> list[str]:
    """Range-check a caller-supplied list of type names, rejecting instead of normalizing."""
    if not isinstance(names, list):
        raise mcp.ToolError("invalid_params", "names must be a list of type names")
    if not 1 <= len(names) <= _MAX_TYPE_LIBRARY_NAMES:
        raise mcp.ToolError(
            "invalid_params",
            f"names must contain between 1 and {_MAX_TYPE_LIBRARY_NAMES} entries",
        )
    for index, name in enumerate(names):
        if not isinstance(name, str):
            raise mcp.ToolError("invalid_params", f"names[{index}] must be a string type name")
        _validate_text(f"names[{index}]", name, _MAX_TYPE_NAME_CHARS, "invalid_params")
    return names


def _validate_library_kind(kind: str) -> None:
    if kind not in ("types", "objects"):
        raise mcp.ToolError(
            "invalid_params", f"kind must be 'types' or 'objects', not '{_show_nul(kind)}'"
        )


def _access_next_step(name: str) -> str:
    return (
        f"apply 'struct {name}*' to a variable that is dereferenced with bn_variable_set_type, "
        "run rex_analysis_wait, then retry"
    )


def _member_layout(structure: StructureType) -> list[tuple[int, str, str]]:
    layout: list[tuple[int, str, str]] = []
    for member in structure.members:
        layout.append((member.offset, member.name, str(member.type)))
    return layout


@mcp.tool(destructive=True)
def rex_struct_from_access(call: mcp.ToolCall, name: str) -> _StructFromAccessResult:
    """Add members inferred from recorded offset accesses to an existing struct. Writes; undoable.

    :param name: Existing struct type that dereferenced variables are typed as pointers to.
    """
    bv = call.binary_view
    # The plugin's per-parameter *_too_large string-cap code family.
    _validate_text("name", name, _MAX_TYPE_NAME_CHARS, "name_too_large")
    shown = _truncate(name)
    existing = bv.get_type_by_name(name)
    if existing is None:
        raise mcp.ToolError(
            "type_not_found",
            f"no type named '{shown}' in the view; create it as an empty struct with "
            f"bn_type_struct_create, then {_access_next_step(shown)}",
        )
    if not isinstance(existing, StructureType):
        raise mcp.ToolError(
            "not_a_structure", f"type '{shown}' is not a structure; pass the name of a struct type"
        )
    try:
        structure = bv.create_structure_from_offset_access(name)
    except Exception as error:
        raise mcp.ToolError(
            "create_failed",
            f"analysis has recorded no offset accesses for struct '{shown}' ({error}); "
            f"{_access_next_step(shown)}",
        ) from None
    same_width = structure.width == existing.width
    if same_width and _member_layout(structure) == _member_layout(existing):
        raise mcp.ToolError(
            "create_failed",
            f"analysis has recorded no offset accesses for struct '{shown}' beyond its existing "
            f"members; {_access_next_step(shown)}",
        )
    # A user type replaces the definition under the same name, so code already typed with
    # it sees the members, and the write lands on the undo stack.
    with bv.undoable_transaction():
        bv.define_user_type(name, structure)
    members = structure.members
    return {
        "name": shown,
        "registered": shown,
        "width": structure.width,
        "member_count": len(members),
        "members": [
            {
                "offset": member.offset,
                "name": _truncate(member.name),
                "type": _truncate(str(member.type)),
            }
            for member in members[:_MAX_STRUCT_MEMBERS]
        ],
        "truncated": len(members) > _MAX_STRUCT_MEMBERS,
    }


class _ObjectRank(enum.IntEnum):
    FUNCTION = 0
    DATA_VARIABLE = 1
    VOID_DATA_VARIABLE = 2
    IMPORT_SLOT = 3


class _ObjectCandidate(NamedTuple):
    rank: _ObjectRank
    address: int
    type: Type


def _object_candidates(bv: BinaryView, name: str) -> list[_ObjectCandidate]:
    candidates = [
        _ObjectCandidate(_ObjectRank.FUNCTION, function.start, function.type)
        for function in bv.get_functions_by_name(name)
    ]
    symbols = bv.get_symbols_by_name(name)
    import_slot_addresses: set[int] = set()
    for symbol in symbols:
        if symbol.type == SymbolType.ImportAddressSymbol:
            import_slot_addresses.add(symbol.address)
    for address in {symbol.address for symbol in symbols}:
        data_variable = bv.get_data_var_at(address)
        if data_variable is None:
            continue
        if address in import_slot_addresses:
            rank = _ObjectRank.IMPORT_SLOT
        elif data_variable.type.type_class == TypeClass.VoidTypeClass:
            rank = _ObjectRank.VOID_DATA_VARIABLE
        else:
            rank = _ObjectRank.DATA_VARIABLE
        candidates.append(_ObjectCandidate(rank, address, data_variable.type))
    # _ObjectCandidate's natural order is (rank, address); same-address candidates
    # always differ in rank, so the third field never enters a comparison.
    return sorted(candidates)


@mcp.tool(destructive=True)
def rex_type_library_export(
    call: mcp.ToolCall,
    library_name: str,
    names: list[str],
    filename: str,
    kind: ExportKind = "types",
) -> _TypeLibraryExportResult:
    """Export types or objects into a new .bntl; object entries add address and alternatives.

    :param library_name: Name for the new type library.
    :param names: 1 to 128 type names to export from the view.
    :param filename: Plain file name inside the export root; overwritten if it exists.
    :param kind: "types" or "objects" (function, else typed data, else void, else import slot).
    """
    bv = call.binary_view
    # The plugin's per-parameter *_too_large string-cap code family.
    _validate_text("library_name", library_name, _MAX_TYPE_NAME_CHARS, "library_name_too_large")
    _validate_type_names(names)
    _validate_export_path(filename)
    _reject_unusable_export_target(filename)
    # Widened to str so the body check stays reachable by direct calls; match the Literal.
    requested: str = kind
    _validate_library_kind(requested)
    arch = bv.arch
    if arch is None:
        raise mcp.ToolError(
            "no_arch", "the binary view has no architecture to create a type library for"
        )
    library = TypeLibrary.new(arch, library_name)
    exported: list[_ExportedType | _ExportedObject] = []
    failed: list[_UnresolvedName] = []
    for name in names:
        if requested == "types":
            type_obj = bv.get_type_by_name(name)
            if type_obj is None:
                failed.append({"requested": name, "reason": "no type with this name in the view"})
                continue
            bv.export_type_to_library(library, name, type_obj)
            exported.append({"name": name, "type": _truncate(str(type_obj))})
            continue
        candidates = _object_candidates(bv, name)
        if not candidates:
            failed.append(
                {
                    "requested": name,
                    "reason": "no function or data variable with this name in the view",
                }
            )
            continue
        chosen, *others = candidates
        bv.export_object_to_library(library, name, chosen.type)
        exported.append(
            {
                "name": name,
                "type": _truncate(str(chosen.type)),
                "address": hex(chosen.address),
                "alternatives": [
                    {"address": hex(other.address), "type": _truncate(str(other.type))}
                    for other in others
                ],
            }
        )
    if not library.finalize():
        raise mcp.ToolError(
            "finalize_failed", f"could not finalize type library '{_truncate(library_name)}'"
        )
    resolved = _resolve_export_path(filename)
    try:
        library.write_to_file(str(resolved))
        bytes_written = resolved.stat().st_size
    except OSError as error:
        raise mcp.ToolError("export_failed", f"could not write export file: {error}") from None
    if bytes_written > _MAX_EXPORT_FILE_BYTES:
        with contextlib.suppress(OSError):
            resolved.unlink()
        raise mcp.ToolError(
            "export_failed",
            f"type library file exceeds the {_MAX_EXPORT_FILE_BYTES} byte export cap; "
            "export fewer names",
        )
    return {
        "path": str(resolved),
        "bytes_written": bytes_written,
        "library": _truncate(library_name),
        "exported": exported,
        "failed": failed,
        # applied counts exported entries, failed_count the per-name failures under ``failed``.
        "applied": len(exported),
        "failed_count": len(failed),
        "total": len(names),
    }


@mcp.tool(destructive=True)
def rex_type_library_import(
    call: mcp.ToolCall, path: str, names: list[str], kind: ImportKind = "types"
) -> _TypeLibraryImportResult:
    """Import types or objects from a .bntl into the current binary view. Writes; not undoable.

    :param path: Filesystem path of the .bntl file to load.
    :param names: 1 to 128 type or object names to import from the library.
    :param kind: "types" (named types) or "objects" (function and data variable types).
    """
    bv = call.binary_view
    _reject_nul("path", path)
    _validate_type_names(names)
    # Widened to str so the body check stays reachable by direct calls; match the Literal.
    requested_kind: str = kind
    _validate_library_kind(requested_kind)
    library = TypeLibrary.load_from_file(path)
    if library is None:
        raise mcp.ToolError(
            "library_not_found",
            f"could not load a type library from '{_truncate(path)}'; "
            "pass the path of a .bntl file, such as one rex_type_library_export wrote",
        )
    bv.add_type_library(library)
    imported: list[_ImportedType | _ImportedObject] = []
    failed: list[_UnresolvedName] = []
    for name in names:
        if requested_kind == "objects":
            if library.get_named_object(name) is None:
                failed.append({"requested": name, "reason": "not provided by this type library"})
                continue
            object_type = bv.import_library_object(name, library)
            if object_type is None:
                failed.append(
                    {"requested": name, "reason": "the core could not import this object"}
                )
                continue
            imported.append({"requested": name, "type": _truncate(str(object_type))})
            continue
        if library.get_named_type(name) is None:
            failed.append({"requested": name, "reason": "not provided by this type library"})
            continue
        type_obj = bv.import_library_type(name, library)
        if type_obj is None:
            failed.append({"requested": name, "reason": "not provided by this type library"})
            continue
        # The return value is a NamedTypeReference named by the deconflicted name the core inserted.
        imported.append({"requested": name, "resolved": str(type_obj.name)})
    return {
        "library": _truncate(library.name) if library.name is not None else None,
        "imported": imported,
        "failed": failed,
        # applied counts imported names, failed_count the per-name failures under ``failed``.
        "applied": len(imported),
        "failed_count": len(failed),
        "total": len(names),
    }
