"""Type-system tools: structure inference from offset accesses and type-library import/export."""

from __future__ import annotations

import contextlib
from typing import Literal

from binaryninja import Type, TypeLibrary, mcp

from binja_plugin.tools import (
    _MAX_EXPORT_FILE_BYTES,
    _resolve_export_path,
    _truncate,
    _validate_export_path,
    _validate_text,
)

# Type-library tools: one call moves at most this many type names, and each name is
# capped before it reaches the type system — QualifiedNames have no core-side length
# bound and persist in the type database or the .bntl.
_MAX_TYPE_LIBRARY_NAMES = 64
_MAX_TYPE_NAME_CHARS = 255
_EXPORT_KINDS = Literal["types", "objects"]
# rex_struct_from_access echoes at most this many members; the struct is defined in full
# regardless, the cap bounds only the echoed list.
_MAX_STRUCT_MEMBERS = 128
# Source passed to Type.generate_auto_type_id, so the auto types this tool defines are
# identifiable in the type system as originating here.
_STRUCT_TYPE_SOURCE = "rex_struct"


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


@mcp.tool(destructive=True)
def rex_struct_from_access(call: mcp.ToolCall, name: str) -> dict[str, object]:
    """Infer and define a struct from the view's recorded offset accesses.

    :param name: Name for the new structure.
    """
    bv = call.binary_view
    # The plugin's per-parameter *_too_large string-cap code family.
    _validate_text("name", name, _MAX_TYPE_NAME_CHARS, "name_too_large")
    try:
        structure = bv.create_structure_from_offset_access(name)
    except Exception as error:
        raise mcp.ToolError(
            "create_failed", f"could not create a structure from offset accesses: {error}"
        ) from None
    members = structure.members
    registered = bv.define_type(
        Type.generate_auto_type_id(_STRUCT_TYPE_SOURCE, name), name, structure
    )
    return {
        "name": _truncate(name),
        "registered": _truncate(str(registered)),
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


@mcp.tool(destructive=True)
def rex_type_library_export(
    call: mcp.ToolCall,
    library_name: str,
    names: list[str],
    kind: _EXPORT_KINDS = "types",
    filename: str = "",
) -> dict[str, object]:
    """Export recovered types or objects into a new .bntl in the export root.

    :param library_name: Name for the new type library.
    :param names: 1 to 64 type names to export from the view.
    :param kind: Export type definitions ("types") or named objects ("objects").
    :param filename: Plain file name inside the export root; overwritten if it exists.
    """
    bv = call.binary_view
    # The plugin's per-parameter *_too_large string-cap code family.
    _validate_text("library_name", library_name, _MAX_TYPE_NAME_CHARS, "library_name_too_large")
    _validate_type_names(names)
    _validate_export_path(filename)
    # The schema-side Literal and the body-side check below must agree; widening to str
    # keeps the body check statically reachable for direct handler invocation.
    requested: str = kind
    if requested not in ("types", "objects"):
        raise mcp.ToolError(
            "invalid_params", f"kind must be 'types' or 'objects', not '{requested}'"
        )
    arch = bv.arch
    if arch is None:
        raise mcp.ToolError(
            "no_arch", "the binary view has no architecture to create a type library for"
        )
    library = TypeLibrary.new(arch, library_name)
    exported: list[str] = []
    failed: list[dict[str, str]] = []
    for name in names:
        type_obj = bv.get_type_by_name(name)
        if type_obj is None:
            failed.append({"requested": name, "reason": "no type with this name in the view"})
            continue
        if requested == "types":
            bv.export_type_to_library(library, name, type_obj)
        else:
            bv.export_object_to_library(library, name, type_obj)
        exported.append(name)
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
            f"type library file exceeds the {_MAX_EXPORT_FILE_BYTES} byte export cap",
        )
    return {
        "path": str(resolved),
        "bytes_written": bytes_written,
        "library": _truncate(library_name),
        "exported": exported,
        "failed": failed,
        # The uniform batch-summary keys (see rex_annotate_many): applied counts the
        # exported names, failed_count the per-name failures echoed under ``failed``.
        "applied": len(exported),
        "failed_count": len(failed),
        "total": len(names),
    }


@mcp.tool(destructive=True)
def rex_type_library_import(call: mcp.ToolCall, path: str, names: list[str]) -> dict[str, object]:
    """Import types from a .bntl into the current binary view.

    :param path: Filesystem path of the .bntl file to load.
    :param names: 1 to 64 type names to import from the library.
    """
    bv = call.binary_view
    _validate_type_names(names)
    library = TypeLibrary.load_from_file(path)
    if library is None:
        raise mcp.ToolError(
            "library_not_found", f"could not load a type library from '{_truncate(path)}'"
        )
    bv.add_type_library(library)
    imported: list[dict[str, str]] = []
    failed: list[dict[str, str]] = []
    for name in names:
        type_obj = bv.import_library_type(name, library)
        if type_obj is None:
            failed.append({"requested": name, "reason": "not provided by this type library"})
            continue
        # The return value is a NamedTypeReference whose name is the deconflicted name
        # the core actually inserted.
        imported.append({"requested": name, "resolved": str(type_obj.name)})
    return {
        "library": _truncate(library.name) if library.name is not None else None,
        "imported": imported,
        "failed": failed,
        # The uniform batch-summary keys (see rex_annotate_many): applied counts the
        # imported names, failed_count the per-name failures echoed under ``failed``.
        "applied": len(imported),
        "failed_count": len(failed),
        "total": len(names),
    }
