from __future__ import annotations

from pathlib import Path

import pytest
from helpers import (
    FakeToolError,
    _call,
    _use_export_root,
    get_tool,
)
from helpers_view import (
    TYPE_LIBRARIES_ON_DISK,
    FakeArchitecture,
    FakeBinaryView,
    FakeStructureMember,
    FakeStructureType,
    FakeType,
    FakeTypeLibrary,
)

from binja_plugin import tools
from binja_plugin.tools import types


def test_type_library_export_rejects_a_symlink_escaping_the_export_root(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _use_export_root(monkeypatch, tmp_path)
    root.mkdir(parents=True)
    outside = tmp_path / "outside.bntl"
    outside.write_bytes(b"untouched")
    (root / "link.bntl").symlink_to(outside)
    view = _typed_view()
    _, export = get_tool("rex_type_library_export")
    # The .bntl writer goes through the same resolved path as the text exports, so the
    # core-side write is contained by the same check.
    with pytest.raises(FakeToolError) as exc:
        export(_call(view), "recovered", ["open"], filename="link.bntl")
    assert exc.value.code == "path_escape"
    assert outside.read_bytes() == b"untouched"


# --- rex_type_library_import ----------------------------------------------------------------


def _library_on_disk(tmp_path: Path, library: FakeTypeLibrary) -> str:
    path = str(tmp_path / "libc.bntl")
    TYPE_LIBRARIES_ON_DISK[path] = library
    return path


def test_type_library_import_attaches_and_imports(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(tools, "_EXPORT_ROOT", tmp_path / "exports")
    library = FakeTypeLibrary(name="libc", named_types={"open": FakeType("open")})
    path = _library_on_disk(tmp_path, library)
    # "open" resolves to a deconflicted name because the view already has one; "bad" is
    # not provided by the library at all.
    view = FakeBinaryView(library_types={"open": "open_0"})
    _, import_tool = get_tool("rex_type_library_import")
    result = import_tool(_call(view), path, ["open", "bad"])
    assert result == {
        "library": "libc",
        "imported": [{"requested": "open", "resolved": "open_0"}],
        "failed": [{"requested": "bad", "reason": "not provided by this type library"}],
        "applied": 1,
        "failed_count": 1,
        "total": 2,
    }
    # The library itself was attached to the view once, before any name was imported.
    assert view.type_libraries == [library]
    assert view.imported_library_types == [(library, "open")]


def test_type_library_import_fails_names_absent_from_the_library(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(tools, "_EXPORT_ROOT", tmp_path / "exports")
    library = FakeTypeLibrary(name="libc", named_types={"open": FakeType("open")})
    path = _library_on_disk(tmp_path, library)
    view = FakeBinaryView()
    _, import_tool = get_tool("rex_type_library_import")
    # "bogus" is absent from the library, yet the view-level import still hands back an
    # NTR for it: only the library-level check keeps it out of the imported list.
    result = import_tool(_call(view), path, ["bogus"])
    assert result == {
        "library": "libc",
        "imported": [],
        "failed": [{"requested": "bogus", "reason": "not provided by this type library"}],
        "applied": 0,
        "failed_count": 1,
        "total": 1,
    }
    assert view.imported_library_types == []


def test_type_library_import_reports_a_failed_core_insertion(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(tools, "_EXPORT_ROOT", tmp_path / "exports")
    # The library provides "open", but the core-side insertion returns no handle.
    library = FakeTypeLibrary(name="libc", named_types={"open": FakeType("open")})
    path = _library_on_disk(tmp_path, library)
    view = FakeBinaryView(library_types={"open": None})
    _, import_tool = get_tool("rex_type_library_import")
    result = import_tool(_call(view), path, ["open"])
    assert result == {
        "library": "libc",
        "imported": [],
        "failed": [{"requested": "open", "reason": "not provided by this type library"}],
        "applied": 0,
        "failed_count": 1,
        "total": 1,
    }
    assert view.imported_library_types == [(library, "open")]


def test_type_library_import_reports_an_unnamed_library(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _library_on_disk(tmp_path, FakeTypeLibrary(name=None, named_types={"open": FakeType("open")}))
    view = FakeBinaryView(library_types={"open": "open"})
    _, import_tool = get_tool("rex_type_library_import")
    result = import_tool(_call(view), str(tmp_path / "libc.bntl"), ["open"])
    assert result["library"] is None
    assert result["imported"] == [{"requested": "open", "resolved": "open"}]


def test_type_library_import_reports_a_missing_library_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(tools, "_EXPORT_ROOT", tmp_path / "exports")
    view = FakeBinaryView()
    _, import_tool = get_tool("rex_type_library_import")
    with pytest.raises(FakeToolError) as exc:
        import_tool(_call(view), str(tmp_path / "absent.bntl"), ["open"])
    assert exc.value.code == "library_not_found"
    # A path short enough to echo whole is echoed whole.
    assert exc.value.message == (f"could not load a type library from '{tmp_path / 'absent.bntl'}'")


def test_type_library_import_rejects_bad_names_lists(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(tools, "_EXPORT_ROOT", tmp_path / "exports")
    _library_on_disk(tmp_path, FakeTypeLibrary(name="libc"))
    view = FakeBinaryView()
    _, import_tool = get_tool("rex_type_library_import")
    long_name = "x" * (types._MAX_TYPE_NAME_CHARS + 1)
    for names, message in (
        ("open", "names must be a list of type names"),
        ([], f"names must contain between 1 and {types._MAX_TYPE_LIBRARY_NAMES} entries"),
        (
            ["a"] * (types._MAX_TYPE_LIBRARY_NAMES + 1),
            f"names must contain between 1 and {types._MAX_TYPE_LIBRARY_NAMES} entries",
        ),
        ([1], "names[0] must be a string type name"),
        ([""], "names[0] must not be empty"),
        ([long_name], f"names[0] exceeds {types._MAX_TYPE_NAME_CHARS} characters"),
    ):
        with pytest.raises(FakeToolError) as exc:
            import_tool(_call(view), "/nowhere.bntl", names)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == message
    # Exactly at both caps — 64 entries of exactly 255 characters each — the list is
    # accepted: the library loads, attaches, and every name reports as not provided.
    at_cap = ["n" * types._MAX_TYPE_NAME_CHARS] * types._MAX_TYPE_LIBRARY_NAMES
    at_cap_result = import_tool(_call(view), str(tmp_path / "libc.bntl"), at_cap)
    assert at_cap_result["total"] == types._MAX_TYPE_LIBRARY_NAMES
    assert len(at_cap_result["failed"]) == types._MAX_TYPE_LIBRARY_NAMES


# --- rex_type_library_export ----------------------------------------------------------------


def _typed_view() -> FakeBinaryView:
    return FakeBinaryView(
        arch=FakeArchitecture("x86_64"),
        types={
            "open": FakeType("open", "int open(char *path, int flags)"),
            "color": FakeType("color", "enum color { RED, GREEN }"),
        },
    )


def test_type_library_export_writes_types_to_a_bntl(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _use_export_root(monkeypatch, tmp_path)
    view = _typed_view()
    _, export = get_tool("rex_type_library_export")
    result = export(_call(view), "recovered", ["open", "color"], filename="recovered.bntl")
    assert result == {
        "path": str((root / "recovered.bntl").resolve()),
        "bytes_written": 4,
        "library": "recovered",
        "exported": ["open", "color"],
        "failed": [],
        "applied": 2,
        "failed_count": 0,
        "total": 2,
    }
    # The file holds exactly the bytes the (fake) core wrote, in the export root.
    assert (root / "recovered.bntl").read_bytes() == b"BNTL"
    library = view.exported_types[0][0]
    assert library.name == "recovered"
    assert library.arch is not None and library.arch.name == "x86_64"
    assert library.finalized is True
    assert [(name, type_obj) for _, name, type_obj in view.exported_types] == [
        ("open", view._types["open"]),
        ("color", view._types["color"]),
    ]


def test_type_library_export_objects_routes_through_the_object_exporter(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _use_export_root(monkeypatch, tmp_path)
    view = _typed_view()
    _, export = get_tool("rex_type_library_export")
    result = export(_call(view), "recovered", ["open"], kind="objects", filename="objs.bntl")
    assert result["exported"] == ["open"]
    assert view.exported_objects == [(view.exported_objects[0][0], "open", view._types["open"])]
    assert view.exported_types == []


def test_type_library_export_reports_missing_types(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _use_export_root(monkeypatch, tmp_path)
    view = _typed_view()
    _, export = get_tool("rex_type_library_export")
    result = export(_call(view), "recovered", ["color", "absent"], filename="mixed.bntl")
    assert result["exported"] == ["color"]
    assert result["failed"] == [
        {"requested": "absent", "reason": "no type with this name in the view"}
    ]
    assert result["applied"] == 1
    assert result["failed_count"] == 1
    assert result["total"] == 2
    assert [name for _, name, _ in view.exported_types] == ["color"]


def test_type_library_export_requires_an_architecture() -> None:
    _, export = get_tool("rex_type_library_export")
    with pytest.raises(FakeToolError) as exc:
        export(_call(FakeBinaryView()), "recovered", ["open"], filename="x.bntl")
    assert exc.value.code == "no_arch"
    assert exc.value.message == ("the binary view has no architecture to create a type library for")


def test_type_library_export_reports_finalize_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _use_export_root(monkeypatch, tmp_path)
    broken = FakeTypeLibrary(finalize_result=False)
    monkeypatch.setattr(FakeTypeLibrary, "new", staticmethod(lambda arch, name: broken))
    view = FakeBinaryView(arch=FakeArchitecture("x86_64"), types={"open": FakeType("open")})
    _, export = get_tool("rex_type_library_export")
    with pytest.raises(FakeToolError) as exc:
        export(_call(view), "recovered", ["open"], filename="x.bntl")
    assert exc.value.code == "finalize_failed"
    assert exc.value.message == "could not finalize type library 'recovered'"
    assert broken.written_paths == []


def test_type_library_export_reports_write_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _use_export_root(monkeypatch, tmp_path)
    broken = FakeTypeLibrary(write_error=OSError("disk full"))
    monkeypatch.setattr(FakeTypeLibrary, "new", staticmethod(lambda arch, name: broken))
    view = FakeBinaryView(arch=FakeArchitecture("x86_64"), types={"open": FakeType("open")})
    _, export = get_tool("rex_type_library_export")
    with pytest.raises(FakeToolError) as exc:
        export(_call(view), "recovered", ["open"], filename="broken.bntl")
    assert exc.value.code == "export_failed"
    assert exc.value.message == "could not write export file: disk full"


def test_type_library_export_enforces_the_byte_cap(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _use_export_root(monkeypatch, tmp_path)
    blob = b"\x00" * 100
    library = FakeTypeLibrary(file_bytes=blob)
    monkeypatch.setattr(FakeTypeLibrary, "new", staticmethod(lambda arch, name: library))
    view = FakeBinaryView(arch=FakeArchitecture("x86_64"), types={"open": FakeType("open")})
    _, export = get_tool("rex_type_library_export")
    # Exactly at the cap the file stays: the boundary is inclusive.
    monkeypatch.setattr(types, "_MAX_EXPORT_FILE_BYTES", 100)
    result = export(_call(view), "recovered", ["open"], filename="exact.bntl")
    assert result["bytes_written"] == 100
    assert (root / "exact.bntl").read_bytes() == blob
    # One byte over the cap and the file is removed, not left behind oversized.
    monkeypatch.setattr(types, "_MAX_EXPORT_FILE_BYTES", 99)
    with pytest.raises(FakeToolError) as exc:
        export(_call(view), "recovered", ["open"], filename="huge.bntl")
    assert exc.value.code == "export_failed"
    assert exc.value.message == (
        f"type library file exceeds the {types._MAX_EXPORT_FILE_BYTES} byte export cap"
    )
    assert not (root / "huge.bntl").exists()


def test_type_library_export_rejects_invalid_inputs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _use_export_root(monkeypatch, tmp_path)
    view = _typed_view()
    _, export = get_tool("rex_type_library_export")
    for violation, message, code in (
        ({"library_name": ""}, "library_name must not be empty", "invalid_params"),
        (
            {"library_name": "x" * (types._MAX_TYPE_NAME_CHARS + 1)},
            f"library_name exceeds {types._MAX_TYPE_NAME_CHARS} characters",
            "library_name_too_large",
        ),
        ({"kind": "bogus"}, "kind must be 'types' or 'objects', not 'bogus'", "invalid_params"),
        (
            {"filename": "/abs/path.bntl"},
            "filename must be a plain file name, not an absolute path",
            "invalid_params",
        ),
        ({"filename": ""}, "filename must not be empty", "invalid_params"),
    ):
        arguments = {"library_name": "recovered", "filename": "x.bntl", **violation}
        with pytest.raises(FakeToolError) as exc:
            export(_call(view), arguments.pop("library_name"), ["open"], **arguments)
        assert exc.value.code == code
        assert exc.value.message == message
    # Validation happens before the library is created: nothing was attached or exported.
    assert view.exported_types == []


# --- rex_struct_from_access ------------------------------------------------------------------


def _struct_view(members: list[FakeStructureMember], width: int) -> FakeBinaryView:
    return FakeBinaryView(structure=FakeStructureType(members, width))


def test_struct_from_access_creates_and_defines_the_struct() -> None:
    members = [
        FakeStructureMember("field_0", 0, FakeType("field_0", "int32_t")),
        FakeStructureMember("ptr", 8, FakeType("ptr", "void *")),
    ]
    view = _struct_view(members, width=16)
    _, create = get_tool("rex_struct_from_access")
    result = create(_call(view), "ctx")
    assert result == {
        "name": "ctx",
        "registered": "ctx",
        "width": 16,
        "member_count": 2,
        "members": [
            {"offset": 0, "name": "field_0", "type": "int32_t"},
            {"offset": 8, "name": "ptr", "type": "void *"},
        ],
        "truncated": False,
    }
    # The struct is defined in the view under an auto type id derived from this tool's
    # source marker and the requested name.
    assert view.defined_types == [("auto:rex_struct:ctx", "ctx", view._structure)]


def test_struct_from_access_reports_a_deconflicted_registered_name() -> None:
    view = FakeBinaryView(
        structure=FakeStructureType([], 0),
        defined_type_name="ctx_0",
    )
    _, create = get_tool("rex_struct_from_access")
    result = create(_call(view), "ctx")
    assert result["registered"] == "ctx_0"
    assert result["member_count"] == 0


def test_struct_from_access_caps_the_echoed_members() -> None:
    exact = [
        FakeStructureMember(f"field_{offset}", offset, FakeType(f"field_{offset}"))
        for offset in range(types._MAX_STRUCT_MEMBERS)
    ]
    view = _struct_view(exact, width=types._MAX_STRUCT_MEMBERS)
    _, create = get_tool("rex_struct_from_access")
    at_cap = create(_call(view), "ctx")
    assert at_cap["member_count"] == types._MAX_STRUCT_MEMBERS
    assert len(at_cap["members"]) == types._MAX_STRUCT_MEMBERS
    assert at_cap["truncated"] is False

    one_more = exact + [FakeStructureMember("last", types._MAX_STRUCT_MEMBERS, FakeType("last"))]
    over = create(_call(_struct_view(one_more, width=200)), "ctx")
    assert over["member_count"] == types._MAX_STRUCT_MEMBERS + 1
    assert len(over["members"]) == types._MAX_STRUCT_MEMBERS
    assert over["truncated"] is True


def test_struct_from_access_reports_the_core_refusal() -> None:
    view = FakeBinaryView()
    _, create = get_tool("rex_struct_from_access")
    with pytest.raises(FakeToolError) as exc:
        create(_call(view), "ctx")
    assert exc.value.code == "create_failed"
    assert exc.value.message == (
        "could not create a structure from offset accesses: "
        "BNCreateStructureFromOffsetAccess failed to create struct from offsets"
    )
    assert view.defined_types == []


def test_struct_from_access_rejects_bad_names() -> None:
    view = FakeBinaryView()
    _, create = get_tool("rex_struct_from_access")
    for name, message, code in (
        ("", "name must not be empty", "invalid_params"),
        (
            "x" * (types._MAX_TYPE_NAME_CHARS + 1),
            f"name exceeds {types._MAX_TYPE_NAME_CHARS} characters",
            "name_too_large",
        ),
    ):
        with pytest.raises(FakeToolError) as exc:
            create(_call(view), name)
        assert exc.value.code == code
        assert exc.value.message == message
    # Exactly at the cap the name is accepted (with the fake struct in place).
    view_at_cap = _struct_view([], 0)
    at_cap = create(_call(view_at_cap), "x" * types._MAX_TYPE_NAME_CHARS)
    assert at_cap["name"] == "x" * types._MAX_TYPE_NAME_CHARS
