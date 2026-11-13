from __future__ import annotations

from pathlib import Path

import pytest
from helpers import (
    DIRECTORY_NAME_MESSAGE,
    FakeNamedTypeReference,
    FakeToolError,
    _call,
    _use_export_root,
    get_tool,
)
from helpers_types import FakeStructureVariant
from helpers_view import (
    TYPE_LIBRARIES_ON_DISK,
    FakeArchitecture,
    FakeBinaryView,
    FakeFunction,
    FakeStructureMember,
    FakeStructureType,
    FakeSymbol,
    FakeType,
    FakeTypeClass,
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
    assert exc.value.message == (
        f"could not load a type library from '{tmp_path / 'absent.bntl'}'; "
        "pass the path of a .bntl file, such as one rex_type_library_export wrote"
    )


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


def _objects_library(tmp_path: Path) -> tuple[FakeTypeLibrary, str]:
    library = FakeTypeLibrary(
        name="libc",
        named_types={"stat_t": FakeType("stat_t", "struct stat_t")},
        named_objects={"open": FakeType("open", "int32_t(char const* path, int32_t flags)")},
    )
    return library, _library_on_disk(tmp_path, library)


def test_type_library_import_objects_imports_named_objects(tmp_path: Path) -> None:
    library, path = _objects_library(tmp_path)
    view = FakeBinaryView()
    _, import_tool = get_tool("rex_type_library_import")
    # "stat_t" is only a named type, so the objects import does not find it.
    result = import_tool(_call(view), path, ["open", "stat_t"], kind="objects")
    assert result == {
        "library": "libc",
        "imported": [{"requested": "open", "type": "int32_t(char const* path, int32_t flags)"}],
        "failed": [{"requested": "stat_t", "reason": "not provided by this type library"}],
        "applied": 1,
        "failed_count": 1,
        "total": 2,
    }
    assert view.type_libraries == [library]
    assert view.imported_library_objects == [(library, "open")]
    assert view.imported_library_types == []


def test_type_library_import_types_ignores_named_objects(tmp_path: Path) -> None:
    library, path = _objects_library(tmp_path)
    view = FakeBinaryView(library_types={"stat_t": "stat_t"})
    _, import_tool = get_tool("rex_type_library_import")
    result = import_tool(_call(view), path, ["open", "stat_t"], kind="types")
    assert result["imported"] == [{"requested": "stat_t", "resolved": "stat_t"}]
    assert result["failed"] == [
        {"requested": "open", "reason": "not provided by this type library"}
    ]
    assert view.imported_library_types == [(library, "stat_t")]
    assert view.imported_library_objects == []


def test_type_library_import_objects_reports_a_failed_core_import(tmp_path: Path) -> None:
    library, path = _objects_library(tmp_path)
    view = FakeBinaryView()
    view.refused_library_objects = frozenset({"open"})
    _, import_tool = get_tool("rex_type_library_import")
    result = import_tool(_call(view), path, ["open"], kind="objects")
    assert result["imported"] == []
    assert result["failed"] == [
        {"requested": "open", "reason": "the core could not import this object"}
    ]
    assert view.imported_library_objects == [(library, "open")]


@pytest.mark.parametrize(
    ("type_string", "reported"),
    [
        ("t" * 512, "t" * 512),
        ("t" * 513, "t" * 512 + "... [1 chars truncated]"),
    ],
)
def test_type_library_import_objects_bounds_the_reported_type_string(
    tmp_path: Path, type_string: str, reported: str
) -> None:
    library = FakeTypeLibrary(name="libc", named_objects={"wide": FakeType("wide", type_string)})
    path = _library_on_disk(tmp_path, library)
    _, import_tool = get_tool("rex_type_library_import")
    result = import_tool(_call(FakeBinaryView()), path, ["wide"], kind="objects")
    assert result["imported"] == [{"requested": "wide", "type": reported}]


def test_type_library_import_rejects_an_unknown_kind(tmp_path: Path) -> None:
    _, path = _objects_library(tmp_path)
    view = FakeBinaryView()
    _, import_tool = get_tool("rex_type_library_import")
    for kind, shown in (
        ("bogus", "bogus"),
        ("Objects", "Objects"),
        ("t\x00", "t\N{REPLACEMENT CHARACTER}"),
    ):
        with pytest.raises(FakeToolError) as exc:
            import_tool(_call(view), path, ["open"], kind=kind)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == f"kind must be 'types' or 'objects', not '{shown}'"
    assert view.type_libraries == []


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
        "exported": [
            {"name": "open", "type": "int open(char *path, int flags)"},
            {"name": "color", "type": "enum color { RED, GREEN }"},
        ],
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


def test_type_library_export_objects_exports_a_function_by_its_own_type(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _use_export_root(monkeypatch, tmp_path)
    function = FakeFunction("open", 0x1000, 0x1010)
    function.type = FakeType("open_fn", "int open(char *path, int flags)")
    view = FakeBinaryView(
        arch=FakeArchitecture("x86_64"),
        functions=[function],
        types={"open": FakeType("open", "struct open_flags")},
    )
    _, export = get_tool("rex_type_library_export")
    result = export(_call(view), "recovered", ["open"], kind="objects", filename="objs.bntl")
    assert result["exported"] == [
        {
            "name": "open",
            "type": "int open(char *path, int flags)",
            "address": "0x1000",
            "alternatives": [],
        }
    ]
    assert result["failed"] == []
    assert view.exported_objects == [(view.exported_objects[0][0], "open", function.type)]
    assert view.exported_types == []


def test_type_library_export_objects_exports_a_data_variable_by_its_own_type(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _use_export_root(monkeypatch, tmp_path)
    table_type = FakeType("table_t", "int32_t[4]")
    view = FakeBinaryView(
        arch=FakeArchitecture("x86_64"),
        symbols=[FakeSymbol(0x4000, "DataSymbol", "g_table")],
    )
    view.data_variable_types = {0x4000: table_type}
    _, export = get_tool("rex_type_library_export")
    result = export(_call(view), "recovered", ["g_table"], kind="objects", filename="objs.bntl")
    assert result["exported"] == [
        {"name": "g_table", "type": "int32_t[4]", "address": "0x4000", "alternatives": []}
    ]
    assert view.exported_objects == [(view.exported_objects[0][0], "g_table", table_type)]


def _void_object_view() -> FakeBinaryView:
    view = FakeBinaryView(
        arch=FakeArchitecture("x86_64"),
        symbols=[
            FakeSymbol(0x40031C, "DataSymbol", "__elf_interp"),
            FakeSymbol(0x4000, "DataSymbol", "g_table"),
        ],
    )
    view.data_variable_types = {
        0x40031C: FakeType("void", "void", type_class=FakeTypeClass.VoidTypeClass),
        0x4000: FakeType("table_t", "int32_t[4]"),
    }
    return view


def test_type_library_export_objects_exports_a_void_data_variable_and_reports_void(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _use_export_root(monkeypatch, tmp_path)
    view = _void_object_view()
    _, export = get_tool("rex_type_library_export")
    result = export(_call(view), "recovered", ["__elf_interp"], kind="objects", filename="v.bntl")
    assert result == {
        "path": str((root / "v.bntl").resolve()),
        "bytes_written": 4,
        "library": "recovered",
        "exported": [
            {"name": "__elf_interp", "type": "void", "address": "0x40031c", "alternatives": []}
        ],
        "failed": [],
        "applied": 1,
        "failed_count": 0,
        "total": 1,
    }
    assert [(name, str(type_obj)) for _, name, type_obj in view.exported_objects] == [
        ("__elf_interp", "void")
    ]


def test_type_library_export_objects_tells_void_apart_from_typed_objects_in_one_batch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _use_export_root(monkeypatch, tmp_path)
    _, export = get_tool("rex_type_library_export")
    result = export(
        _call(_void_object_view()),
        "recovered",
        ["g_table", "absent", "__elf_interp"],
        kind="objects",
        filename="v.bntl",
    )
    assert result["exported"] == [
        {"name": "g_table", "type": "int32_t[4]", "address": "0x4000", "alternatives": []},
        {"name": "__elf_interp", "type": "void", "address": "0x40031c", "alternatives": []},
    ]
    assert result["failed"] == [
        {"requested": "absent", "reason": "no function or data variable with this name in the view"}
    ]
    assert (result["applied"], result["failed_count"], result["total"]) == (2, 1, 3)


def _objects_view(
    *,
    functions: list[FakeFunction] | None = None,
    symbols: list[FakeSymbol] | None = None,
    data_variable_types: dict[int, FakeType] | None = None,
) -> FakeBinaryView:
    view = FakeBinaryView(
        arch=FakeArchitecture("x86_64"), functions=functions or [], symbols=symbols or []
    )
    view.data_variable_types = data_variable_types or {}
    return view


def _function(name: str, start: int, type_string: str) -> FakeFunction:
    function = FakeFunction(name, start, start + 0x10)
    function.type = FakeType(
        f"{name}_{start:x}", type_string, type_class=FakeTypeClass.FunctionTypeClass
    )
    return function


def _export_objects(view: FakeBinaryView, *names: str):
    _, export = get_tool("rex_type_library_export")
    return export(_call(view), "recovered", list(names), kind="objects", filename="objs.bntl")


def test_type_library_export_objects_prefers_the_function_and_lists_data_variables(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _use_export_root(monkeypatch, tmp_path)
    function = _function("setlocale", 0x40ABB0, "char* setlocale(int32_t category)")
    pointer = FakeType(
        "ptr", "char* (* const)(int32_t category)", type_class=FakeTypeClass.PointerTypeClass
    )
    external = FakeType(
        "ext", "char*(int32_t category)", type_class=FakeTypeClass.FunctionTypeClass
    )
    view = _objects_view(
        functions=[function],
        symbols=[
            FakeSymbol(0x426828, "ExternalSymbol", "setlocale"),
            FakeSymbol(0x40ABB0, "ImportedFunctionSymbol", "setlocale"),
            FakeSymbol(0x424E98, "ImportAddressSymbol", "setlocale"),
        ],
        data_variable_types={0x424E98: pointer, 0x426828: external},
    )
    result = _export_objects(view, "setlocale")
    assert result["exported"] == [
        {
            "name": "setlocale",
            "type": "char* setlocale(int32_t category)",
            "address": "0x40abb0",
            "alternatives": [
                {"address": "0x426828", "type": "char*(int32_t category)"},
                {"address": "0x424e98", "type": "char* (* const)(int32_t category)"},
            ],
        }
    ]
    assert [(name, type_obj) for _, name, type_obj in view.exported_objects] == [
        ("setlocale", function.type)
    ]


def test_type_library_export_objects_prefers_the_extern_object_over_its_import_slot(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _use_export_root(monkeypatch, tmp_path)
    slot = FakeType("slot", "int64_t (* const)()", type_class=FakeTypeClass.PointerTypeClass)
    extern = FakeType("extern", "void", type_class=FakeTypeClass.VoidTypeClass)
    view = _objects_view(
        symbols=[
            FakeSymbol(0x424F80, "ImportAddressSymbol", "stdout"),
            FakeSymbol(0x426880, "ExternalSymbol", "stdout"),
        ],
        data_variable_types={0x424F80: slot, 0x426880: extern},
    )
    result = _export_objects(view, "stdout")
    assert result["exported"] == [
        {
            "name": "stdout",
            "type": "void",
            "address": "0x426880",
            "alternatives": [{"address": "0x424f80", "type": "int64_t (* const)()"}],
        }
    ]
    assert [(name, type_obj) for _, name, type_obj in view.exported_objects] == [("stdout", extern)]


def test_type_library_export_objects_exports_the_import_slot_when_it_is_the_only_object(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _use_export_root(monkeypatch, tmp_path)
    slot = FakeType("slot", "int64_t (* const)()", type_class=FakeTypeClass.PointerTypeClass)
    view = _objects_view(
        symbols=[FakeSymbol(0x424F80, "ImportAddressSymbol", "stdout")],
        data_variable_types={0x424F80: slot},
    )
    result = _export_objects(view, "stdout")
    assert result["exported"] == [
        {"name": "stdout", "type": "int64_t (* const)()", "address": "0x424f80", "alternatives": []}
    ]


@pytest.mark.parametrize("symbol_type", ["DataSymbol", "ExternalSymbol", "ImportedDataSymbol"])
def test_type_library_export_objects_prefers_a_typed_object_over_a_lower_import_slot(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, symbol_type: str
) -> None:
    _use_export_root(monkeypatch, tmp_path)
    view = _objects_view(
        symbols=[
            FakeSymbol(0x1000, "ImportAddressSymbol", "environ"),
            FakeSymbol(0x2000, symbol_type, "environ"),
        ],
        data_variable_types={
            0x1000: FakeType(
                "slot", "int64_t (* const)()", type_class=FakeTypeClass.PointerTypeClass
            ),
            0x2000: FakeType("env", "char**", type_class=FakeTypeClass.PointerTypeClass),
        },
    )
    result = _export_objects(view, "environ")
    assert result["exported"] == [
        {
            "name": "environ",
            "type": "char**",
            "address": "0x2000",
            "alternatives": [{"address": "0x1000", "type": "int64_t (* const)()"}],
        }
    ]


def test_type_library_export_objects_treats_an_address_with_an_import_symbol_as_a_slot(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _use_export_root(monkeypatch, tmp_path)
    view = _objects_view(
        symbols=[
            FakeSymbol(0x1000, "DataSymbol", "environ"),
            FakeSymbol(0x1000, "ImportAddressSymbol", "environ"),
            FakeSymbol(0x2000, "DataSymbol", "environ"),
        ],
        data_variable_types={0x1000: FakeType("a", "int8_t"), 0x2000: FakeType("b", "char**")},
    )
    [entry] = _export_objects(view, "environ")["exported"]
    assert (entry["address"], entry["alternatives"]) == (
        "0x2000",
        [{"address": "0x1000", "type": "int8_t"}],
    )


def test_type_library_export_objects_picks_the_lowest_function_and_lists_the_others(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _use_export_root(monkeypatch, tmp_path)
    view = _objects_view(
        functions=[
            _function("_start", 0x40D5D0, "void _start(int64_t arg1)"),
            _function("_start", 0x40D5B0, "void _start()"),
            _function("_start", 0x40D5C0, "void _start(int64_t arg1, int64_t arg2)"),
        ]
    )
    result = _export_objects(view, "_start")
    assert result["exported"] == [
        {
            "name": "_start",
            "type": "void _start()",
            "address": "0x40d5b0",
            "alternatives": [
                {"address": "0x40d5c0", "type": "void _start(int64_t arg1, int64_t arg2)"},
                {"address": "0x40d5d0", "type": "void _start(int64_t arg1)"},
            ],
        }
    ]


def test_type_library_export_objects_prefers_a_non_void_data_variable_over_a_void_one(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _use_export_root(monkeypatch, tmp_path)
    void = FakeType("void", "void", type_class=FakeTypeClass.VoidTypeClass)
    interp = FakeType("interp", "char[0x1c]", type_class=FakeTypeClass.ArrayTypeClass)
    view = _objects_view(
        symbols=[
            FakeSymbol(0x40031C, "DataSymbol", "__elf_interp"),
            FakeSymbol(0x40033C, "DataSymbol", "__elf_interp"),
        ],
        data_variable_types={0x40031C: void, 0x40033C: interp},
    )
    result = _export_objects(view, "__elf_interp")
    assert result["exported"] == [
        {
            "name": "__elf_interp",
            "type": "char[0x1c]",
            "address": "0x40033c",
            "alternatives": [{"address": "0x40031c", "type": "void"}],
        }
    ]
    assert [(name, type_obj) for _, name, type_obj in view.exported_objects] == [
        ("__elf_interp", interp)
    ]


def test_type_library_export_objects_prefers_non_void_whatever_the_symbol_order(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _use_export_root(monkeypatch, tmp_path)
    view = _objects_view(
        symbols=[
            FakeSymbol(0x40033C, "DataSymbol", "__elf_interp"),
            FakeSymbol(0x40031C, "DataSymbol", "__elf_interp"),
        ],
        data_variable_types={
            0x40031C: FakeType("void", "void", type_class=FakeTypeClass.VoidTypeClass),
            0x40033C: FakeType("interp", "char[0x1c]", type_class=FakeTypeClass.ArrayTypeClass),
        },
    )
    entry = _export_objects(view, "__elf_interp")["exported"][0]
    assert (entry["type"], entry["address"]) == ("char[0x1c]", "0x40033c")


def test_type_library_export_objects_exports_visibly_void_when_only_void_exists(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _use_export_root(monkeypatch, tmp_path)
    void = FakeType("void", "void", type_class=FakeTypeClass.VoidTypeClass)
    view = _objects_view(
        symbols=[
            FakeSymbol(0x40032C, "DataSymbol", "__elf_interp"),
            FakeSymbol(0x40031C, "DataSymbol", "__elf_interp"),
        ],
        data_variable_types={0x40031C: void, 0x40032C: void},
    )
    result = _export_objects(view, "__elf_interp")
    assert result["exported"] == [
        {
            "name": "__elf_interp",
            "type": "void",
            "address": "0x40031c",
            "alternatives": [{"address": "0x40032c", "type": "void"}],
        }
    ]
    assert result["failed"] == []


def test_type_library_export_objects_picks_the_lowest_address_among_non_void_variables(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _use_export_root(monkeypatch, tmp_path)
    view = _objects_view(
        symbols=[
            FakeSymbol(0x3000, "DataSymbol", "g_value"),
            FakeSymbol(0x1000, "DataSymbol", "g_value"),
            FakeSymbol(0x2000, "DataSymbol", "g_value"),
            FakeSymbol(0x1800, "DataSymbol", "g_other"),
        ],
        data_variable_types={
            0x3000: FakeType("c", "int64_t", type_class=FakeTypeClass.IntegerTypeClass),
            0x1000: FakeType("a", "int32_t", type_class=FakeTypeClass.IntegerTypeClass),
            0x2000: FakeType("b", "char[4]", type_class=FakeTypeClass.ArrayTypeClass),
            0x1800: FakeType("o", "int8_t", type_class=FakeTypeClass.IntegerTypeClass),
        },
    )
    result = _export_objects(view, "g_value")
    assert result["exported"] == [
        {
            "name": "g_value",
            "type": "int32_t",
            "address": "0x1000",
            "alternatives": [
                {"address": "0x2000", "type": "char[4]"},
                {"address": "0x3000", "type": "int64_t"},
            ],
        }
    ]


def test_type_library_export_objects_lists_the_ranked_alternatives_by_preference(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _use_export_root(monkeypatch, tmp_path)
    view = _objects_view(
        functions=[_function("f", 0x9000, "void f()")],
        symbols=[
            FakeSymbol(0x1000, "DataSymbol", "f"),
            FakeSymbol(0x2000, "DataSymbol", "f"),
            FakeSymbol(0x3000, "DataSymbol", "f"),
            FakeSymbol(0x0500, "ImportAddressSymbol", "f"),
        ],
        data_variable_types={
            0x0500: FakeType("s", "int64_t (* const)()", type_class=FakeTypeClass.PointerTypeClass),
            0x1000: FakeType("v", "void", type_class=FakeTypeClass.VoidTypeClass),
            0x2000: FakeType("i", "int32_t", type_class=FakeTypeClass.IntegerTypeClass),
            0x3000: FakeType("j", "int64_t", type_class=FakeTypeClass.IntegerTypeClass),
        },
    )
    entry = _export_objects(view, "f")["exported"][0]
    assert entry["address"] == "0x9000"
    assert [alternative["address"] for alternative in entry["alternatives"]] == [
        "0x2000",
        "0x3000",
        "0x1000",
        "0x500",
    ]


def test_type_library_export_objects_counts_symbols_sharing_an_address_once(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _use_export_root(monkeypatch, tmp_path)
    view = _objects_view(
        symbols=[
            FakeSymbol(0x4000, "DataSymbol", "g_table"),
            FakeSymbol(0x4000, "ImportAddressSymbol", "g_table"),
        ],
        data_variable_types={0x4000: FakeType("t", "int32_t[4]")},
    )
    entry = _export_objects(view, "g_table")["exported"][0]
    assert entry["alternatives"] == []


def test_type_library_export_objects_ignores_symbols_without_a_data_variable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _use_export_root(monkeypatch, tmp_path)
    view = _objects_view(
        symbols=[
            FakeSymbol(0x5000, "DataSymbol", "g_table"),
            FakeSymbol(0x4000, "DataSymbol", "g_table"),
        ],
        data_variable_types={0x4000: FakeType("t", "int32_t[4]")},
    )
    entry = _export_objects(view, "g_table")["exported"][0]
    assert (entry["address"], entry["alternatives"]) == ("0x4000", [])


def test_type_library_export_objects_chooses_per_name_in_one_batch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _use_export_root(monkeypatch, tmp_path)
    view = _objects_view(
        functions=[_function("open", 0x1000, "int open()")],
        symbols=[
            FakeSymbol(0x4000, "DataSymbol", "g_table"),
            FakeSymbol(0x4100, "DataSymbol", "g_table"),
        ],
        data_variable_types={0x4000: FakeType("t", "int32_t[4]"), 0x4100: FakeType("u", "int8_t")},
    )
    result = _export_objects(view, "g_table", "missing", "open")
    assert [(entry["name"], entry["address"]) for entry in result["exported"]] == [
        ("g_table", "0x4000"),
        ("open", "0x1000"),
    ]
    assert result["failed"] == [
        {
            "requested": "missing",
            "reason": "no function or data variable with this name in the view",
        }
    ]
    assert [name for _, name, _ in view.exported_objects] == ["g_table", "open"]


@pytest.mark.parametrize(
    ("type_string", "reported"),
    [
        ("t" * 512, "t" * 512),
        ("t" * 513, "t" * 512 + "... [1 chars truncated]"),
    ],
)
def test_type_library_export_objects_bounds_the_alternative_type_strings(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, type_string: str, reported: str
) -> None:
    _use_export_root(monkeypatch, tmp_path)
    view = _objects_view(
        symbols=[
            FakeSymbol(0x1000, "DataSymbol", "g_value"),
            FakeSymbol(0x2000, "DataSymbol", "g_value"),
        ],
        data_variable_types={0x1000: FakeType("a", "int32_t"), 0x2000: FakeType("b", type_string)},
    )
    entry = _export_objects(view, "g_value")["exported"][0]
    assert entry["alternatives"] == [{"address": "0x2000", "type": reported}]


def test_type_library_export_types_entries_carry_only_name_and_type(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _use_export_root(monkeypatch, tmp_path)
    _, export = get_tool("rex_type_library_export")
    result = export(_call(_typed_view()), "recovered", ["open"], filename="t.bntl")
    assert result["exported"] == [{"name": "open", "type": "int open(char *path, int flags)"}]


@pytest.mark.parametrize(
    ("type_string", "reported"),
    [
        ("t" * 512, "t" * 512),
        ("t" * 513, "t" * 512 + "... [1 chars truncated]"),
    ],
)
def test_type_library_export_bounds_the_reported_type_string(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, type_string: str, reported: str
) -> None:
    _use_export_root(monkeypatch, tmp_path)
    view = FakeBinaryView(
        arch=FakeArchitecture("x86_64"), types={"wide": FakeType("wide", type_string)}
    )
    _, export = get_tool("rex_type_library_export")
    result = export(_call(view), "recovered", ["wide"], filename="w.bntl")
    assert result["exported"] == [{"name": "wide", "type": reported}]


def test_type_library_export_objects_fails_a_name_that_is_only_a_type(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _use_export_root(monkeypatch, tmp_path)
    view = _typed_view()
    _, export = get_tool("rex_type_library_export")
    result = export(_call(view), "recovered", ["open"], kind="objects", filename="objs.bntl")
    assert result["exported"] == []
    assert result["failed"] == [
        {"requested": "open", "reason": "no function or data variable with this name in the view"}
    ]
    assert view.exported_objects == []


def test_type_library_export_objects_fails_a_symbol_without_a_data_variable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _use_export_root(monkeypatch, tmp_path)
    view = FakeBinaryView(
        arch=FakeArchitecture("x86_64"),
        symbols=[FakeSymbol(0x4000, "DataSymbol", "g_table")],
    )
    _, export = get_tool("rex_type_library_export")
    result = export(_call(view), "recovered", ["g_table"], kind="objects", filename="objs.bntl")
    assert result["exported"] == []
    assert result["failed"] == [
        {
            "requested": "g_table",
            "reason": "no function or data variable with this name in the view",
        }
    ]


def test_type_library_export_types_ignores_functions_of_the_same_name(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _use_export_root(monkeypatch, tmp_path)
    function = FakeFunction("open", 0x1000, 0x1010)
    function.type = FakeType("open_fn", "int open()")
    view = FakeBinaryView(
        arch=FakeArchitecture("x86_64"),
        functions=[function],
        types={"open": FakeType("open", "struct open_flags")},
    )
    _, export = get_tool("rex_type_library_export")
    export(_call(view), "recovered", ["open"], filename="types.bntl")
    assert [type_obj for _, _, type_obj in view.exported_types] == [view._types["open"]]


def test_type_library_export_reports_missing_types(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _use_export_root(monkeypatch, tmp_path)
    view = _typed_view()
    _, export = get_tool("rex_type_library_export")
    result = export(_call(view), "recovered", ["color", "absent"], filename="mixed.bntl")
    assert result["exported"] == [{"name": "color", "type": "enum color { RED, GREEN }"}]
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


def test_type_library_export_reports_a_write_that_produced_no_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _use_export_root(monkeypatch, tmp_path)
    silent = FakeTypeLibrary(writes_file=False)
    monkeypatch.setattr(FakeTypeLibrary, "new", staticmethod(lambda arch, name: silent))
    view = FakeBinaryView(arch=FakeArchitecture("x86_64"), types={"open": FakeType("open")})
    _, export = get_tool("rex_type_library_export")
    with pytest.raises(FakeToolError) as exc:
        export(_call(view), "recovered", ["open"], filename="missing.bntl")
    assert exc.value.code == "export_failed"
    assert exc.value.message == (
        f"could not write export file: [Errno 2] No such file or directory: "
        f"'{root / 'missing.bntl'}'"
    )


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
        f"type library file exceeds the {types._MAX_EXPORT_FILE_BYTES} byte export cap; "
        "export fewer names"
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
        (
            {"filename": "."},
            DIRECTORY_NAME_MESSAGE,
            "invalid_params",
        ),
    ):
        arguments = {"library_name": "recovered", "filename": "x.bntl", **violation}
        with pytest.raises(FakeToolError) as exc:
            export(_call(view), arguments.pop("library_name"), ["open"], **arguments)
        assert exc.value.code == code
        assert exc.value.message == message
    # Validation happens before the library is created: nothing was attached or exported.
    assert view.exported_types == []


# --- rex_struct_from_access ------------------------------------------------------------------


_NEXT_STEP = (
    "apply 'struct {name}*' to a variable that is dereferenced with bn_variable_set_type, "
    "run rex_analysis_wait, then retry"
)


def _struct_view(
    members: list[FakeStructureMember], width: int, name: str = "ctx"
) -> FakeBinaryView:
    return FakeBinaryView(
        types={name: FakeStructureType([], 0)}, structure=FakeStructureType(members, width)
    )


def test_struct_from_access_redefines_the_existing_type_in_place() -> None:
    members = [
        FakeStructureMember("field_0", 0, FakeType("field_0", "int32_t")),
        FakeStructureMember("ptr", 8, FakeType("ptr", "void *")),
    ]
    view = _struct_view(members, width=16, name="probe_s")
    _, create = get_tool("rex_struct_from_access")
    result = create(_call(view), "probe_s")
    assert result == {
        "name": "probe_s",
        "registered": "probe_s",
        "width": 16,
        "member_count": 2,
        "members": [
            {"offset": 0, "name": "field_0", "type": "int32_t"},
            {"offset": 8, "name": "ptr", "type": "void *"},
        ],
        "truncated": False,
    }
    # The inferred members replace the existing user type under its own name, in one
    # undoable transaction, so code typed 'struct probe_s*' sees them.
    assert view.defined_types == [("probe_s", view._structure)]
    assert view.get_type_by_name("probe_s") is view._structure
    assert view.transactions == ["open", "commit"]


def test_struct_from_access_rejects_a_name_that_is_not_a_type() -> None:
    # With no structure the core would refuse, so reaching it would surface create_failed.
    view = FakeBinaryView()
    _, create = get_tool("rex_struct_from_access")
    with pytest.raises(FakeToolError) as exc:
        create(_call(view), "ctx")
    assert exc.value.code == "type_not_found"
    assert exc.value.message == (
        "no type named 'ctx' in the view; create it as an empty struct with "
        "bn_type_struct_create, then " + _NEXT_STEP.format(name="ctx")
    )
    assert view.defined_types == []


def test_struct_from_access_rejects_a_type_that_is_not_a_structure() -> None:
    view = FakeBinaryView(types={"ctx_t": FakeType("ctx_t", "int32_t")})
    _, create = get_tool("rex_struct_from_access")
    with pytest.raises(FakeToolError) as exc:
        create(_call(view), "ctx_t")
    assert exc.value.code == "not_a_structure"
    assert exc.value.message == "type 'ctx_t' is not a structure; pass the name of a struct type"
    assert view.defined_types == []


def _union() -> FakeStructureType:
    union = FakeStructureType([], 8)
    union.type = FakeStructureVariant.UnionStructureType
    return union


_NOT_PLAIN = "which is not a plain struct; pass the name of a plain struct type"
_LONG_TARGET = "s" * 513


@pytest.mark.parametrize(
    ("target_name", "target", "message"),
    [
        (
            "conn",
            FakeStructureType([], 0),
            "type 'conn_t' is an alias of struct 'conn'; pass 'conn' as name instead",
        ),
        ("conn", _union(), f"type 'conn_t' is an alias of 'conn', {_NOT_PLAIN}"),
        ("conn", FakeType("conn", "int32_t"), f"type 'conn_t' is an alias of 'conn', {_NOT_PLAIN}"),
        ("conn", None, f"type 'conn_t' is an alias of 'conn', {_NOT_PLAIN}"),
        (
            "conn_t",
            None,
            "type 'conn_t' is a named reference to itself, not a struct definition; define it "
            "with bn_type_struct_create, then " + _NEXT_STEP.format(name="conn_t"),
        ),
        (
            _LONG_TARGET,
            FakeStructureType([], 0),
            "type 'conn_t' is an alias of struct '{shown}'; pass '{shown}' as name instead".format(
                shown="s" * 512 + "... [1 chars truncated]"
            ),
        ),
    ],
)
def test_struct_from_access_rejects_an_alias_by_its_target(
    target_name: str, target: FakeType | FakeStructureType | None, message: str
) -> None:
    named: dict[str, FakeType | FakeStructureType] = {
        "conn_t": FakeNamedTypeReference(target_name, f"struct {target_name}")
    }
    if target is not None:
        named[target_name] = target
    view = FakeBinaryView(types=named, structure=FakeStructureType([], 8))
    _, create = get_tool("rex_struct_from_access")
    with pytest.raises(FakeToolError) as exc:
        create(_call(view), "conn_t")
    assert exc.value.code == "not_a_structure"
    assert exc.value.message == message
    assert view.defined_types == []


@pytest.mark.parametrize(
    ("variant", "message"),
    [
        (
            FakeStructureVariant.UnionStructureType,
            "type 'ctx' is a union, and this tool fills plain structs only; "
            "edit the union's members with bn_type_union_modify",
        ),
        (
            FakeStructureVariant.ClassStructureType,
            "type 'ctx' is a class, and this tool fills plain structs only; "
            "edit the class's members with bn_type_struct_modify",
        ),
    ],
)
def test_struct_from_access_rejects_a_union_or_class(
    variant: FakeStructureVariant, message: str
) -> None:
    existing = FakeStructureType([], 0)
    existing.type = variant
    view = FakeBinaryView(types={"ctx": existing}, structure=FakeStructureType([], 8))
    _, create = get_tool("rex_struct_from_access")
    with pytest.raises(FakeToolError) as exc:
        create(_call(view), "ctx")
    assert exc.value.code == "not_a_structure"
    assert exc.value.message == message
    assert view.defined_types == []


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


def test_struct_from_access_reports_a_type_without_recorded_accesses() -> None:
    view = FakeBinaryView(types={"ctx": FakeStructureType([], 0)})
    _, create = get_tool("rex_struct_from_access")
    with pytest.raises(FakeToolError) as exc:
        create(_call(view), "ctx")
    assert exc.value.code == "create_failed"
    assert exc.value.message == (
        "analysis has recorded no offset accesses for struct 'ctx' "
        "(BNCreateStructureFromOffsetAccess failed to create struct from offsets); "
        + _NEXT_STEP.format(name="ctx")
    )
    assert view.defined_types == []
    assert view.transactions == []


def test_struct_from_access_writes_only_when_the_inference_changes_the_struct() -> None:
    def member(name: str, type_string: str) -> FakeStructureMember:
        return FakeStructureMember(name, 0, FakeType(name, type_string))

    _, create = get_tool("rex_struct_from_access")
    existing = FakeStructureType([member("field_0", "int32_t")], 8)
    same = FakeStructureType([member("field_0", "int32_t")], 8)
    view = FakeBinaryView(types={"ctx": existing}, structure=same)
    with pytest.raises(FakeToolError) as exc:
        create(_call(view), "ctx")
    assert exc.value.code == "create_failed"
    assert exc.value.message == (
        "analysis has recorded no offset accesses for struct 'ctx' beyond its existing "
        "members; " + _NEXT_STEP.format(name="ctx")
    )
    assert view.defined_types == []
    # Each of width, member type, member name, and member offset alone counts as a change.
    moved = FakeStructureMember("field_0", 4, FakeType("field_0", "int32_t"))
    for changed in (
        FakeStructureType([member("field_0", "int32_t")], 16),
        FakeStructureType([member("field_0", "uint32_t")], 8),
        FakeStructureType([member("count", "int32_t")], 8),
        FakeStructureType([moved], 8),
        FakeStructureType([member("field_0", "int32_t"), moved], 8),
    ):
        view = FakeBinaryView(types={"ctx": existing}, structure=changed)
        create(_call(view), "ctx")
        assert view.defined_types == [("ctx", changed)]


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
    view_at_cap = _struct_view(
        [FakeStructureMember("a", 0, FakeType("a"))], 8, name="x" * types._MAX_TYPE_NAME_CHARS
    )
    at_cap = create(_call(view_at_cap), "x" * types._MAX_TYPE_NAME_CHARS)
    assert at_cap["name"] == "x" * types._MAX_TYPE_NAME_CHARS


def test_type_library_export_objects_orders_candidates_by_rank_before_address(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _use_export_root(monkeypatch, tmp_path)
    typed = FakeType("table_t", "int32_t[4]")
    void = FakeType("void", "void", type_class=FakeTypeClass.VoidTypeClass)
    view = _objects_view(
        symbols=[
            FakeSymbol(0x100, "DataSymbol", "g_shared"),
            FakeSymbol(0x200, "DataSymbol", "g_shared"),
        ],
        data_variable_types={0x100: void, 0x200: typed},
    )
    result = _export_objects(view, "g_shared")
    assert result["exported"] == [
        {
            "name": "g_shared",
            "type": "int32_t[4]",
            "address": "0x200",
            "alternatives": [{"address": "0x100", "type": "void"}],
        }
    ]
