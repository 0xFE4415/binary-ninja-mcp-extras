from __future__ import annotations

import pytest
from helpers import (
    FakeBinaryView,
    FakeComponent,
    FakeFunction,
    FakeParsingToolCall,
    FakeToolError,
    _call,
    get_tool,
)

# --- rex_component_get / rex_component_create / rex_component_add_functions ------------


def _component_view() -> FakeBinaryView:
    crypto = FakeFunction("crypto_mix", 0x3000, 0x3100)
    parse = FakeFunction("parse_header", 0x1000, 0x1100)
    root_fn = FakeFunction("root_fn", 0x5000, 0x5100)
    net = FakeComponent("Network", "guid-net", functions=[crypto])
    net.children.append(FakeComponent("Crypto", "guid-crypto", functions=[parse]))
    return FakeBinaryView(
        functions=[crypto, parse, root_fn],
        component_root=FakeComponent("__root__", "guid-root", children=[net], functions=[root_fn]),
    )


def test_component_get_reports_root_and_nested_members() -> None:
    view = _component_view()
    _, get = get_tool("rex_component_get")
    root = get(_call(view), "/")
    assert root["guid"] == "guid-root"
    assert root["parent_path"] is None
    assert root["children"] == [{"path": "/Network", "display_name": "Network", "guid": "guid-net"}]
    assert root["functions"] == [{"start": "0x5000", "name": "root_fn"}]
    # The root resolves through the verified root_component property, never through the
    # "/" pathname lookup the installed API does not document.
    assert view.component_path_lookups == []

    network = get(_call(view), "/Network")
    assert network["parent_path"] == "/"
    assert network["display_name"] == "Network"
    assert network["children"] == [
        {"path": "/Network/Crypto", "display_name": "Crypto", "guid": "guid-crypto"}
    ]
    assert network["functions"] == [{"start": "0x3000", "name": "crypto_mix"}]

    crypto = get(_call(view), "/Network/Crypto")
    assert crypto["parent_path"] == "/Network"
    assert crypto["children"] == []
    assert crypto["functions"] == [{"start": "0x1000", "name": "parse_header"}]


def test_component_get_sorts_functions_and_paginates() -> None:
    view = _component_view()
    first = FakeFunction("zzz", 0x8300, 0x8400)
    second = FakeFunction("aaa", 0x8100, 0x8200)
    third = FakeFunction("mmm", 0x8200, 0x8300)
    view.root_component.children.append(
        FakeComponent("Shuffled", "guid-shuffled", functions=[first, second, third])
    )
    _, get = get_tool("rex_component_get")
    result = get(_call(view), "/Shuffled")
    assert [entry["name"] for entry in result["functions"]] == ["aaa", "mmm", "zzz"]
    assert result["function_count"] == 3
    assert result["truncated"] is False
    paged = get(_call(view), "/Shuffled", limit=1, offset=1)
    assert [entry["name"] for entry in paged["functions"]] == ["mmm"]
    assert paged["function_count"] == 3
    assert paged["truncated"] is True
    tail = get(_call(view), "/Shuffled", limit=1, offset=2)
    assert tail["truncated"] is False
    assert [entry["name"] for entry in tail["functions"]] == ["zzz"]
    empty = get(_call(view), "/Shuffled", limit=0)
    assert empty["functions"] == []
    assert empty["truncated"] is True


def test_component_get_defaults_to_a_bounded_function_page() -> None:
    functions = [FakeFunction(f"f{i}", 0x1000 + 4 * i, 0x1100 + 4 * i) for i in range(101)]
    hub = FakeComponent("Hub", "guid-hub", functions=functions)
    view = FakeBinaryView(component_root=FakeComponent("__root__", "guid-root", children=[hub]))
    _, get = get_tool("rex_component_get")
    result = get(_call(view), "/Hub")
    assert len(result["functions"]) == 100
    assert result["functions"][-1]["start"] == "0x118c"
    assert result["function_count"] == 101
    assert result["truncated"] is True


def test_component_get_caps_children() -> None:
    overflow = FakeComponent(
        "Hub", "guid-hub", children=[FakeComponent(f"k{i}", f"guid-k{i}") for i in range(201)]
    )
    view = FakeBinaryView(
        component_root=FakeComponent("__root__", "guid-root", children=[overflow])
    )
    _, get = get_tool("rex_component_get")
    result = get(_call(view), "/Hub")
    assert len(result["children"]) == 200
    assert result["children"][-1]["path"] == "/Hub/k199"
    assert result["children_truncated"] is True


def test_component_get_children_at_the_cap_are_not_truncated() -> None:
    exact = FakeComponent(
        "Hub", "guid-hub", children=[FakeComponent(f"k{i}", f"guid-k{i}") for i in range(200)]
    )
    view = FakeBinaryView(component_root=FakeComponent("__root__", "guid-root", children=[exact]))
    _, get = get_tool("rex_component_get")
    assert get(_call(view), "/Hub")["children_truncated"] is False


def test_component_get_rejects_bad_paths_and_reports_missing() -> None:
    view = _component_view()
    _, get = get_tool("rex_component_get")
    for path, message in (
        ("", "path must not be empty"),
        ("Network", "path must be an absolute path starting with '/'"),
        ("/Network/", "path must not end with '/'"),
        ("/Network//Crypto", "path must not contain empty path segments"),
        ("x" * 513, "path exceeds 512 characters"),
    ):
        with pytest.raises(FakeToolError) as exc:
            get(_call(view), path)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == message
    # At the length cap the path still goes to the lookup and misses cleanly.
    with pytest.raises(FakeToolError) as exc:
        get(_call(view), "/" + "x" * 511)
    assert exc.value.code == "component_not_found"
    assert exc.value.message.startswith("no component at path '/")


def test_component_create_nests_and_reports_canonical_paths() -> None:
    view = _component_view()
    _, create = get_tool("rex_component_create")
    top = create(_call(view), "Crypto")
    assert top == {"path": "/Crypto", "display_name": "Crypto", "guid": "guid-1"}
    nested = create(_call(view), "Symmetric", "/Crypto")
    assert nested == {"path": "/Crypto/Symmetric", "display_name": "Symmetric", "guid": "guid-2"}
    under_root = create(_call(view), "Solver", "/")
    assert under_root == {"path": "/Solver", "display_name": "Solver", "guid": "guid-3"}
    resolved = view.get_component_by_path("/Crypto/Symmetric")
    assert resolved is not None and resolved.guid == "guid-2"


def test_component_create_reports_the_core_suffix_for_duplicate_names() -> None:
    view = _component_view()
    _, create = get_tool("rex_component_create")
    create(_call(view), "Crypto")
    duplicate = create(_call(view), "Crypto")
    assert duplicate["display_name"] == "Crypto (1)"
    assert duplicate["path"] == "/Crypto (1)"


def test_component_create_validates_name_and_parent() -> None:
    view = _component_view()
    _, create = get_tool("rex_component_create")
    for kwargs, message, code in (
        ({"name": ""}, "name must not be empty", "invalid_params"),
        ({"name": "a/b"}, "name must not contain '/'", "invalid_params"),
        ({"name": "x" * 129}, "name exceeds 128 characters", "name_too_large"),
        (
            {"name": "ok", "parent_path": "Network"},
            "parent_path must be an absolute path starting with '/'",
            "invalid_params",
        ),
        (
            {"name": "ok", "parent_path": "/Network/"},
            "parent_path must not end with '/'",
            "invalid_params",
        ),
        (
            {"name": "ok", "parent_path": "/Network//Crypto"},
            "parent_path must not contain empty path segments",
            "invalid_params",
        ),
        (
            {"name": "ok", "parent_path": "y" * 513},
            "parent_path exceeds 512 characters",
            "invalid_params",
        ),
    ):
        with pytest.raises(FakeToolError) as exc:
            create(_call(view), **kwargs)
        assert exc.value.code == code
        assert exc.value.message == message
    with pytest.raises(FakeToolError) as exc:
        create(_call(view), "ok", "/Missing")
    assert exc.value.code == "component_not_found"
    # At the name cap creation still works, and an empty parent_path means top level.
    assert create(_call(view), "x" * 128)["display_name"] == "x" * 128
    assert create(_call(view), "atcap", "")["path"] == "/atcap"


def test_component_add_functions_resolves_then_adds() -> None:
    view = _component_view()
    _, add = get_tool("rex_component_add_functions")
    result = add(FakeParsingToolCall(view), "/Network", ["0x3000", "0x5000"])
    assert result["path"] == "/Network"
    assert result["added_count"] == 2
    # The uniform batch-summary keys, shared with rex_annotate_many and the type-library
    # tools so a caller reads the same failed summary from every batch response.
    assert result["applied"] == 2
    assert result["failed_count"] == 0
    assert result["total"] == 2
    assert result["results"] == [
        {"start": "0x3000", "name": "crypto_mix", "added": True},
        {"start": "0x5000", "name": "root_fn", "added": True},
    ]
    added_names = [function.name for function in view.root_component.children[0].added_functions]
    assert added_names == ["crypto_mix", "root_fn"]


def test_component_add_functions_is_all_or_nothing() -> None:
    view = _component_view()
    _, add = get_tool("rex_component_add_functions")
    network = view.root_component.children[0]
    with pytest.raises(FakeToolError) as exc:
        add(FakeParsingToolCall(view), "/Network", ["0x3000", "0x9999"])
    assert exc.value.code == "invalid_params"
    assert exc.value.message == "no analyzed function contains 0x9999"
    assert network.added_functions == []


def test_component_add_functions_reports_declined_adds() -> None:
    view = _component_view()
    network = view.root_component.children[0]
    network.rejected_functions.append(view.functions[1])
    _, add = get_tool("rex_component_add_functions")
    result = add(FakeParsingToolCall(view), "/Network", ["0x1000"])
    assert result["added_count"] == 0
    assert result["applied"] == 0
    assert result["failed_count"] == 1
    assert result["total"] == 1
    assert result["results"] == [{"start": "0x1000", "name": "parse_header", "added": False}]


def test_component_add_functions_into_the_root_component() -> None:
    view = _component_view()
    _, add = get_tool("rex_component_add_functions")
    result = add(FakeParsingToolCall(view), "/", ["0x3000"])
    assert result == {
        "path": "/",
        "added_count": 1,
        "applied": 1,
        "failed_count": 0,
        "total": 1,
        "results": [{"start": "0x3000", "name": "crypto_mix", "added": True}],
    }
    assert len(view.root_component.added_functions) == 1
    assert view.component_path_lookups == []


def test_component_add_functions_validates_inputs() -> None:
    view = _component_view()
    _, add = get_tool("rex_component_add_functions")
    for kwargs, message in (
        (
            {"path": "Network", "functions": ["0x3000"]},
            "path must be an absolute path starting with '/'",
        ),
        (
            {"path": "/Network", "functions": []},
            "functions must contain between 1 and 64 address expressions",
        ),
        (
            {"path": "/Network", "functions": ["0x3000"] * 65},
            "functions must contain between 1 and 64 address expressions",
        ),
        (
            {"path": "/Network", "functions": [7]},
            "functions[0] must be a string address expression",
        ),
    ):
        with pytest.raises(FakeToolError) as exc:
            add(_call(view), **kwargs)
        assert exc.value.code == "invalid_params"
        assert exc.value.message == message
    with pytest.raises(FakeToolError) as exc:
        add(_call(view), "/Network", "0x3000")
    assert exc.value.message == "functions must be a list of address expressions"
    with pytest.raises(FakeToolError) as exc:
        add(FakeParsingToolCall(view), "/Network", ["@@@"])
    assert exc.value.code == "invalid_params"
    assert "bad address expression" in exc.value.message
    # At the batch cap the call still goes through.
    at_cap = add(FakeParsingToolCall(view), "/Network", ["0x3000"] * 64)
    assert at_cap["added_count"] == 64
