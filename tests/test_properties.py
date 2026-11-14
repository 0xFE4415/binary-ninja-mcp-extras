from __future__ import annotations

import csv
import io
import json
import re
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from helpers import (
    NO_ALTERNATIVES,
    FakeToolCall,
    FakeToolError,
    get_tool,
)
from helpers_invoke import invoke_tool
from helpers_view import (
    FakeBinaryView,
    FakeDerivedString,
    FakeFunction,
    FakeSegment,
    FakeStringReference,
    FakeSymbol,
    RenderableText,
)
from hypothesis import assume, example, given
from hypothesis import strategies as st

from binja_plugin import tools
from binja_plugin.hexpattern import compile_hex_pattern

_TOKENS = ["00", "7f", "80", "ff", "a5", "??"]
# Bias the blob alphabet toward bytes that appear in the tokens plus the newline byte:
# a wildcard compiled without re.DOTALL misses matches on b"\n", and uniform random
# blobs almost never place one under a wildcard.
_BLOB_BYTES = [0x00, 0x0A, 0x41, 0xA5, 0xFF]


@given(st.lists(st.sampled_from(_TOKENS), min_size=1, max_size=16))
def test_compiled_pattern_matches_its_own_bytes(tokens: list[str]) -> None:
    matcher, length = compile_hex_pattern(" ".join(tokens))
    blob = bytes(0x00 if token == "??" else int(token, 16) for token in tokens)
    assert [match.start() for match in matcher.finditer(blob)] == [0]
    assert length == len(tokens)


def _naive_pattern_starts(blob: bytes, tokens: list[str]) -> list[int]:
    return [
        index
        for index in range(len(blob) - len(tokens) + 1)
        if all(
            token == "??" or blob[index + offset] == int(token, 16)
            for offset, token in enumerate(tokens)
        )
    ]


@given(
    tokens=st.lists(st.sampled_from(_TOKENS), min_size=1, max_size=8),
    blob=st.lists(st.sampled_from(_BLOB_BYTES), max_size=48).map(bytes),
)
def test_matches_agree_with_naive_search(tokens: list[str], blob: bytes) -> None:
    matcher, _ = compile_hex_pattern(" ".join(tokens))
    assert [match.start() for match in matcher.finditer(blob)] == _naive_pattern_starts(
        blob, tokens
    )


# --- rex_string_search pagination -------------------------------------------------
#
# The full match list (one unbounded scan) is the reference; every page must be the
# exact slice of it. The scan stops at the first match past the window, so a page's
# "total" is min(true_total, offset+limit+1) and "truncated" is exactly "the window
# ended before the matches did". Nothing here recomputes matching logic: it only pins
# window arithmetic against the tool's own untruncated scan. Out-of-range pagination
# input is covered by the rejection properties below.


def _string_view(strings: list[str]) -> tuple[FakeToolCall, Any]:
    view = FakeBinaryView(
        strings=[
            FakeStringReference(value, 0x1000 + 16 * index) for index, value in enumerate(strings)
        ]
    )
    _, search = get_tool("rex_string_search")
    call = FakeToolCall(view)
    return call, search


def _check_page(
    page: dict[str, Any],
    everything: list[dict[str, object]],
    true_total: int,
    offset: int,
    limit: int,
    items_key: str = "strings",
) -> None:
    # Callers pass only in-range values: rejection of anything else is its own contract.
    assert offset >= 0
    assert 0 <= limit <= tools._MAX_LIMIT
    assert page[items_key] == everything[offset : offset + limit]
    assert page["total"] == min(true_total, offset + limit + 1)
    assert page["truncated"] is (true_total > offset + limit)


@given(
    strings=st.lists(st.text(max_size=8), max_size=10),
    pattern=st.text(min_size=1, max_size=3),
    limit=st.integers(min_value=0, max_value=tools._MAX_LIMIT),
    offset=st.integers(min_value=0, max_value=2**63),
)
def test_string_search_pages_tile_the_full_result(
    strings: list[str], pattern: str, limit: int, offset: int
) -> None:
    call, search = _string_view(strings)
    full = search(call, pattern=pattern, limit=tools._MAX_LIMIT)
    assert full["truncated"] is False
    everything = full["strings"]
    true_total = full["total"]

    # Tiling: consecutive pages of 2 reproduce the full result with no gaps or duplicates.
    tiled = [
        found
        for page_offset in range(0, true_total + 1, 2)
        for found in search(call, pattern=pattern, limit=2, offset=page_offset)["strings"]
    ]
    assert tiled == everything

    # Every page boundary in range is the exact expected slice with exact flags.
    for page_offset in range(0, true_total + 2):
        _check_page(
            search(call, pattern=pattern, limit=2, offset=page_offset),
            everything,
            true_total,
            page_offset,
            2,
        )

    # An arbitrary adversarial (but valid) offset pages the exact expected slice.
    _check_page(
        search(call, pattern=pattern, limit=limit, offset=offset),
        everything,
        true_total,
        offset,
        limit,
    )


# --- out-of-range pagination input is rejected, never normalized --------------------
#
# Adversarial integers: any limit outside [0, _MAX_LIMIT] or any negative offset must
# raise the mcp layer's argument-error convention with the exact per-parameter message,
# regardless of the other parameter's validity.


@given(
    strings=st.lists(st.text(max_size=8), max_size=5),
    limit=st.integers(min_value=-(2**63), max_value=2**63),
    offset=st.integers(min_value=-(2**63), max_value=2**63),
)
def test_string_search_rejects_out_of_range_pagination(
    strings: list[str], limit: int, offset: int
) -> None:
    assume(not (0 <= limit <= tools._MAX_LIMIT and offset >= 0))
    call, search = _string_view(strings)
    with pytest.raises(FakeToolError) as exc:
        invoke_tool(search, call, pattern="a", limit=limit, offset=offset)
    assert exc.value.code == "invalid_params"
    if limit < 0:
        assert exc.value.message == "Invalid integer parameter 'limit': Must be at least 0"
    elif limit > tools._MAX_LIMIT:
        assert exc.value.message == (
            f"Invalid integer parameter 'limit': Must be at most {tools._MAX_LIMIT}"
        )
    else:
        assert exc.value.message == "Invalid integer parameter 'offset': Must be at least 0"


# --- rex_data_find pagination -------------------------------------------------------


@given(
    blob=st.lists(st.sampled_from(_BLOB_BYTES), max_size=48).map(bytes),
    tokens=st.lists(st.sampled_from(_TOKENS), min_size=1, max_size=3),
    limit=st.integers(min_value=0, max_value=tools._MAX_LIMIT),
    offset=st.integers(min_value=0, max_value=2**63),
)
def test_data_find_pages_tile_the_full_result(
    blob: bytes, tokens: list[str], limit: int, offset: int
) -> None:
    pattern = " ".join(tokens)
    view = FakeBinaryView(
        segments=[FakeSegment(0x2000, max(len(blob), 1))],
        memory={0x2000: blob} if blob else {},
    )
    _, find = get_tool("rex_data_find")
    call = FakeToolCall(view)
    full = find(call, pattern=pattern, limit=tools._MAX_LIMIT)
    assert full["truncated"] is False
    everything = full["matches"]
    true_total = full["total"]

    tiled = [
        found
        for page_offset in range(0, true_total + 1, 2)
        for found in find(call, pattern=pattern, limit=2, offset=page_offset)["matches"]
    ]
    assert tiled == everything

    for page_offset in range(0, true_total + 2):
        _check_page(
            find(call, pattern=pattern, limit=2, offset=page_offset),
            everything,
            true_total,
            page_offset,
            2,
            items_key="matches",
        )
    _check_page(
        find(call, pattern=pattern, limit=limit, offset=offset),
        everything,
        true_total,
        offset,
        limit,
        items_key="matches",
    )


@given(
    blob=st.lists(st.sampled_from(_BLOB_BYTES), max_size=8).map(bytes),
    limit=st.integers(min_value=-(2**63), max_value=2**63),
    offset=st.integers(min_value=-(2**63), max_value=2**63),
)
def test_data_find_rejects_out_of_range_pagination(blob: bytes, limit: int, offset: int) -> None:
    assume(not (0 <= limit <= tools._MAX_LIMIT and offset >= 0))
    view = FakeBinaryView(
        segments=[FakeSegment(0x2000, max(len(blob), 1))],
        memory={0x2000: blob} if blob else {},
    )
    _, find = get_tool("rex_data_find")
    with pytest.raises(FakeToolError) as exc:
        invoke_tool(find, FakeToolCall(view), pattern="00", limit=limit, offset=offset)
    assert exc.value.code == "invalid_params"
    if limit < 0:
        assert exc.value.message == "Invalid integer parameter 'limit': Must be at least 0"
    elif limit > tools._MAX_LIMIT:
        assert exc.value.message == (
            f"Invalid integer parameter 'limit': Must be at most {tools._MAX_LIMIT}"
        )
    else:
        assert exc.value.message == "Invalid integer parameter 'offset': Must be at least 0"


# --- rex_constant_find pagination ------------------------------------------------------
#
# One function per matched address keeps the reference list trivial: the full
# untruncated scan is the reference, and every page must be the exact slice of it with
# "truncated" meaning exactly "matches exist past the window".


@given(
    names=st.lists(st.text(alphabet="abcde", min_size=1, max_size=4), min_size=1, max_size=8),
    limit=st.integers(min_value=0, max_value=tools._MAX_LIMIT),
    offset=st.integers(min_value=0, max_value=2**63),
)
def test_constant_find_pages_tile_the_full_result(
    names: list[str], limit: int, offset: int
) -> None:
    functions = [
        FakeFunction(name, 0x1000 + 16 * index, 0x1010 + 16 * index)
        for index, name in enumerate(names)
    ]
    view = FakeBinaryView(
        functions=functions,
        constant_references=[(7, function.start + 8, function) for function in functions],
    )
    _, find = get_tool("rex_constant_find")
    call = FakeToolCall(view)
    full = find(call, value=7, limit=tools._MAX_LIMIT)
    assert full["truncated"] is False
    everything = full["functions"]
    true_total = len(everything)

    # Tiling: consecutive pages of 2 reproduce the full result with no gaps or duplicates.
    tiled = [
        found
        for page_offset in range(0, true_total + 1, 2)
        for found in find(call, value=7, limit=2, offset=page_offset)["functions"]
    ]
    assert tiled == everything

    # An arbitrary adversarial (but valid) offset pages the exact expected slice.
    page = find(call, value=7, limit=limit, offset=offset)
    assert page["functions"] == everything[offset : offset + limit]
    assert page["truncated"] is (true_total > offset + limit)
    # The count seen: exact once the scan completed, offset+limit+1 once truncated.
    assert page["total"] == min(true_total, offset + limit + 1)


# --- rex_tag_list paging -------------------------------------------------------------
#
# tag_list reports the true total (it builds the whole list before slicing), slices
# tags[:limit], and flags truncated exactly when tags exist past the page.


@given(
    tags=st.lists(st.tuples(st.integers(0, 2**63), st.text(max_size=600)), max_size=10),
    limit=st.integers(min_value=0, max_value=tools._MAX_LIMIT),
)
def test_tag_list_pages_arbitrary_limits(tags: list[tuple[int, str]], limit: int) -> None:
    view = FakeBinaryView()
    for address, data in tags:
        view.add_tag(address, "Finding", data)
    _, tag_list = get_tool("rex_tag_list")
    result = tag_list(FakeToolCall(view), limit=limit)
    expected = [
        {
            "address": hex(address),
            "scope": "data",
            "tag_type": "Finding",
            "data": data
            if len(data) <= tools._MAX_CHARS
            else data[: tools._MAX_CHARS] + f"... [{len(data) - tools._MAX_CHARS} chars truncated]",
            "data_truncated": len(data) > tools._MAX_CHARS,
        }
        for address, data in sorted(tags)
    ]
    assert result["total"] == len(tags)
    assert result["truncated"] is (len(tags) > limit)
    assert result["tags"] == expected[:limit]


@given(
    tags=st.lists(st.tuples(st.integers(0, 2**63), st.text(max_size=8)), max_size=5),
    limit=st.integers(min_value=-(2**63), max_value=2**63),
)
def test_tag_list_rejects_out_of_range_limits(tags: list[tuple[int, str]], limit: int) -> None:
    assume(not 0 <= limit <= tools._MAX_LIMIT)
    view = FakeBinaryView()
    for address, data in tags:
        view.add_tag(address, "Finding", data)
    _, tag_list = get_tool("rex_tag_list")
    with pytest.raises(FakeToolError) as exc:
        invoke_tool(tag_list, FakeToolCall(view), limit=limit)
    assert exc.value.code == "invalid_params"
    if limit < 0:
        assert exc.value.message == "Invalid integer parameter 'limit': Must be at least 0"
    else:
        assert exc.value.message == (
            f"Invalid integer parameter 'limit': Must be at most {tools._MAX_LIMIT}"
        )


# --- rex_call_paths on random call graphs -------------------------------------------
#
# Invariants over generated graphs: paths are real edges of the graph, start at the
# from-function, end at the to-function, never exceed the requested depth, are unique
# and loop-free, reachable is exactly "target within the requested depth" (verified by
# an independent Floyd-Warshall oracle), and truncated is exactly "the path cap was hit".


_NODES = 6
_UNREACHABLE = 10**9
_STARTS = [0x1000 + 0x10 * index for index in range(_NODES)]


def _graph(edges: list[tuple[int, int]]) -> tuple[list[FakeFunction], list[set[int]]]:
    functions = [FakeFunction(f"f{index}", start, start + 8) for index, start in enumerate(_STARTS)]
    adjacency: list[set[int]] = [set() for _ in range(_NODES)]
    for caller, callee in edges:
        functions[caller].callees.append(functions[callee])
        functions[callee].callers.append(functions[caller])
        adjacency[caller].add(callee)
    return functions, adjacency


def _min_distances(adjacency: list[set[int]], direction: str) -> list[list[int]]:
    """Floyd-Warshall over the traversal edges: callers walk call edges backwards."""
    huge = _UNREACHABLE
    dist = [[huge] * _NODES for _ in range(_NODES)]
    for node in range(_NODES):
        dist[node][node] = 0
    for caller in range(_NODES):
        for callee in adjacency[caller]:
            if direction == "callees":
                dist[caller][callee] = 1
            else:
                dist[callee][caller] = 1
    for middle in range(_NODES):
        for start in range(_NODES):
            for end in range(_NODES):
                if dist[start][middle] + dist[middle][end] < dist[start][end]:
                    dist[start][end] = dist[start][middle] + dist[middle][end]
    return dist


@given(
    edges=st.lists(st.tuples(st.integers(0, _NODES - 1), st.integers(0, _NODES - 1)), max_size=14),
    from_index=st.integers(0, _NODES - 1),
    to_index=st.integers(0, _NODES - 1),
    direction=st.sampled_from(["callers", "callees"]),
    max_depth=st.integers(min_value=1, max_value=tools._MAX_CALL_PATH_DEPTH),
    max_paths=st.integers(min_value=1, max_value=tools._MAX_CALL_PATHS),
)
def test_call_paths_reports_real_edges_within_the_depth_cap(
    edges: list[tuple[int, int]],
    from_index: int,
    to_index: int,
    direction: str,
    max_depth: int,
    max_paths: int,
) -> None:
    functions, adjacency = _graph(edges)
    _, paths_tool = get_tool("rex_call_paths")
    result = paths_tool(
        FakeToolCall(FakeBinaryView(functions=functions)),
        _STARTS[from_index] + 4,
        _STARTS[to_index] + 4,
        direction=direction,
        max_depth=max_depth,
        max_paths=max_paths,
    )
    depth_cap = max_depth
    path_cap = max_paths

    if from_index == to_index:
        endpoint = {
            "start": hex(_STARTS[from_index]),
            "name": f"f{from_index}",
            **NO_ALTERNATIVES,
        }
        assert result == {
            "from_function": endpoint,
            "to_function": endpoint,
            "reachable": True,
            "paths": [[{"start": hex(_STARTS[from_index]), "name": f"f{from_index}"}]],
            "truncated": False,
            "depth_limited": False,
            "explored": 1,
        }
        return

    paths = result["paths"]
    assert len(paths) <= path_cap
    assert result["reachable"] is bool(paths)
    assert result["truncated"] is (len(paths) == path_cap)
    for path in paths:
        nodes = [int(entry["start"], 16) for entry in path]
        assert path[0] == {"start": hex(_STARTS[from_index]), "name": f"f{from_index}"}
        assert path[-1] == {"start": hex(_STARTS[to_index]), "name": f"f{to_index}"}
        assert len(path) <= depth_cap + 1
        # Tree paths never revisit a node (target is never enqueued, source never
        # re-enqueued). Duplicate identical paths are legitimate: one call site per
        # entry means the target can appear several times in one neighbor list.
        assert len(set(nodes)) == len(nodes)
        for step, following in zip(nodes, nodes[1:]):
            step_index = _STARTS.index(step)
            following_index = _STARTS.index(following)
            if direction == "callees":
                assert following_index in adjacency[step_index]
            else:
                assert step_index in adjacency[following_index]

    oracle = _min_distances(adjacency, direction)
    distance = oracle[from_index][to_index]
    assert result["reachable"] is (distance <= depth_cap)
    if not result["reachable"] and not result["depth_limited"]:
        assert distance == _UNREACHABLE
    if depth_cap < distance < _UNREACHABLE:
        assert result["depth_limited"] is True


@given(
    max_depth=st.integers(min_value=-(2**63), max_value=2**63),
    max_paths=st.integers(min_value=-(2**63), max_value=2**63),
)
def test_call_paths_rejects_out_of_range_bounds(max_depth: int, max_paths: int) -> None:
    assume(
        not (
            1 <= max_depth <= tools._MAX_CALL_PATH_DEPTH and 1 <= max_paths <= tools._MAX_CALL_PATHS
        )
    )
    functions, _ = _graph([])
    _, paths_tool = get_tool("rex_call_paths")
    with pytest.raises(FakeToolError) as exc:
        invoke_tool(
            paths_tool,
            FakeToolCall(FakeBinaryView(functions=functions)),
            _STARTS[0] + 4,
            _STARTS[0] + 4,
            max_depth=max_depth,
            max_paths=max_paths,
        )
    assert exc.value.code == "invalid_params"
    if max_depth < 1:
        assert exc.value.message == "Invalid integer parameter 'max_depth': Must be at least 1"
    elif max_depth > tools._MAX_CALL_PATH_DEPTH:
        assert exc.value.message == (
            f"Invalid integer parameter 'max_depth': Must be at most {tools._MAX_CALL_PATH_DEPTH}"
        )
    elif max_paths < 1:
        assert exc.value.message == "Invalid integer parameter 'max_paths': Must be at least 1"
    else:
        assert exc.value.message == (
            f"Invalid integer parameter 'max_paths': Must be at most {tools._MAX_CALL_PATHS}"
        )


# --- rex_string_search regex/ignore_case composition --------------------------------
#
# Regex mode with re.escape must agree with substring mode, and ignore_case must be a
# superset of case-sensitive matching, in the same order. ASCII-only alphabets keep
# both claims exact: str.lower() is length-preserving on ASCII, so the substring path's
# lower()-based comparison and re.IGNORECASE coincide there. (Exotic unicode case
# pairs are out of scope: regex mode runs on unbounded re, so untrusted input belongs
# in substring mode.)


@given(
    strings=st.lists(st.text(alphabet="aAbBcC ", max_size=10), max_size=10),
    pattern=st.text(alphabet="aAcC", min_size=1, max_size=3),
)
def test_regex_ignore_case_agrees_with_substring_ignore_case(
    strings: list[str], pattern: str
) -> None:
    call, search = _string_view(strings)
    caseless = search(call, pattern=pattern, ignore_case=True, limit=500)
    as_regex = search(call, pattern=re.escape(pattern), regex=True, ignore_case=True, limit=500)
    assert as_regex == caseless
    sensitive = search(call, pattern=pattern, limit=500)
    caseless_addresses = [entry["address"] for entry in caseless["strings"]]
    sensitive_addresses = {entry["address"] for entry in sensitive["strings"]}
    assert [entry["address"] for entry in sensitive["strings"]] == [
        address for address in caseless_addresses if address in sensitive_addresses
    ]


@given(
    ordinary=st.lists(st.text(alphabet="aAbB ", max_size=8), max_size=8),
    derived=st.lists(st.text(alphabet="aAbB ", max_size=8), max_size=8),
    pattern=st.text(alphabet="aAbB ", max_size=3),
    ignore_case=st.booleans(),
    limit=st.integers(min_value=0, max_value=tools._MAX_LIMIT),
    offset=st.integers(min_value=0, max_value=20),
)
def test_string_refs_filters_mixed_sources_before_paging(
    ordinary: list[str],
    derived: list[str],
    pattern: str,
    ignore_case: bool,
    limit: int,
    offset: int,
) -> None:
    view = FakeBinaryView(
        strings=[
            FakeStringReference(value, 0x1000 + 16 * index) for index, value in enumerate(ordinary)
        ],
        derived_strings=[FakeDerivedString(value) for value in derived],
    )
    _, refs = get_tool("rex_string_refs")
    result = refs(
        FakeToolCall(view), pattern=pattern, ignore_case=ignore_case, limit=limit, offset=offset
    )

    values = [(value, False) for value in ordinary] + [(value, True) for value in derived]
    if ignore_case:
        matching = [(value, source) for value, source in values if pattern.lower() in value.lower()]
    else:
        matching = [(value, source) for value, source in values if pattern in value]
    expected_page = matching[offset : offset + limit]

    assert [(entry["value"], entry["derived"]) for entry in result["strings"]] == expected_page
    assert result["total"] == min(len(matching), offset + limit + 1)
    assert result["truncated"] is (len(matching) > offset + limit)


def test_compile_user_regex_adds_no_flags_beyond_ignore_case() -> None:
    assert tools._compile_user_regex("pattern", "x").flags == re.compile("x").flags
    caseless = tools._compile_user_regex("pattern", "x", ignore_case=True)
    assert caseless.flags == re.compile("x", re.IGNORECASE).flags


# --- _paginate against plain slicing -----------------------------------------------------
#
# Offsets are unbounded above (the schema only requires >= 0), so go well past sys.maxsize.


@given(
    items=st.lists(st.integers(), max_size=12),
    offset=st.integers(min_value=0, max_value=2**70),
    limit=st.integers(min_value=0, max_value=15),
)
def test_paginate_agrees_with_slicing(items: list[int], offset: int, limit: int) -> None:
    page, total, truncated = tools._paginate(iter(items), offset, limit)
    assert page == items[offset : offset + limit]
    assert truncated is (len(items) > offset + limit)
    assert total == min(len(items), offset + limit + 1)


@example(count=5, offset=0, limit=1)
@given(
    count=st.integers(min_value=0, max_value=12),
    offset=st.integers(min_value=0, max_value=2**70),
    limit=st.integers(min_value=0, max_value=15),
)
def test_paginate_consumes_at_most_one_item_past_the_window(
    count: int, offset: int, limit: int
) -> None:
    consumed = 0

    def counted() -> Iterator[int]:
        nonlocal consumed
        for item in range(count):
            consumed += 1
            yield item

    tools._paginate(counted(), offset, limit)
    assert consumed == min(count, offset + limit + 1)


# --- chunked memory scan ---------------------------------------------------------------
#
# Chunk size and section bounds are implementation details of the scan: the matches must
# equal a naive search of the blob, whatever the chunk size, and a section clips matches
# to those lying entirely inside it.


@given(
    blob=st.lists(st.sampled_from(_BLOB_BYTES), max_size=48).map(bytes),
    tokens=st.lists(st.sampled_from(_TOKENS), min_size=1, max_size=3),
    chunk=st.integers(min_value=1, max_value=16),
    first=st.integers(min_value=0, max_value=52),
    last=st.integers(min_value=0, max_value=52),
)
def test_data_find_is_independent_of_the_read_chunk_and_clips_to_the_section(
    blob: bytes, tokens: list[str], chunk: int, first: int, last: int
) -> None:
    low, high = min(first, last), max(first, last)
    view = FakeBinaryView(
        segments=[FakeSegment(0x2000, max(len(blob), 1))],
        memory={0x2000: blob} if blob else {},
        sections={"s": (0x2000 + low, 0x2000 + high)},
    )
    _, find = get_tool("rex_data_find")
    call = FakeToolCall(view)
    pattern = " ".join(tokens)
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(tools, "_READ_CHUNK", chunk)
        unbounded = find(call, pattern=pattern, limit=tools._MAX_LIMIT)
        bounded = find(call, pattern=pattern, limit=tools._MAX_LIMIT, section="s")
    starts = _naive_pattern_starts(blob, tokens)
    assert unbounded["matches"] == [hex(0x2000 + index) for index in starts]
    assert bounded["matches"] == [
        hex(0x2000 + index) for index in starts if low <= index and index + len(tokens) <= high
    ]


# --- rex_find_functions_by_pattern ----------------------------------------------------------
#
# Disjoint, ascending functions make the full result predictable from the naive match
# list: per-function counts and example addresses, in first-match order. Every page is the
# exact slice of it, including for offsets past any integer a C-level slice accepts.


@example(blob=b"\x00", tokens=["00"], layout=[(0, 4)], limit=0, offset=2**63)
@given(
    blob=st.lists(st.sampled_from(_BLOB_BYTES), max_size=48).map(bytes),
    tokens=st.lists(st.sampled_from(_TOKENS), min_size=1, max_size=3),
    layout=st.lists(
        st.tuples(st.integers(min_value=0, max_value=6), st.integers(min_value=1, max_value=12)),
        max_size=6,
    ),
    limit=st.integers(min_value=0, max_value=tools._MAX_LIMIT),
    offset=st.integers(min_value=0, max_value=2**63),
)
def test_find_functions_by_pattern_pages_tile_the_full_result(
    blob: bytes, tokens: list[str], layout: list[tuple[int, int]], limit: int, offset: int
) -> None:
    functions: list[FakeFunction] = []
    cursor = 0x3000
    for index, (gap, length) in enumerate(layout):
        start = cursor + gap
        functions.append(FakeFunction(f"f{index}", start, start + length))
        cursor = start + length
    view = FakeBinaryView(
        segments=[FakeSegment(0x3000, max(len(blob), 1))],
        memory={0x3000: blob} if blob else {},
        functions=functions,
    )
    _, find = get_tool("rex_find_functions_by_pattern")
    call = FakeToolCall(view)
    pattern = " ".join(tokens)

    addresses = [0x3000 + index for index in _naive_pattern_starts(blob, tokens)]
    expected: list[dict[str, object]] = []
    for function in functions:
        inside = [address for address in addresses if function.start <= address < function.end]
        if inside:
            expected.append(
                {
                    "start": hex(function.start),
                    "name": function.name,
                    "match_count": len(inside),
                    "addresses": [hex(a) for a in inside[: tools._MAX_FIND_FUNCTIONS_EXAMPLES]],
                    "addresses_truncated": len(inside) > tools._MAX_FIND_FUNCTIONS_EXAMPLES,
                }
            )
    full = find(call, pattern=pattern, limit=tools._MAX_LIMIT)
    assert full == {"total": len(expected), "truncated": False, "functions": expected}

    page = find(call, pattern=pattern, limit=limit, offset=offset)
    assert page["functions"] == expected[offset : offset + limit]
    assert page["truncated"] is (len(expected) > offset + limit)
    # The count seen: exact once the scan completed, offset+limit+1 once truncated.
    assert page["total"] == min(len(expected), offset + limit + 1)


# --- rex_hlil_grep paging ------------------------------------------------------------------
#
# The documented contract: pass next_offset back as offset while either truncated or
# scan_incomplete is set, and the concatenated pages are the full result. truncated means
# a rendered match past the page; scan_incomplete means the render budget ran out. A
# function with no HLIL is skipped, not counted.

_HLIL_BODIES = st.lists(
    st.none() | st.lists(st.text(alphabet="ab ", min_size=1, max_size=4), max_size=5),
    max_size=8,
)


def _hlil_view(bodies: list[list[str] | None]) -> FakeBinaryView:
    return FakeBinaryView(
        functions=[
            FakeFunction(
                f"f{index}",
                0x1000 + 0x10 * index,
                0x1008 + 0x10 * index,
                hlil=None if lines is None else RenderableText("\n".join(lines)),
            )
            for index, lines in enumerate(bodies)
        ]
    )


def _expected_hlil_hits(bodies: list[list[str] | None]) -> list[tuple[int, dict[str, object]]]:
    expected: list[tuple[int, dict[str, object]]] = []
    for index, lines in enumerate(bodies):
        hits = [line for line in lines or [] if "a" in line]
        if hits:
            entry: dict[str, object] = {
                "start": hex(0x1000 + 0x10 * index),
                "name": f"f{index}",
                "lines": hits[:3],
            }
            expected.append((index, entry))
    return expected


@given(
    bodies=_HLIL_BODIES,
    limit=st.integers(min_value=1, max_value=tools._MAX_HLIL_GREP_LIMIT),
)
def test_hlil_grep_pages_chain_through_next_offset(
    bodies: list[list[str] | None], limit: int
) -> None:
    _, grep = get_tool("rex_hlil_grep")
    call = FakeToolCall(_hlil_view(bodies))
    chained: list[dict[str, object]] = []
    next_offset = 0
    while True:
        page = grep(call, regex="a", limit=limit, offset=next_offset)
        chained.extend(page["functions"])
        if not page["truncated"] and not page["scan_incomplete"]:
            break
        # Strict progress bounds the loop by the function count.
        assert page["next_offset"] > next_offset
        next_offset = page["next_offset"]
    assert chained == [entry for _, entry in _expected_hlil_hits(bodies)]


@given(
    bodies=_HLIL_BODIES,
    limit=st.integers(min_value=0, max_value=tools._MAX_HLIL_GREP_LIMIT),
    offset=st.integers(min_value=0, max_value=2**63),
)
def test_hlil_grep_offset_selects_the_functions_from_that_index(
    bodies: list[list[str] | None], limit: int, offset: int
) -> None:
    _, grep = get_tool("rex_hlil_grep")
    page = grep(FakeToolCall(_hlil_view(bodies)), regex="a", limit=limit, offset=offset)
    expected = [entry for index, entry in _expected_hlil_hits(bodies) if index >= offset]
    assert page["functions"] == expected[:limit]


def _reference_hlil_lines(body: list[str], before: int, after: int) -> list[str]:
    hits = [position for position, line in enumerate(body) if "a" in line][:3]
    if before == 0 and after == 0:
        return [body[hit] for hit in hits]
    lines: list[str] = []
    for number, hit in enumerate(hits):
        if number > 0:
            lines.append("--")
        first = max(hit - before, 0)
        last = min(hit + after, len(body) - 1)
        for position in range(first, last + 1):
            marker = "> " if position == hit else "  "
            lines.append(marker + body[position])
    return lines


@example(body=["b", "a", "b", "a", "a", "a", "b"], before=3, after=2)
@given(
    body=st.lists(st.sampled_from(["a", "b", "ab", " "]), min_size=1, max_size=14),
    before=st.integers(min_value=0, max_value=tools._MAX_HLIL_GREP_CONTEXT),
    after=st.integers(min_value=0, max_value=tools._MAX_HLIL_GREP_CONTEXT),
)
def test_hlil_grep_context_windows_match_an_index_based_reference(
    body: list[str], before: int, after: int
) -> None:
    _, grep = get_tool("rex_hlil_grep")
    call = FakeToolCall(_hlil_view([body]))
    result = grep(call, regex="a", context_before=before, context_after=after)
    expected = _reference_hlil_lines(body, before, after)
    assert [entry["lines"] for entry in result["functions"]] == ([expected] if expected else [])


# --- rex_disasm_at window ----------------------------------------------------------------
#
# Differential test against the plain linear anchor scan: the anchor is the last line at
# or before the address (shared addresses included), else the first line.


@given(
    addresses=st.lists(st.integers(min_value=0, max_value=30), max_size=12).map(sorted),
    address=st.integers(min_value=-2, max_value=32),
    before=st.integers(min_value=0, max_value=tools._MAX_DISASM_CONTEXT),
    after=st.integers(min_value=0, max_value=tools._MAX_DISASM_CONTEXT),
)
def test_disasm_window_matches_a_linear_anchor_scan(
    addresses: list[int], address: int, before: int, after: int
) -> None:
    lines = [(line_address, "insn") for line_address in addresses]
    # Reference implementation: the linear scan that predates the bisect lookup.
    anchor = 0
    for index, line_address in enumerate(addresses):
        if line_address > address:
            break
        anchor = index
    assert tools._disasm_window(lines, address, before, after) == (
        max(0, anchor - before),
        min(len(lines), anchor + 1 + after),
    )


# --- export tools ---------------------------------------------------------------------------


@given(filename=st.text(alphabet="ab./\\\x00", max_size=12))
def test_validated_export_filenames_stay_inside_the_export_root(filename: str) -> None:
    try:
        tools._validate_export_path(filename)
    except FakeToolError:
        return
    root = Path(tempfile.gettempdir()) / "rex-export-property-root"
    assert (root / filename).resolve().is_relative_to(root.resolve())


@given(
    symbols=st.lists(
        st.tuples(
            st.integers(min_value=0x1000, max_value=0x1040),
            st.sampled_from(["FunctionSymbol", "DataSymbol"]),
            st.text(alphabet='ab,\r\n"\u00e9', max_size=12),
        ),
        unique_by=lambda symbol: symbol[0],
        max_size=12,
    ),
    start=st.integers(min_value=0x1000, max_value=0x1040),
    span=st.integers(min_value=1, max_value=0x41),
    limit=st.integers(min_value=0, max_value=tools._MAX_EXPORT_SYMBOLS),
    offset=st.integers(min_value=0, max_value=2**63),
)
def test_export_symbols_writes_the_exact_sorted_window(
    symbols: list[tuple[int, str, str]], start: int, span: int, limit: int, offset: int
) -> None:
    view = FakeBinaryView(
        symbols=[FakeSymbol(address, symbol_type, name) for address, symbol_type, name in symbols]
    )
    _, export = get_tool("rex_export_symbols")
    in_range = sorted(
        (address, symbol_type, name)
        for address, symbol_type, name in symbols
        if start <= address < start + span
    )
    window = in_range[offset : offset + limit]
    expected = [
        {"symbol_address": hex(address), "symbol_type": symbol_type, "name": name}
        for address, symbol_type, name in window
    ]
    with tempfile.TemporaryDirectory() as directory, pytest.MonkeyPatch.context() as patch:
        patch.setattr(tools, "_EXPORT_ROOT", Path(directory) / "exports")
        for file_format in ("csv", "json"):
            result = export(
                FakeToolCall(view),
                start,
                start + span,
                limit=limit,
                offset=offset,
                format=file_format,
                filename=f"symbols.{file_format}",
            )
            content = Path(result["path"]).read_bytes().decode("utf-8")
            if file_format == "csv":
                written = list(csv.DictReader(io.StringIO(content, newline="")))
            else:
                written = json.loads(content)
            assert written == expected
            assert result["rows"] == len(window)
            assert result["total"] == len(in_range)
            assert result["truncated"] is (len(in_range) > offset + limit)
