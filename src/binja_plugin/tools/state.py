"""View state tools: key/value scratch data, tags, report rendering, and the undo stack."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Annotated, Any, TypedDict

from binaryninja import mcp

from binja_plugin.tools import (
    _MAX_LIMIT,
    _reject_nul,
    _truncate,
    _truncate_with_flag,
    _validate_range,
    _validate_text,
)

if TYPE_CHECKING:
    from binaryninja.binaryview import Tag

_MAX_KV_VALUE_CHARS = 65536
_MAX_KV_KEY_CHARS = 128
_MAX_TAG_DATA_CHARS = 65536
_MAX_TAG_TYPE_CHARS = 64

# The core renders title and markdown unbounded in a GUI popup, so both are capped.
_MAX_REPORT_TITLE_CHARS = 256
_MAX_REPORT_CONTENT_CHARS = 65536
_MAX_UNDO_ACTIONS = 32

_METADATA_PREFIX = "rex/"
_TAG_ICON = "\u25c6"


class _KvKeyResult(TypedDict):
    key: str


class _KvGetResult(TypedDict):
    key: str
    value: str
    truncated: bool


class _KvSetResult(TypedDict):
    key: str
    length: int
    value: str
    truncated: bool


class _UndoResult(TypedDict):
    undone: bool
    actions: list[str]
    actions_truncated: bool
    undo_left: int
    redo_left: int


class _RedoResult(TypedDict):
    redone: bool
    actions: list[str]
    actions_truncated: bool
    undo_left: int
    redo_left: int


class _ReportResult(TypedDict):
    title: str
    length: int
    preview: str
    truncated: bool


class _TagEntry(TypedDict):
    address: str
    tag_type: str
    data: str
    data_truncated: bool


class _TagListResult(TypedDict):
    total: int
    truncated: bool
    tags: list[_TagEntry]


class _TagSetResult(TypedDict):
    address: str
    tag_type: str
    data: str
    data_truncated: bool
    length: int


def _require_key(key: str) -> None:
    if not key:
        raise mcp.ToolError("invalid_key", "key must not be empty")
    _reject_nul("key", key)


def _top_entry_actions(entries: list[Any]) -> tuple[list[str], bool]:
    """The core's summary of each action in the newest entry, capped, and whether it was cut."""
    if not entries:
        return [], False
    summaries = [action.summary_text for action in entries[-1].actions]
    shown = [_truncate(summary) for summary in summaries[:_MAX_UNDO_ACTIONS]]
    return shown, len(summaries) > _MAX_UNDO_ACTIONS


def _run_undo_stack_step(verb: str, step: Callable[[], None], failed_code: str) -> None:
    try:
        step()
    except Exception as error:
        raise mcp.ToolError(failed_code, f"could not {verb}: {error}") from None


@mcp.tool(destructive=True)
def rex_kv_delete(call: mcp.ToolCall, key: str) -> _KvKeyResult:
    """Delete a value previously stored with rex_kv_set. Writes; not undoable.

    :param key: Key to delete.
    """
    _require_key(key)
    call.binary_view.remove_metadata(_METADATA_PREFIX + key)
    return {"key": _truncate(key)}


@mcp.tool(read_only=True)
def rex_kv_get(call: mcp.ToolCall, key: str) -> _KvGetResult:
    """Read a string previously stored with rex_kv_set.

    :param key: Key to read.
    """
    _require_key(key)
    try:
        value = call.binary_view.query_metadata(_METADATA_PREFIX + key)
    except Exception:
        raise mcp.ToolError(
            "not_found", f"no value stored under '{_truncate(key)}'; store one with rex_kv_set"
        ) from None
    text, truncated = _truncate_with_flag(str(value), _MAX_KV_VALUE_CHARS)
    return {"key": _truncate(key), "value": text, "truncated": truncated}


@mcp.tool(destructive=True)
def rex_kv_set(call: mcp.ToolCall, key: str, value: str) -> _KvSetResult:
    """Persist scratch in the view database across calls and restarts. Writes; not undoable.

    :param key: Key to store under.
    :param value: String value to store.
    """
    _require_key(key)
    if len(key) > _MAX_KV_KEY_CHARS:
        # The key becomes part of the persistent metadata path with no core-side length bound.
        raise mcp.ToolError("key_too_large", f"key exceeds {_MAX_KV_KEY_CHARS} characters")
    _reject_nul("value", value)
    if len(value) > _MAX_KV_VALUE_CHARS:
        raise mcp.ToolError("value_too_large", f"value exceeds {_MAX_KV_VALUE_CHARS} characters")
    call.binary_view.store_metadata(_METADATA_PREFIX + key, value)
    preview, truncated = _truncate_with_flag(value)
    return {"key": _truncate(key), "length": len(value), "value": preview, "truncated": truncated}


@mcp.tool(destructive=True)
def rex_redo(call: mcp.ToolCall) -> _RedoResult:
    """Redo the last undone transaction; returns what it redid and the stack depths."""
    file = call.binary_view.file
    redo_before = len(file.redo_entries)
    actions, actions_truncated = _top_entry_actions(file.redo_entries)
    _run_undo_stack_step("redo", call.binary_view.redo, "redo_failed")
    redone = len(file.redo_entries) < redo_before
    return {
        "redone": redone,
        "actions": actions if redone else [],
        "actions_truncated": actions_truncated and redone,
        "undo_left": len(file.undo_entries),
        "redo_left": len(file.redo_entries),
    }


@mcp.tool(read_only=True)
def rex_report_show(
    call: mcp.ToolCall,
    title: Annotated[str, mcp.NonEmpty()],
    markdown: Annotated[str, mcp.NonEmpty()],
) -> _ReportResult:
    """Show a markdown report in Binary Ninja; returns its title, length, and a preview.

    :param title: Title displayed on the report tab.
    :param markdown: Markdown to render; ``binaryninja://?expr=...`` links into the view.
    """
    bv = call.binary_view
    _validate_text("title", title, _MAX_REPORT_TITLE_CHARS, "title_too_large")
    _validate_text("markdown", markdown, _MAX_REPORT_CONTENT_CHARS, "content_too_large")
    # CLI hosts show only the plaintext variant, so the markdown doubles as its own plaintext.
    bv.show_markdown_report(title, markdown, markdown)
    preview, truncated = _truncate_with_flag(markdown)
    return {"title": title, "length": len(markdown), "preview": preview, "truncated": truncated}


def _tag_entry(address: int, tag: Tag) -> _TagEntry:
    data, data_truncated = _truncate_with_flag(tag.data)
    return {
        "address": hex(address),
        "tag_type": tag.type.name,
        "data": data,
        "data_truncated": data_truncated,
    }


@mcp.tool(read_only=True)
def rex_tag_list(
    call: mcp.ToolCall,
    limit: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_LIMIT)] = 100,
    offset: Annotated[int, mcp.Minimum(0)] = 0,
) -> _TagListResult:
    """List the tags set on the binary view.

    :param limit: Maximum tags to return.
    :param offset: Tags to skip before collecting results.
    """
    limit = _validate_range("limit", limit, 0, _MAX_LIMIT)
    offset = _validate_range("offset", offset, 0)
    tags = [_tag_entry(address, tag) for address, tag in call.binary_view.get_tags()]
    return {
        "total": len(tags),
        "truncated": offset + limit < len(tags),
        "tags": tags[offset : offset + limit],
    }


@mcp.tool(destructive=True)
def rex_tag_set(
    call: mcp.ToolCall, addr: mcp.Address, tag_type: str, data: str, create_missing: bool = True
) -> _TagSetResult:
    """Attach a tag at an address, visible in the GUI. Writes; undoable.

    :param addr: Address expression to tag, e.g. "main" or ".text + 0x10".
    :param tag_type: Tag type name, e.g. "Crashes" or "Finding".
    :param data: Tag text.
    :param create_missing: Create tag_type when it does not exist yet.
    """
    bv = call.binary_view
    _reject_nul("tag_type", tag_type)
    _reject_nul("data", data)
    if len(data) > _MAX_TAG_DATA_CHARS:
        raise mcp.ToolError("data_too_large", f"tag data exceeds {_MAX_TAG_DATA_CHARS} characters")
    missing_type = tag_type not in bv.tag_types
    if missing_type:
        if not create_missing:
            raise mcp.ToolError(
                "tag_type_not_found",
                f"no tag type named '{_truncate(tag_type)}'; pass create_missing=true to create it",
            )
        if len(tag_type) > _MAX_TAG_TYPE_CHARS:
            # create_tag_type persists the name in the database with no core-side length bound.
            raise mcp.ToolError(
                "tag_type_too_large", f"tag type name exceeds {_MAX_TAG_TYPE_CHARS} characters"
            )
    with bv.undoable_transaction():
        if missing_type:
            bv.create_tag_type(tag_type, _TAG_ICON)
        bv.add_tag(addr, tag_type, data)
    data_preview, data_truncated = _truncate_with_flag(data)
    return {
        "address": hex(addr),
        "tag_type": _truncate(tag_type),
        "data": data_preview,
        "data_truncated": data_truncated,
        "length": len(data),
    }


@mcp.tool(destructive=True)
def rex_undo(call: mcp.ToolCall) -> _UndoResult:
    """Undo the last committed transaction; returns what it undid and the stack depths."""
    file = call.binary_view.file
    undo_before = len(file.undo_entries)
    actions, actions_truncated = _top_entry_actions(file.undo_entries)
    _run_undo_stack_step("undo", call.binary_view.undo, "undo_failed")
    undone = len(file.undo_entries) < undo_before
    return {
        "undone": undone,
        "actions": actions if undone else [],
        "actions_truncated": actions_truncated and undone,
        "undo_left": len(file.undo_entries),
        "redo_left": len(file.redo_entries),
    }
