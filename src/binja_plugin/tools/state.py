"""View state tools: key/value scratch data, tags, report rendering, and the undo stack."""

from __future__ import annotations

from collections.abc import Callable
from typing import Annotated

from binaryninja import mcp

from binja_plugin.tools import (
    _MAX_LIMIT,
    _truncate,
    _truncate_with_flag,
    _validate_range,
    _validate_text,
)

_MAX_KV_VALUE_CHARS = 65536
_MAX_KV_KEY_CHARS = 128
_MAX_TAG_DATA_CHARS = 65536
_MAX_TAG_TYPE_CHARS = 64

# rex_report_show: the core receives title and markdown as unbounded strings and renders
# them in a GUI popup named by the title, so both are capped — the markdown to keep one
# agent call from pushing megabytes into the viewer, the title because it labels the tab.
_MAX_REPORT_TITLE_CHARS = 256
_MAX_REPORT_CONTENT_CHARS = 65536

_METADATA_PREFIX = "rex/"
_TAG_ICON = "\u25c6"

# rex_undo/rex_redo echo post-operation stack depths (never the entry text) so an agent
# can stop when the depth stops changing. The stack is the file's undo database, shared
# with the GUI user. Which plugin writes leave an undo entry is documented only for
# rex_annotate_many (one batch = one entry); tag/metadata/type-library/memory writes are
# undocumented in the API source, so settle each with a one-call undo_left experiment on
# a live core before relying on rollback.


def _require_key(key: str) -> None:
    if not key:
        raise mcp.ToolError("invalid_key", "key must not be empty")


def _run_undo_stack_step(
    call: mcp.ToolCall, step: Callable[[], None], failed_code: str, verb: str, done: str
) -> dict[str, object]:
    """Shared body of rex_undo and rex_redo: run one undo-database step, echo the depths."""
    try:
        step()
    except Exception as error:
        raise mcp.ToolError(failed_code, f"could not {verb}: {error}") from None
    return {
        done: True,
        "undo_left": len(call.binary_view.file.undo_entries),
        "redo_left": len(call.binary_view.file.redo_entries),
    }


@mcp.tool(destructive=True)
def rex_kv_delete(call: mcp.ToolCall, key: str) -> dict[str, object]:
    """Delete a value previously stored with rex_kv_set.

    :param key: Key to delete.
    """
    _require_key(key)
    call.binary_view.remove_metadata(_METADATA_PREFIX + key)
    return {"key": _truncate(key)}


@mcp.tool(read_only=True)
def rex_kv_get(call: mcp.ToolCall, key: str) -> dict[str, object]:
    """Read a string previously stored with rex_kv_set.

    :param key: Key to read.
    """
    _require_key(key)
    try:
        value = call.binary_view.query_metadata(_METADATA_PREFIX + key)
    except Exception:
        raise mcp.ToolError("not_found", f"no value stored under '{_truncate(key)}'") from None
    text, truncated = _truncate_with_flag(str(value), _MAX_KV_VALUE_CHARS)
    return {"key": _truncate(key), "value": text, "truncated": truncated}


@mcp.tool(destructive=True)
def rex_kv_set(call: mcp.ToolCall, key: str, value: str) -> dict[str, object]:
    """Store a string in the binary view database as persistent scratch data.

    :param key: Key to store under.
    :param value: String value to store.
    """
    _require_key(key)
    if len(key) > _MAX_KV_KEY_CHARS:
        # The key becomes part of the persistent metadata path with no core-side length bound.
        raise mcp.ToolError("key_too_large", f"key exceeds {_MAX_KV_KEY_CHARS} characters")
    if len(value) > _MAX_KV_VALUE_CHARS:
        raise mcp.ToolError("value_too_large", f"value exceeds {_MAX_KV_VALUE_CHARS} characters")
    call.binary_view.store_metadata(_METADATA_PREFIX + key, value)
    preview, truncated = _truncate_with_flag(value)
    return {"key": _truncate(key), "length": len(value), "value": preview, "truncated": truncated}


@mcp.tool(destructive=True)
def rex_redo(call: mcp.ToolCall) -> dict[str, object]:
    """Redo the last undone transaction in the view's undo database."""
    return _run_undo_stack_step(call, call.binary_view.redo, "redo_failed", "redo", "redone")


@mcp.tool(read_only=True)
def rex_report_show(
    call: mcp.ToolCall,
    title: Annotated[str, mcp.NonEmpty()],
    markdown: Annotated[str, mcp.NonEmpty()],
) -> dict[str, object]:
    """Render a markdown triage report inside Binary Ninja.

    :param title: Title displayed on the report tab.
    :param markdown: Markdown to render; ``binaryninja://?expr=...`` links into the view.
    """
    bv = call.binary_view
    _validate_text("title", title, _MAX_REPORT_TITLE_CHARS, "title_too_large")
    _validate_text("markdown", markdown, _MAX_REPORT_CONTENT_CHARS, "content_too_large")
    # On command-line hosts the default interaction handler displays only the plaintext
    # variant, and an empty plaintext shows nothing; the markdown is its own plaintext so
    # the report survives the degradation.
    bv.show_markdown_report(title, markdown, markdown)
    preview, truncated = _truncate_with_flag(markdown)
    return {"title": title, "length": len(markdown), "preview": preview, "truncated": truncated}


@mcp.tool(read_only=True)
def rex_tag_list(
    call: mcp.ToolCall,
    limit: Annotated[int, mcp.Minimum(0), mcp.Maximum(_MAX_LIMIT)] = 100,
    offset: Annotated[int, mcp.Minimum(0)] = 0,
) -> dict[str, object]:
    """List the tags set on the binary view.

    :param limit: Maximum tags to return.
    :param offset: Tags to skip before collecting results.
    """
    limit = _validate_range("limit", limit, 0, _MAX_LIMIT)
    offset = _validate_range("offset", offset, 0)
    tags = []
    for address, tag in call.binary_view.get_tags():
        data, data_truncated = _truncate_with_flag(tag.data)
        tags.append(
            {
                "address": hex(address),
                "tag_type": tag.type.name,
                "data": data,
                "data_truncated": data_truncated,
            }
        )
    # Like the other listing tools: total covers the whole listing, truncated marks a
    # window that ends before it, and the page is [offset, offset + limit).
    return {
        "total": len(tags),
        "truncated": offset + limit < len(tags),
        "tags": tags[offset : offset + limit],
    }


@mcp.tool(destructive=True)
def rex_tag_set(
    call: mcp.ToolCall, addr: mcp.Address, tag_type: str, data: str, create_missing: bool = True
) -> dict[str, object]:
    """Attach a Binary Ninja tag at an address, visible in the GUI.

    :param addr: Address expression to tag, e.g. "main" or ".text + 0x10".
    :param tag_type: Tag type name, e.g. "Crashes" or "Finding".
    :param data: Tag text.
    :param create_missing: Create tag_type when it does not exist yet.
    """
    bv = call.binary_view
    if len(data) > _MAX_TAG_DATA_CHARS:
        raise mcp.ToolError("data_too_large", f"tag data exceeds {_MAX_TAG_DATA_CHARS} characters")
    if tag_type not in bv.tag_types:
        if not create_missing:
            raise mcp.ToolError("tag_type_not_found", f"no tag type named '{_truncate(tag_type)}'")
        if len(tag_type) > _MAX_TAG_TYPE_CHARS:
            # create_tag_type persists the name in the database with no core-side length bound.
            raise mcp.ToolError(
                "tag_type_too_large", f"tag type name exceeds {_MAX_TAG_TYPE_CHARS} characters"
            )
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
def rex_undo(call: mcp.ToolCall) -> dict[str, object]:
    """Undo the last committed transaction in the view's undo database."""
    return _run_undo_stack_step(call, call.binary_view.undo, "undo_failed", "undo", "undone")
