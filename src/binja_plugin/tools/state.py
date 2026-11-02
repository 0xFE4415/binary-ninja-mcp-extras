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
# can stop when the depth stops changing.


def _require_key(key: str) -> None:
    if not key:
        raise mcp.ToolError("invalid_key", "key must not be empty")


def _run_undo_stack_step(
    call: mcp.ToolCall, step: Callable[[], None], failed_code: str, verb: str, done: str
) -> dict[str, object]:
    """Shared body of rex_undo and rex_redo: run one undo-database step, echo the depths.

    The depths are read after the step, so a caller can stop when ``undo_left`` stops
    changing; an empty stack is a core-side no-op, not an error.
    """
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

    Values are stored under the "rex/" metadata namespace and survive across sessions.

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
    """Redo the last undone transaction in the view's undo database.

    The counterpart of rex_undo: re-applies the entry rex_undo most recently took off
    the undo stack. The stack is shared with the GUI user, so this may redo their last
    undone edit too. An empty stack is a core-side no-op, not an error; the
    post-operation depths report the state the caller lands in.
    """
    return _run_undo_stack_step(call, call.binary_view.redo, "redo_failed", "redo", "redone")


@mcp.tool(read_only=True)
def rex_report_show(
    call: mcp.ToolCall,
    title: Annotated[str, mcp.NonEmpty()],
    markdown: Annotated[str, mcp.NonEmpty()],
) -> dict[str, object]:
    """Render a markdown triage report inside Binary Ninja.

    Opens Binary Ninja's markdown report viewer on this view, so report text can link
    back into the analysis with ``binaryninja://?expr=`` hyperlinks (e.g.
    ``[main](binaryninja://?expr=main)``). Read-only: nothing in the view, database, or
    filesystem changes — the report is presentation only. The markdown is also passed as
    the API's plaintext fallback, so command-line hosts (where the viewer degrades to
    plain text) still show the report instead of dropping it silently. Title and markdown
    are size-capped and rejected beyond the cap, never clipped: the core receives both as
    single unbounded strings and the title names the report tab. The response echoes only
    a capped preview of the markdown, so an overlarge report can never flood the MCP
    response either.

    :param title: Title displayed on the report tab.
    :param markdown: Markdown contents to render; ``binaryninja://?expr=...`` links into
        the active Binary View.
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

    :param limit: Maximum number of tags to return (0 to 500).
    :param offset: Number of tags to skip before collecting results (>= 0).
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

    :param addr: Address to tag; accepts expressions like "main" or ".text + 0x10".
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
    """Undo the last committed transaction in the view's undo database.

    The rollback for the plugin's destructive tools. The undo database belongs to the
    file, so the stack is shared with the GUI user and this may roll back their most
    recent edit too. An empty stack is a core-side no-op, not an error — the
    post-operation ``undo_left``/``redo_left`` depths let a caller stop when
    ``undo_left`` stops changing.

    Which plugin operations leave an undo entry, per the installed API source (what the
    docstrings there document, not a live observation):

    - rex_annotate_many: yes. Its batch commits inside ``BinaryView.undoable_transaction``,
      which the API documents as creating "an Undo state containing those actions" —
      so one batch is one entry, and this tool reverses it whole.
    - rex_tag_set: not documented. The API documents the removal direction only
      (``BinaryView.remove_user_data_tag`` and the Function counterparts: "will be
      added to the current undo buffer"); ``BinaryView.add_tag``, which rex_tag_set
      calls, says nothing about undo.
    - rex_kv_set: not documented. ``store_metadata`` documents only its BNDB snapshot
      persistence flags and says nothing about undo entries.
    - rex_type_library_import: not documented. Neither ``add_type_library`` nor
      ``import_library_type`` mentions undo.
    - rex_memory_write: not documented. ``BinaryView.write`` says nothing about undo,
      so whether a bare write outside a transaction is undoable is unknown here too.

    The undocumented four need a live Binary Ninja to settle. The depths make that a
    one-call experiment per operation: read ``undo_left`` before and after the
    interleaved write — a depth change means this tool would roll it back.
    """
    return _run_undo_stack_step(call, call.binary_view.undo, "undo_failed", "undo", "undone")
