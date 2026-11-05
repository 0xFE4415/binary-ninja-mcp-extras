# Repository instructions

## MCP tool contract

This is the normative response and parameter contract for MCP tools. If implementation and
contract differ, do not silently change the contract to match implementation: fix the
implementation or raise the discrepancy for resolution. Keep user-facing usage guidance in
`README.md`.

### Responses

- Stock `bn_*` listings return a Markdown table in `content`, not `structuredContent`;
  `rex_*` listings return structured data.
- Paged tools accept but do not echo `limit`/`offset`. `rex_string_search`,
  `rex_data_find`, `rx_data_find`, `rex_string_refs`, `rex_xrefs_to`, `rex_tag_list`,
  `rex_uidf_list`, and `rex_export_symbols` return `total`/`truncated`. Except for
  `rex_export_symbols`, they return the selected results inline. That tool writes the
  selected rows to a file and returns `path`, `bytes_written`, `rows` written, `total`,
  and `truncated`; the flag also covers rows dropped by its 4 MiB file cap.
  `rex_component_get` pages functions and returns exact `function_count` instead of
  `total`.
  `rex_function_constraints`, `rex_hlil_statements`, and `rex_mlil_uses` build their full
  list and return exact `total`/`truncated`. `rex_mlil_uses` resolves the variable one
  address assigns; a split write defines a high:low pair and the tool reports the high
  half.
- For `rex_string_search`, `rex_data_find`, `rx_data_find`, `rex_string_refs`, and
  `rex_uidf_list`, a truncated `total` is a lower bound: scanning stops at the first
  result past the page. `rex_xrefs_to` has the same rule for fetched refs; `rx_multi_find`
  applies it per pattern, sums those totals, and sets top-level `truncated` if any
  pattern is truncated. `rex_tag_list`, `rex_export_symbols`, and `rex_component_get`
  return exact totals.
- `rex_xrefs_to` fetches at most 501 code and 501 data refs, sorts each fetched list by
  address, then pages the combined list with code refs first. Counts cover only fetched
  refs; omitted refs are not necessarily higher addresses, and `truncated` can be false.
- `rex_constant_find`, `rex_find_functions_by_pattern`, and `rex_hlil_grep` accept
  `limit`/`offset` and return `truncated`, not `total`. All three stop their scan at the
  first result past the page, so `truncated` means exactly "another matching function
  exists beyond it".
  `rex_hlil_grep` additionally returns `scan_incomplete`, set when the `max_functions`
  render budget ran out before the whole view was scanned: nothing was proven about
  matches past the page, so more may exist even though `truncated` is false. Its
  `offset`/`next_offset` count functions in the view, not matches; pass the
  cursor back as `offset` and page while either flag is set. `rex_disasm_many`
  also returns `truncated` and a `next_offset` index into the input addresses;
  continue with addresses from that index.
  It returns valid `windows` plus per-address `errors` (`index`, `address`, and an
  `error` code/message); a bad address does not fail other items. Each window includes its
  input `index`.
  Per-function address lists cap the echoed examples and say so per function:
  `rex_constant_find` returns at most 6 addresses and `rex_find_functions_by_pattern`
  at most 5, each function carrying an `addresses_truncated` flag.
- Returned strings usually keep 512 characters, then append `... [N chars truncated]`;
  the suffix is additional. Larger caps are `rex_eval_python.stdout` (65,536),
  `result` (16,384), `rex_kv_get.value` (65,536), and `rex_string_read_at.value`
  (up to 4,096 via `max_chars`, default 512). `rx_multi_find` returns each input
  `pattern` unchanged, up to 8,192 characters.
- String-clipping flags: `stdout_truncated`, `result_truncated`, and `error_truncated`
  apply to the matching `rex_eval_python` fields; `data_truncated` applies to `data` in
  `rex_tag_list`/`rex_tag_set`; `truncated` applies to values in `rex_kv_set`/`rex_kv_get`,
  `rex_report_show.preview`, and `rex_string_read_at.value`.
  `refs_truncated` means `rex_string_refs` returns at most 20 refs per string;
  `children_truncated` means `rex_component_get` returns at most 200 children. Other
  `truncated` flags describe tool-specific omissions; for `rex_eval_result`, more text
  remains to page.
- `rex_eval_python` always returns `stdout`. It is the only tool that reports a whole-call
  exception in-band: it sets `error` and nulls `result` instead of raising a tool error;
  captured output remains in `stdout`. On success, an assigned `result` is returned as
  Python `repr()`.
- Non-null `stdout_key`/`result_key` values let `rex_eval_result` page spilled text. The
  server keeps up to 8 spills (a call spilling both fields uses two slots), evicting the
  oldest first. Each spill is limited to 4,194,304 characters; larger text is dropped,
  its key is null, and its `*_length` is still returned. A null key also means no spill
  was needed. Spills disappear when the server exits. Pages return `key`, `value`,
  `total`, `truncated`, and `next_offset`; pass the cursor as `offset`. `limit` is
  1-65,536 characters (default 65,536), `offset` is non-negative, and missing/evicted
  keys raise `not_found`.
- `rex_data_read` returns `bytes_read` and `complete` (whether all requested bytes were
  read). An unmapped start returns zero bytes. A short read gives the byte count, not
  the locations of unreadable gaps.
- `rex_annotate_many`, `rex_component_add_functions`, `rex_type_library_export`, and
  `rex_type_library_import` return count fields `applied`, `failed_count`, and `total`.
  `rex_annotate_many` also has legacy `failed` and `results`; `rex_component_add_functions`
  has legacy `added_count` and `results`; the type-library tools return a `failed` list.
  Other batch responses: `rex_function_define_many` has `defined`, `failed`, `pending`,
  `waited_ms`; `rex_disasm_many` has `windows` and `errors`; `rex_decompile_many` has
  `functions`. `rex_uidf_set_many` reports per-item `results`, counts, one
  `analysis_complete` state, and the final HLIL `lines`.

### Parameters

- Numeric parameters such as `limit`, `length`, `offset`, `max_depth`, `max_paths`,
  `max_functions`, and `max_chars` are range-checked, not clamped; invalid values return
  `invalid_params`.
- Over-cap strings return parameter-specific codes such as `pattern_too_large`,
  `key_too_large`, `value_too_large`, `data_too_large`, `name_too_large`, or
  `library_name_too_large`. Over-cap component paths, type-name list entries, and export
  filenames return `invalid_params` instead.
- `rx_multi_find` accepts 1-64 patterns: an empty list returns `invalid_params`, a longer
  one `too_many_patterns`. Each entry is capped at 8,192 characters like `rex_data_find`'s
  `pattern`, and an over-cap entry returns `pattern_too_large` naming its index.
