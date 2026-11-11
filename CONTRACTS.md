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
  list and return exact `total`/`truncated`. `rex_mlil_uses` takes definitions from the
  core, not an operation list: a variable is defined at an instruction when
  `get_var_definitions` lists it there. That covers assignments, split writes, field writes,
  call, syscall, tailcall, and intrinsic outputs, and forced versions; an instruction the
  core defines nothing at (a call without outputs, a store) is `no_definition`; its
  message lists up to 10 addresses that do define variables (`(+N more)` past that), or
  says the function defines no MLIL variables when there are none. It returns
  `variables`, one entry per defined variable (in `vars_written` order, then any further
  variable the core records, such as a field write's destination), each with its own
  `storage`, `type`, `definitions`, `total`, `truncated`, and `uses`. Two distinct
  variables can share a name, so `storage` and `type` (the rendered type, truncated)
  identify the entry. `storage` is `{source: "register", register}` with the register
  name from the function's architecture, `{source: "stack", stack_offset}` with the
  signed core offset, `{source: "flag", flag}`, or `{source: "composite_return_value" |
  "composite_parameter", storage}` with the raw core value. `flag` is the architecture's
  flag name, except for a temporary flag (storage with bit 31 set, the variable `condN`),
  which reads `temp flag N` with N the storage minus 0x80000000; the core's own name for it
  is `flag<storage>`, so nothing is lost. `rex_parameter_variables`
  reports the same shapes. `limit` and `offset` page
  each entry's uses, and `variable` keeps every variable with that name, same-named ones
  included (`no_variable` if the instruction defines none). That error lists the defined
  variables as `name (storage)`, with the register name, `stack +0x8` or `stack -0x8`, the
  flag text, or the composite source and raw value as the storage, so same-named variables
  read apart.
- `no_mlil` (`rex_function_constraints`, `rex_mlil_uses`, `rex_parameter_variables`, and the
  uidf setters and clearers that resolve a variable name) and `no_hlil`
  (`rex_hlil_statements`) distinguish a skipped function from a pending one. When the core
  reports `analysis_skipped`, the message says analysis is skipped, names the cause from
  `analysis_skip_reason` (user override, size, time, or update-count limit, suppressed
  new-function analysis, `analysis.mode`, or a suspended pipeline), and does not advise
  waiting. Otherwise analysis is pending and the message advises
  `bn_analysis_update_and_wait` or a bounded `rex_analysis_wait`.
  `rex_quick_main` applies the same rule to its `note` when the entry function has no HLIL
  and no `main` symbol exists: the note is `the entry`, a space, and that message. It does
  the same when the `main` it found has no HLIL, whatever the method: `the main`, a space,
  and that message.
- An address can lie in several functions: a cold or outlined block belongs to its parent and
  to a function of its own. Every tool that resolves an address expression to a function
  (`rex_function_constraints`, `rex_hlil_statements`, `rex_mlil_uses`,
  `rex_parameter_variables`, `rex_uidf_set`, `rex_uidf_set_many`, `rex_uidf_clear`,
  `rex_uidf_list`, `rex_disasm_at`, `rex_disasm_many`, `rex_decompile_many`,
  `rex_export_disasm`, `rex_call_paths`, `rex_function_undefine`,
  `rex_component_add_functions`, `rex_annotate_many`, and `rex_quick_main`) picks one: the
  containing function with the lowest start address, the architecture name breaking a tie
  between equal starts. The core lists containing functions in no documented order, so the
  pick never follows it. `rex_find_functions_by_pattern` credits each hit to the same pick,
  so overlapping code counts once, for the lowest-start function. The chosen function comes
  back as a resolved function entry, `{start, name, also_containing, same_name}`:
  `also_containing` lists the other functions that contain the address and `same_name` the
  other functions with the chosen name, each as `{start, name}` by ascending start and at
  most 64 per list. `rex_function_containing` lists every containing function in the same
  order, so its first entry is the pick.
  Passing a function name in an address expression is ambiguous too: the core resolves it
  to one address before the plugin sees it and does not say that other functions share the
  name. `same_name` is where that shows, whether the caller passed a name or an address.
  `rex_quick_main` reports the entry function's containing functions, or the containing
  functions of main's start when main is found by symbol.
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
  `limit`/`offset` and return `truncated`. All three stop their scan at the
  first result past the page, so `truncated` means exactly "another matching function
  exists beyond it". `rex_constant_find` and `rex_find_functions_by_pattern` also return
  `total`, the count of matching functions seen before the scan stopped: exact once
  `truncated` is false, so an empty page whose `total` is at or below the `offset` is an
  out-of-range page, not an empty result set. While `truncated` is true, each returned
  function's `addresses` (`rex_constant_find`) and `match_count` plus `addresses`
  (`rex_find_functions_by_pattern`) are lower bounds, because the scan stopped before
  reaching every hit of functions in the page (for example a cold block placed after its
  function); `addresses_truncated` only reports the cap on what was seen.
  `rex_constant_find` lists functions, and picks each function's
  example addresses, in the core's hit order, which is not address order.
  `rex_hlil_grep` returns no `total`; it additionally returns `scan_incomplete`, set when
  the `max_functions` render budget ran out before the whole view was scanned: nothing
  was proven about matches past the page, so more may exist even though `truncated` is
  false. It also always returns an integer `skipped_no_hlil`: the functions in the
  scanned range that passed `function_filter` but had no HLIL, so were not counted in
  `scanned` or searched. Filtered-out functions never count, and a function is counted
  in exactly one page (the one whose range covers it). Its
  `offset`/`next_offset` count functions in the view, not matches; pass the
  cursor back as `offset` and page while either flag is set. The first render of a
  function's HLIL costs tens of milliseconds, which is why a call renders at most
  `max_functions` functions. `rex_disasm_many`
  also returns `truncated` and a `next_offset` index into the input addresses;
  continue with addresses from that index.
  It returns valid `windows` plus per-address `errors` (`index`, `address`, and an
  `error` code/message); a bad address does not fail other items. Each window includes its
  input `index`.
  Per-function address lists cap the echoed examples and say so per function:
  `rex_constant_find` returns at most 6 distinct addresses (the core can report one
  address several times; each is listed once, at its first occurrence) and
  `rex_find_functions_by_pattern` at most 5, each function carrying an
  `addresses_truncated` flag that is true only when a further distinct address exists.
- Returned strings usually keep 512 characters, then append `... [N chars truncated]`;
  the suffix is additional. Larger caps are `rex_eval_python.stdout` (65,536),
  `result` (16,384), `rex_kv_get.value` (65,536), and `rex_string_read_at.value`
  (up to 4,096 via `max_chars`, default 512). `rx_multi_find` returns each input
  `pattern` unchanged, up to 8,192 characters.
- String-clipping flags: `stdout_truncated`, `result_truncated`, and `error_truncated`
  apply to the matching `rex_eval_python` fields; `data_truncated` applies to `data` in
  `rex_tag_list`/`rex_tag_set`; `truncated` applies to values in `rex_kv_set`/`rex_kv_get`,
  `rex_report_show.preview`, and `rex_string_read_at.value`.
  `refs_truncated` means `rex_string_refs` returns at most 64 refs per string;
  `children_truncated` means `rex_component_get` returns at most 256 children. Other
  `truncated` flags describe tool-specific omissions; for `rex_eval_result`, more text
  remains to page.
- `rex_eval_python` always returns `stdout`. It is the only tool that reports a whole-call
  exception in-band: it sets `error` and nulls `result` instead of raising a tool error;
  captured output remains in `stdout`. The code runs with `bv`, `call`, `binaryninja`, and
  `bn` in scope. On success, an assigned `result` is returned as
  Python `repr()`.
  `error` always leads with the exception type, `Type: message` (bare `Type` when the
  message is empty). `Type` is the qualified name as `traceback.format_exception_only`
  writes it: `module.qualname`, except that `builtins` and `__main__` are omitted, so
  `KeyError: 'x'` but `json.decoder.JSONDecodeError: ...` and `binaryninja.mcp.ToolError:
  ...`. A class defined in the submitted code has no `__name__` in the exec globals, so its
  module is `builtins` and it reads as its bare qualname (`Custom: x`,
  `make.<locals>.Inner: n`). A `SystemExit` reads `SystemExit: exit status <repr of code>`. It
  is capped like other echoes (`error_truncated`), so the type is never the part cut.
  `error_location` is `{line, text}` for the innermost line of the submitted code on the
  traceback (text stripped, capped at 200 characters), or null on success and for
  syntax errors, whose message already names the line. The code is compiled as
  `<rex_eval_python>`.
- Non-null `stdout_key`/`result_key` values let `rex_eval_result` page spilled text. The
  server keeps up to 8 spills (a call spilling both fields uses two slots), evicting the
  oldest first. Each spill is limited to 4,194,304 characters; larger text is dropped,
  its key is null, and its `*_length` is still returned. A null key also means no spill
  was needed. Spills disappear when the server exits. Pages return `key`, `value`,
  `total`, `truncated`, and `next_offset`; pass the cursor as `offset`. `limit` is
  1-65,536 characters (default 65,536), `offset` is non-negative, and missing/evicted
  keys raise `not_found`.
- `rex_help` has three views. With no arguments it returns `categories`: one entry per
  tool module, plus `other` when it has tools, each with `name`, `use_when`, and the `tools`
  names, and no descriptions.
  `category` returns `category`, `use_when`, and `tools` with each tool's `name` and
  `description`; an unknown name raises `unknown_category`. `tool_name` returns that
  tool's parameters; an unknown name raises `unknown_tool`. Passing both raises
  `invalid_params`. Every `rex_*` tool appears in exactly one category: the module that
  defines it, or `other` for a registered tool no category module defines. The index lists
  `other` only when it has tools; `category=other` is always valid.
- `rex_data_read` returns `bytes_read` and `complete` (whether all requested bytes were
  read). An unmapped start returns zero bytes. A short read gives the byte count, not
  the locations of unreadable gaps.
- `rex_annotate_many`, `rex_component_add_functions`, `rex_type_library_export`, and
  `rex_type_library_import` return count fields `applied`, `failed_count`, and `total`.
  `rex_annotate_many` also has legacy `failed` and `results`; `rex_component_add_functions`
  has legacy `added_count` and `results`; the type-library tools return a `failed` list.
  `rex_type_library_export` lists `exported` as `{name, type}` entries for `kind="types"`,
  `type` being the rendered type (truncated). For `kind="objects"` each entry is
  `{name, type, address, alternatives}`: `address` is the chosen object's hex address and
  `alternatives` lists the other same-name candidates as `{address, type}`, empty when
  there are none. A name resolves to a function first, else a data variable whose type
  is not void, else a void data variable (which still exports and shows as `void`),
  else a data variable at an import address slot (an `ImportAddressSymbol`, e.g. a GOT
  entry, whose type describes the slot and not the imported object). Ties within a tier
  go to the lowest address, and `alternatives` follows the same order (functions,
  non-void data variables, void data variables, import slots, each by ascending address).
  Type names are unique in a view, so `kind="types"` entries have no `address` or
  `alternatives`.
  Other batch responses: `rex_function_define_many` has `defined`, `failed`, `pending`,
  `waited_ms`; `rex_disasm_many` has `windows` and `errors`; `rex_decompile_many` has
  `functions`, and any address that fails to resolve rejects the whole batch before any
  render (its per-item alternative is `rex_disasm_many`). `rex_uidf_set_many` reports
  per-item `results`, counts, one `analysis_complete` state, and the final HLIL `lines`.
  It stages every item, including each row's rendered `value`, before it informs any
  value, so an unexpected error while staging (a value that cannot render) raises for the
  whole call with nothing informed; expected item errors stay per-item rows.
  `rex_uidf_set` renders its `value` before it informs the variable the same way, so a value
  that cannot render raises with nothing informed.

### Response fields

The top-level fields of each response, beyond the paging and truncation rules above.
Addresses are hex strings, and a function entry is `{start, name}`. A resolved function entry
adds `also_containing` and `same_name`, both lists of function entries (see above); every
`function` field below that a tool fills from an address is one. Fields marked `?` are
present only on some rows.

- `rex_analysis_wait`: `completed`, `elapsed_ms`, `progress` (`{state, count, total}`),
  `function_count`, `in_flight` (`{start, name, analysis_time_ms}`, at most 10), and
  `truncated` (more in-flight functions than listed).
- `rex_annotate_many`: `applied`, `failed`, `failed_count`, `total`, and `results` rows
  `{addr, ok, function?, error?}`; `function` is the resolved function entry as it was before
  the batch renamed it, present on every row that passed validation. A `comment` lands at the
  exact `addr` the item named; `name` and `prototype` apply to the whole function.
- `rex_binary_close`: `closed` (always true; a failed close raises `close_failed`) and
  `path`, the closed file's full filename as the core reports it (truncated).
- `rex_call_paths`: `from_function` and `to_function` (resolved function entries for
  `from_addr` and `to_addr`), `reachable`, `paths` (lists of function entries), `truncated`,
  and `explored` (functions expanded during the search).
- `rex_component_add_functions`: `path`, `added_count`, `applied`, `failed_count`, `total`,
  and `results` rows `{start, name, also_containing, same_name, added}`.
- `rex_component_create`: `path`, `display_name`, `guid`.
- `rex_component_get`: `path`, `guid`, `display_name`, `parent_path` (null for the root),
  `functions`, `function_count`, `truncated`, `children` (`{path, display_name, guid}`),
  and `children_truncated`.
- `rex_constant_find`: `total`, `truncated`, and `functions` of `{start, name, addresses,
  addresses_truncated}`.
- `rex_data_find`, `rx_data_find`: `total`, `truncated`, and `matches` (addresses).
  `rx_multi_find`: `total` (the sum), `truncated` (any pattern truncated), and `results`
  of `{pattern, total, truncated, matches}`, one per input pattern.
- `rex_data_read`: `address`, `length`, `bytes_read`, `data` (hex), `complete`.
- `rex_decompile_many`: `functions` of `{start, name, also_containing, same_name, lines,
  truncated}`.
- `rex_disasm_at`: `function`, `instructions` (`{address, text}`), `truncated`.
  `rex_disasm_many`: `windows` of `{address, index, function, instructions, truncated}`,
  `errors` of `{index, address, error: {code, message}}`, `truncated`, `next_offset` (null
  unless `truncated`).
- `rex_eval_python`: `stdout`, `stdout_truncated`, `stdout_key`, `stdout_length`, `result`,
  `result_truncated`, `result_key`, `result_length`, `error`, `error_truncated`,
  `error_location`. `rex_eval_result`: `key`, `value`, `total`, `truncated`,
  `next_offset`.
- `rex_export_disasm`: `function`, `path`, `bytes_written`, `lines`, `truncated`.
  `rex_export_symbols`:
  `path`, `bytes_written`, `rows`, `truncated`, `total`.
- `rex_find_functions_by_pattern`: `total`, `truncated`, and `functions` of `{start, name,
  match_count, addresses, addresses_truncated}`.
- `rex_function_constraints`: `function`, `total`, `truncated`, and `constraints` of
  `{address, operator, constant, char, subject, subject_text}`. `operator` is `==` or
  `!=`, `constant` is hex, and `char` is the printable ASCII character or null. `subject`
  is `{kind: "load", base, offset}` (`base` is null for an absolute address; both are null,
  and `text` is added, when the address is not a base variable plus a constant),
  `{kind: "variable", variable, definition?}` with `definition` `{address, load}` when the
  variable's only definition is a load, or `{kind: "expression", text}`.
- `rex_function_containing`: `functions` (at most 64, ascending start) and `truncated`.
  `rex_function_define`: `start`, `name`, `analyzed`, `waited_ms`.
  `rex_function_define_many`: `defined` of `{start, name, analyzed}`, `failed` (addresses
  the core refused), `pending` (addresses not yet analyzed), `waited_ms`.
  `rex_function_undefine`: the removed function's resolved entry.
- `rex_help`: see above. A tool view is `{name, description, parameters}`.
- `rex_hlil_grep`: `scanned`, `truncated`, `scan_incomplete`, `skipped_no_hlil`,
  `functions` of `{start, name, lines}`, and `next_offset`: the index of the first function
  the next call should start from, set when `truncated` or `scan_incomplete` is true, null
  when the scan reached the end of the view.
- `rex_hlil_statements`: `function`, `total`, `truncated`, and `statements` of
  `{address, index, text}`.
- `rex_kv_delete`: `key`. `rex_kv_get`: `key`, `value`, `truncated`. `rex_kv_set`: `key`,
  `length`, `value` (preview), `truncated`.
- `rex_memory_write`: `address`, `bytes_written`.
- `rex_mlil_uses`: `function`, `definition_site` (the queried address), and `variables`,
  one per defined variable: `variable`, `storage`, `type`, `definitions` (a flat list of
  the addresses of every definition the core records for it), `total`, `truncated`, and
  `uses` of `{address, operation, text}`.
- `rex_parameter_variables`: `function`, `parameter`, `storage` (one entry per matching
  variable in the function's variable order, shaped like `rex_mlil_uses`' `storage`),
  `definitions` (a flat list of addresses over all matching variables), and `carriers` of
  `{variable, address, text}`.
- `rex_quick_main`: `entry_point`, `method` (`symbol`, `entry-arg`, or `entry-fallback`),
  `main` (null when unresolved), `note` and `hint` (each null when it has nothing to add),
  `function` (main, else the entry function), `lines`, `truncated`. When `main` does
  nothing but tail-call a constant address, passing on only variables and constants, `main`
  stays as found and `note` names the real body (`main is a tail-call stub; its real body is
  NAME at ADDRESS`). A tail call that computes an argument is real work, not a stub. The note
  follows up to eight stubs. It is null for a loop, a longer chain, a target that is not the
  start of a function, or a chain that ends in an import thunk (a symbol of type
  `ImportedFunctionSymbol`, or a function whose only statement tail-calls an import), which
  has no body of its own. A target whose analysis is still pending has no HLIL to inspect, so
  it is named as the body even if it later turns out to be a stub.
- `rex_redo`: `redone`, `undo_left`, `redo_left`. `rex_undo`: `undone`, `undo_left`,
  `redo_left`.
- `rex_relocation_at`: `address`, `count`, and `relocations` of `{address, size, type,
  addend, implicit_addend, pc_relative, target, reloc, symbol}` (`symbol` is null when the
  relocation has none).
- `rex_report_show`: `title`, `length`, `preview`, `truncated`. The markdown can link into
  the view with `binaryninja://?expr=...`.
- `rex_string_read_at`: `address`, `length`, `type`, `value`, `truncated`.
  `rex_string_search`: `total`, `truncated`, and `strings` of `{address, length, type,
  value}`. `rex_string_refs`: `total`, `truncated`, and `strings` of `{value, location,
  derived, refs, refs_truncated}`, `location` being `{type, address, length}` or null and
  each ref `{function_start, function_name, address}` (the first two are null outside a
  function).
- `rex_struct_from_access`: `name`, `registered`, `width`, `member_count`, `members` of
  `{offset, name, type}`, `truncated`.
- `rex_tag_list`: `total`, `truncated`, and `tags` of `{address, tag_type, data,
  data_truncated}`. `rex_tag_set`: `address`, `tag_type`, `data`, `data_truncated`,
  `length`. A missing `tag_type` is created when `create_missing` is true (the default),
  and raises `tag_type_not_found` otherwise.
- `rex_type_library_export`: `path` (the resolved file), `bytes_written`, `library` (the
  library name, truncated), `exported`, `failed` (`{requested, reason}`), `applied`,
  `failed_count`, `total`. `rex_type_library_import`: `library` (null when none loaded),
  `imported` of `{requested, resolved}`, `failed`, `applied`, `failed_count`, `total`.
- `rex_uidf_clear`: `function`, `variable` (null when clearing the whole function),
  `cleared`, and `definition_sites` when a variable is named. `rex_uidf_list`: `function`
  (resolved entry, null when listing the whole view), `total`, `truncated`, and `values` of
  `{function, variable, definition_site, architecture, state, value}`, where each value's
  `function` is a plain function entry. `rex_uidf_set`: `function`, `variable`,
  `definition_site`, `value` (`{state, rendered}`), `analysis_complete`, `lines`,
  `truncated`. `rex_uidf_set_many`: `function`, `applied`, `failed`, `total`, `results` of
  `{index, variable, ok, definition_site?, value?, error?}`, `analysis_complete`, `lines`,
  `truncated`.
- `rex_xrefs_to`: `total`, `truncated`, `code_refs` of `{function_start, function_name,
  arch, address, kind}` (`kind` is `call` or `code`; the first three are null outside a
  function), and `data_refs` of `{source}`.

### Parameters

- Numeric parameters such as `limit`, `length`, `offset`, `max_depth`, `max_paths`,
  `max_functions`, and `max_chars` are range-checked, not clamped; invalid values return
  `invalid_params`.
- Batch caps: `rex_annotate_many`, `rex_function_define_many`, `rex_uidf_set_many`, and
  `rex_component_add_functions` take 1-128 items, `rex_disasm_many` 1-64 addresses, and
  `rex_decompile_many` 1-1024 functions. `before` and `after` of `rex_disasm_at` and
  `rex_export_disasm` are 0-4096 instructions.
- Over-cap strings return parameter-specific codes such as `pattern_too_large`,
  `key_too_large`, `value_too_large`, `data_too_large`, `name_too_large`, or
  `library_name_too_large`. Over-cap component paths, type-name list entries, and export
  filenames return `invalid_params` instead.
- The `filename` of `rex_export_disasm`, `rex_export_symbols`, and `rex_type_library_export`
  is a required parameter with no default, and the advertised schema lists it under
  `required`. It raises `invalid_params` for an empty name, an absolute path, a backslash, a
  NUL byte, a `..` component, a last path component that is `.` or empty (a trailing `/`,
  which names a directory, not a file), or a component over 255 bytes.
  `path_escape` is raised only after resolution, when a symlink inside the export root
  points outside it, and `export_failed` when the root or file cannot be written.
  `rex_help` lists these three codes for the parameter.
- A regular expression that does not compile returns `invalid_regex`; the message is
  `Invalid regular expression parameter '<name>': <reason>` and names the bad parameter:
  `pattern` (`rex_string_search` and `rex_string_refs` with `regex=true`), `regex`
  (`rex_hlil_grep`), or `function_filter` (`rex_hlil_grep`, `rex_constant_find`).
  `rex_hlil_grep` checks `regex` before `function_filter`.
- Hex byte patterns (`rex_data_find`, `rx_data_find`, `rex_find_functions_by_pattern`,
  `rx_multi_find`) are separator-delimited bytes written as exactly two ASCII hex digits,
  or `??` for any byte; separators inside a byte are ignored. A separator is any character
  Python's `str.isspace()` accepts: U+0009-U+000D, U+001C-U+001F, U+0020, U+0085, U+00A0,
  U+1680, U+2000-U+200A, U+2028, U+2029, U+202F, U+205F, and U+3000. Any other token (`+f`,
  `-1`, `0x`, `f_`, non-ASCII digits, `?5`) returns `invalid_pattern` naming the token.
- `rex_constant_find` `value` is an integer (0 to 18446744073709551615) or a string: `0x` or
  `0X`, then 1-16 hex digits in either case. A client that reads JSON numbers as doubles
  rounds the integer maximum to 18446744073709552000, so it should send the hex string for
  values above 2^53. A value that is not an integer or string (a boolean, float, null, list,
  or object), any other string, a sign, whitespace, an empty digit list, or more than 16
  digits returns `invalid_params` naming the violation; strings are never coerced.
- `rx_multi_find` accepts 1-64 patterns: an empty list returns `invalid_params`, a longer
  one `too_many_patterns`. Each entry is capped at 8,192 characters like `rex_data_find`'s
  `pattern`, and an over-cap entry returns `pattern_too_large` naming its index.

### Winning strategies

Usage strategies that do not fit a tool's one-line description.

- The UIDF fold: informing an MLIL value reanalyzes the function, dataflow propagates
  the value into dependent loads and compares, and statically decided branches are
  eliminated from HLIL (the core `set_user_var_value` docs warn of exactly this). The
  highest-leverage target is the base pointer of a key/table load, informed as
  `ConstantPointerValue`: one value resolves every `base[index]` load in the family, so
  whole families of per-byte key checks fold away instead of being informed one compare
  at a time. Find the targets with `rex_function_constraints`, which names the variable
  or `base+offset` load behind each constant branch comparison, then inform the family
  with `rex_uidf_set_many` (one reanalysis, not one per value).
- `rex_help` with no arguments is the discovery step: the category index is short and
  says when each group applies, so read it before choosing a tool, then open one
  category for descriptions.
- `rex_constant_find` matches constants in the core's linear-view disassembly lines (the
  engine behind Search > For Constant), never IL and never raw bytes. A hit counts only on
  an instruction line, one whose tokens include an instruction token. The core also reports
  function header lines and the `{ Continuation of function ... }`, `{ Falls through into
  ... }`, and `{Case ...}` annotation lines; those never count, so `value` 0 no longer
  matches every function. The core also matches `value` 0 on an instruction with no zero
  operand, for example `xor eax, eax  {0x0}` (a register's known value in an annotation) or
  a line that carries a string annotation. For `value` 0 the tool keeps a hit only when a
  token that belongs to an operand and carries a number or address (integer, possible
  address, code-relative address, floating point, character constant, enumeration member,
  code or data symbol, import, or external symbol) is 0. A line whose tokens carry no
  operand index at all is kept, since it cannot be judged. The optional boolean
  `include_non_operand_hits` (default false) returns the dropped hits too; it is only
  allowed with `value` 0 and otherwise returns `invalid_params`. Dropped hits take no slot
  in `total`, paging, the address cap, or `truncated`. Other values are not filtered. The
  tool lists a hit under the function the core attributes the line to, not by the
  lowest-start rule, so in overlapping code one address can appear under several functions.
  A value that is rare or absent makes the core scan the whole view before the search ends.
  Use it to enumerate every function touching a magic value; when the value lives in data
  rather than code, use `rex_data_find` or `rx_multi_find` instead.
- `rex_call_paths` with `direction=callers` from a sink answers "who can reach this"
  without hand-walking xrefs; `direction=callees` from a source answers "what can this
  reach". Both directions are bounded by `max_depth` and `max_paths`.
- `rex_call_paths` defaults to `direction=callers`: from a sink it answers "who can reach
  this" without hand-walking xrefs. "Does main reach X?" needs `direction=callees` from
  main, which answers "what can this reach". Both directions are bounded by `max_depth` and
  `max_paths`. A function called from several sites is one edge, so a path is never listed
  twice.
- `rex_struct_from_access` only sees offset accesses analysis has already recorded, so
  run it after the dereferencing code is analyzed; it registers the inferred struct
  under an auto type id.
- `rex_kv_set` stores under the `rex/` metadata prefix with the core's persistent-flag
  default, so values serialize into the BNDB snapshot and survive reload; use it as
  cross-call scratch for findings a later phase would otherwise re-derive.
