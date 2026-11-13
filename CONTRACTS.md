# Repository instructions

## MCP tool contract

This is the normative response and parameter contract for MCP tools. If implementation and
contract differ, do not silently change the contract: fix the implementation or raise the
discrepancy. Keep user-facing usage guidance in `README.md`.

### Responses

- Stock `bn_*` listings return a Markdown table in `content`, not `structuredContent`;
  `rex_*` listings return structured data.
- Paged tools accept but do not echo `limit`/`offset`. `rex_string_search`, `rex_data_find`,
  `rx_data_find`, `rex_string_refs`, `rex_xrefs_to`, `rex_tag_list`, `rex_uidf_list`, and
  `rex_export_symbols` return `total`/`truncated`, with results inline.
  `rex_export_symbols` instead writes the selected rows to a file and returns `path`,
  `bytes_written`, `rows` written, `total`, and `truncated`; the flag also covers rows dropped
  by its 4 MiB file cap. `rex_component_get` pages functions and returns exact
  `function_count` instead of `total`. `rex_function_constraints`, `rex_hlil_statements`, and
  `rex_mlil_uses` build their full list and return exact `total`/`truncated`.
- A truncated `total` is a lower bound (scanning stops at the first result past the page) for
  `rex_string_search`, `rex_data_find`, `rx_data_find`, `rex_string_refs`, `rex_uidf_list`,
  and the fetched refs of `rex_xrefs_to`. `rx_multi_find` applies it per pattern, sums those
  totals, and sets top-level `truncated` if any pattern is truncated. `rex_tag_list`,
  `rex_export_symbols`, and `rex_component_get` return exact totals.
- `rex_xrefs_to` fetches at most 501 code and 501 data refs, sorts each fetched list by
  address, then pages the combined list with code refs first. Counts cover only fetched refs;
  omitted refs are not necessarily higher addresses, and `truncated` can be false.
- `rex_mlil_uses` takes definitions from the core: a variable is defined at an instruction
  when `get_var_definitions` lists it there (assignments, split writes, field writes, call,
  syscall, tailcall, and intrinsic outputs, and forced versions). An instruction with no core
  definition (a call without outputs, a store) is `no_definition`; its message lists up to 10
  addresses that do define variables (`(+N more)` past that), or says the function defines no
  MLIL variables. It returns `variables`, one entry per defined variable (in `vars_written`
  order, then any further variable the core records, such as a field write's destination),
  each with its own `storage`, `type` (rendered, truncated), `definitions`, `total`,
  `truncated`, and `uses`. Two variables can share a name; `storage` and `type` identify the
  entry. `limit` and `offset` page each entry's uses. `variable` keeps every variable with
  that name (`no_variable` if the instruction defines none); that error lists the defined
  variables as `name (storage)`, with `storage` as below in short form (register name,
  `stack +0x8` or `stack -0x8`, flag text, or composite source and raw value).
- `storage` (in `rex_mlil_uses` and `rex_parameter_variables`) is `{source: "register",
  register}` with the register name from the function's architecture, `{source: "stack",
  stack_offset}` with the signed core offset, `{source: "flag", flag}`, or `{source:
  "composite_return_value" | "composite_parameter", storage}` with the raw core value. `flag`
  is the architecture's flag name, except for a temporary flag (storage with bit 31 set, the
  variable `condN`), which reads `temp flag N` with N the storage minus 0x80000000.
- `no_variable` for a name the function does not have (`rex_parameter_variables` and the uidf
  setters and clearers) lists the function's variable names. Names match exactly. A name the
  function has but the MLIL never defines (a saved register, a stack local) fails with
  `no_variable` saying it has no definition sites. A declared parameter with no MLIL
  definition is defined at the function start: the uidf setters and clearers use it as the
  only site, `rex_uidf_set` reports it as `definition_site`, `$here` resolves to it, and the
  value holds from before the entry instruction. Any other `def_address` for it fails with
  `definition_not_found` naming the function start. `rex_uidf_clear` clears every site, held
  before or after the instruction, including values set outside the plugin.
- `no_mlil` (`rex_function_constraints`, `rex_mlil_uses`, `rex_parameter_variables`, and the
  uidf setters and clearers that resolve a variable name) and `no_hlil`
  (`rex_hlil_statements`) distinguish a skipped function from a pending one. When the core
  reports `analysis_skipped`, the message says analysis is skipped, names the cause from
  `analysis_skip_reason` (user override, size, time, or update-count limit, suppressed
  new-function analysis, `analysis.mode`, or a suspended pipeline), and does not advise
  waiting. Otherwise analysis is pending and the message advises
  `bn_analysis_update_and_wait` or a bounded `rex_analysis_wait`.
- Every tool that resolves an address expression to a function (an address can lie in several, e.g.
  a cold or outlined block and its parent) (`rex_function_constraints`, `rex_hlil_statements`,
  `rex_mlil_uses`, `rex_parameter_variables`, `rex_uidf_set`, `rex_uidf_set_many`, `rex_uidf_clear`,
  `rex_uidf_list`, `rex_disasm_at`, `rex_disasm_many`, `rex_decompile_many`, `rex_export_disasm`,
  `rex_call_paths`, `rex_function_undefine`, `rex_component_add_functions`, and `rex_annotate_many`)
  picks the containing function with the lowest start address, the architecture name breaking a tie
  between equal starts, never the core's undocumented order. `rex_find_functions_by_pattern` credits
  each hit to the same pick, so overlapping code counts once. The result is a resolved function
  entry, `{start, name, also_containing, same_name}`: `also_containing` lists the other functions
  that contain the address and `same_name` the other functions with the chosen name, each as
  `{start, name}` by ascending start, at most 64 per list. `rex_function_containing` lists every
  containing function in the same order, so its first entry is the pick. A function name in an
  address expression is ambiguous too (the core resolves it to one address silently); `same_name`
  shows that.
- `rex_constant_find`, `rex_find_functions_by_pattern`, and `rex_hlil_grep` accept `limit`/`offset`
  and return `truncated`. All three stop scanning at the first result past the page, so `truncated`
  means exactly "another matching function exists beyond it". `rex_constant_find` and
  `rex_find_functions_by_pattern` also return `total`, the count of matching functions seen before
  the scan stopped: exact once `truncated` is false, so an empty page whose `total` is at or below
  `offset` is an out-of-range page, not an empty result set. While `truncated` is true, each
  returned function's `addresses` (`rex_constant_find`) and `match_count` plus `addresses`
  (`rex_find_functions_by_pattern`) are lower bounds, because the scan stopped before reaching every
  hit of functions in the page (for example a cold block placed after its function). Both key a
  function by start address and architecture, so two rows can share a `start` for different
  architectures. Per function they cap the echoed `addresses`: `rex_constant_find` at 6 distinct
  (each listed once, at its first occurrence) and `rex_find_functions_by_pattern` at 5;
  `addresses_truncated` is true only when a further distinct address exists. `rex_constant_find`
  lists functions, and picks each function's example addresses, in the core's hit order.
- `rex_hlil_grep` returns no `total`. It returns `scan_incomplete`, set when the
  `max_functions` render budget ran out before the whole view was scanned: matches past the
  page may exist even though `truncated` is false. `skipped_no_hlil` is always an integer: the
  functions in the scanned range that passed `function_filter` but had no HLIL (not counted in
  `scanned`, not searched), each counted in exactly one page; filtered-out functions never
  count.
  `offset`/`next_offset` count functions in the view, not matches; pass the cursor back as
  `offset` and page while either flag is set. A call renders at most `max_functions`
  functions. `limit=0` and `max_functions=0` are probes: `max_functions=0` scans nothing and
  returns `scan_incomplete` with `next_offset` equal to `offset`, and `limit=0` stops at the
  first matching function with `next_offset` pointing at it. A paging loop must pass at least 1
  for both, or it never advances.
- Returned strings usually keep 512 characters, then append `... [N chars truncated]`; the
  suffix is additional. Larger caps are `rex_eval_python.stdout` (65,536), `result` (16,384),
  `rex_kv_get.value` (65,536), and `rex_string_read_at.value` (up to 4,096 via `max_chars`,
  default 512). `rx_multi_find` returns each input `pattern` unchanged, up to 8,192
  characters.
- String-clipping flags: `stdout_truncated`, `result_truncated`, and `error_truncated` apply
  to the matching `rex_eval_python` fields; `data_truncated` to `data` in
  `rex_tag_list`/`rex_tag_set`; `truncated` to values in `rex_kv_set`/`rex_kv_get`,
  `rex_report_show.preview`, and `rex_string_read_at.value`. `refs_truncated` means
  `rex_string_refs` returns at most 64 refs per string; `children_truncated` means
  `rex_component_get` returns at most 256 children. Other `truncated` flags describe
  tool-specific omissions; for `rex_eval_result`, more text remains to page.
- `rex_eval_python` always returns `stdout`. It is the only tool that reports a whole-call exception
  in-band: it sets `error` and nulls `result` instead of raising a tool error; captured output
  remains in `stdout`. The code runs with `bv`, `call`, `binaryninja`, and `bn` in scope. On
  success, an assigned `result` is returned as Python `repr()`. `error` always leads with the
  exception type, `Type: message` (bare `Type` when the message is empty). `Type` is the qualified
  name as `traceback.format_exception_only` writes it: `module.qualname`, with `builtins` and
  `__main__` omitted: `KeyError: 'x'`, `json.decoder.JSONDecodeError: ...`,
  `binaryninja.mcp.ToolError: ...`. A class defined in the submitted code reads as its bare qualname
  (`Custom: x`, `make.<locals>.Inner: n`). A `SystemExit` reads `SystemExit: exit status <repr of
  code>`. A `ToolError` reads `<type>: <code>: <message>` (just the code when the message is empty;
  the plain message when it has no usable string code). Rendering does not raise an `Exception`: a
  message that cannot render reads `<message unavailable>`, a type name that cannot reads `<unknown
  exception type>`, and a chain link that cannot be read ends the chain. Every `BaseException` the
  code raises (including `SystemExit`, `KeyboardInterrupt`, `GeneratorExit`) is reported in-band;
  one raised while rendering still propagates. Chained exceptions follow the outermost, each link
  rendered like it and chosen as Python chooses: `; caused by <error>` for the explicit cause, else
  `; while handling <error>` for the implicit context unless suppressed (`raise X from Y` or `from
  None`). The chain stops at a repeat, or after 8 links with a final `; ...` when more follow. The
  whole text is capped like other echoes (`error_truncated`), never cutting the type.
  `error_location` is `{line, text}` for the innermost line of the submitted code on the traceback
  (text stripped, capped at 200 characters), or null on success, for syntax errors (whose message
  already names the line), and when the traceback cannot be read. The code is compiled as
  `<rex_eval_python>`.
- Non-null `stdout_key`/`result_key` values let `rex_eval_result` page spilled text; a null
  key means no spill was needed or the text was dropped. The server keeps up to 8 spills (a
  call spilling both fields uses two slots), evicting the oldest first. Each spill is limited
  to 4,194,304 characters; larger text is dropped, its key is null, and its `*_length` is
  still returned. Spills disappear when the server exits. Pages return `key`, `value`,
  `total`, `truncated`, and `next_offset`; pass the cursor as `offset`. `limit` is 1-65,536
  characters (default 65,536), `offset` is non-negative, and missing/evicted keys raise
  `not_found`.
- `rex_help` has three views. With no arguments it returns `categories`: one entry per tool
  module, plus `other` when it has tools, each with `name`, `use_when`, and the `tools`
  names, and no descriptions. `category` returns `category`, `use_when`, and `tools` with each
  tool's `name` and `description`; an unknown name raises `unknown_category`. `tool_name`
  returns `{name, description, parameters}`, each parameter with `name`, `type`, `required`,
  `description`, and any schema bounds (`default`, `enum`, `minimum`, `maximum`, `items`, and
  the like); an unknown name raises `unknown_tool`. It does not list error codes; a tool names
  its code and a next step in its message. Passing both raises `invalid_params`. Every
  `rex_*` tool appears in exactly one category: the module that defines it, or `other` for a
  registered tool no category module defines. The index lists `other` only when it has tools;
  `category=other` is always valid. `rex_help` reads the live tool registry, so `rx_data_find`
  and `rx_multi_find` appear, under `scanning`, only while the native plugin is loaded (other
  `rx_` tools are never listed); otherwise `tool_name` for one raises `unknown_tool`.
- `rex_annotate_many`, `rex_component_add_functions`, `rex_type_library_export`, and
  `rex_type_library_import` return count fields `applied`, `failed_count`, and `total`.
  The type-library tools also return a `failed` list.
- `rex_type_library_export` lists `exported` as `{name, type}` entries for `kind="types"`
  (`type` is the rendered type, truncated; type names are unique in a view, so no `address`
  or `alternatives`). For `kind="objects"` each entry is `{name, type, address,
  alternatives}`: `address` is the chosen object's hex address and `alternatives` lists the
  other same-name candidates as `{address, type}`, empty when none. A name resolves to a
  function first, else a data variable whose type is not void, else a void data variable
  (which still exports and shows as `void`), else a data variable at an import address slot
  (an `ImportAddressSymbol`, e.g. a GOT entry, whose type describes the slot and not the
  imported object). Ties within a tier go to the lowest address, and `alternatives` follows
  the same order (functions, non-void data variables, void data variables, import slots, each
  by ascending address).
- `rex_uidf_set_many` stages every item, including each row's rendered `value`, before it
  informs any value, so an unexpected staging error (a value that cannot render) raises for
  the whole call with nothing informed; expected item errors stay per-item rows.
  `rex_uidf_set` renders its `value` first the same way.

### Response fields

The top-level fields of each response, beyond the paging and truncation rules above.
Addresses are hex strings, and a function entry is `{start, name}`. A resolved function entry
adds `also_containing` and `same_name`, both lists of function entries; every `function`
field below that a tool fills from an address is one. Fields marked `?` are present only on
some rows.

- `analysis_complete` (`rex_annotate_many`, `rex_memory_write`, `rex_undo`, `rex_redo`,
  `rex_uidf_set`, `rex_uidf_set_many`, `rex_uidf_clear`): the tool reanalyzes after a change and
  waits up to 10 s for every function the change left stale. False means the deadline passed; wait
  with `rex_analysis_wait` before reading IL. True when nothing changed.
- `rex_analysis_wait`: `completed`, `elapsed_ms`, `progress` (`{state, count, total}`),
  `function_count`, `in_flight` (`{start, name, analysis_time_ms}`, at most 10), and
  `truncated` (more in-flight functions than listed).
- `rex_annotate_many`: `applied`, `failed_count`, `total`, `analysis_complete`, and
  `results` rows `{addr, ok, function?, error?}`; `function` is the resolved function entry
  read after the batch applies, so it carries the new name and its `same_name`, present on
  every row that passed validation. A `comment` lands at the exact `addr` the item named; `name`
  and `prototype` apply to the whole function. A rename keeps the symbol's type, binding,
  namespace, and ordinal; only the name changes.
- `rex_binary_close`: `closed` (always true; a failed close raises `close_failed`) and
  `path`, the closed file's full filename as the core reports it (truncated).
- `rex_call_paths`: `from_function` and `to_function` (resolved function entries for
  `from_addr` and `to_addr`), `reachable`, `paths` (lists of function entries), `truncated`,
  and `explored` (functions expanded during the search). `direction` defaults to `callers`.
  Both directions are bounded by `max_depth` and `max_paths`. Edges come from the core's call
  graph and include tail calls. A function called from several sites is one edge, so a path
  is never listed twice. Code pointers passed as data and imports with no function object are
  not edges.
- `rex_component_add_functions`: `path`, `applied`, `failed_count`, `total`,
  and `results` rows `{start, name, also_containing, same_name, added}`.
- `rex_component_create`: `path`, `display_name`, `guid`.
- `rex_component_get`: `path`, `guid`, `display_name`, `parent_path` (null for the root),
  `functions`, `function_count`, `truncated`, `children` (`{path, display_name, guid}`), and
  `children_truncated`.
- `rex_constant_find`: `total`, `truncated`, and `functions` of `{start, name, addresses,
  addresses_truncated}`.
- `rex_data_find`, `rx_data_find`: `total`, `truncated`, and `matches` (addresses).
  `rx_multi_find`: `total` (the sum), `truncated` (any pattern truncated), and `results` of
  `{pattern, total, truncated, matches}`, one per input pattern.
- `rex_data_read`: `address`, `length`, `bytes_read`, `data` (hex), `complete` (all requested
  bytes read). An unmapped start returns zero bytes; a short read gives no gap locations.
- `rex_decompile_many`: `functions` of `{index, start, name, also_containing, same_name,
  lines, truncated}` and `errors` of `{index, address, error: {code, message}}`; `index` is
  the position in the request; every entry lands in exactly one list, and an address that
  fails to resolve is an `errors` row, as is a function with no HLIL (`no_hlil`: skipped
  analysis, which waiting will not fix, or pending analysis, which a retry may). Only a
  non-list `functions` or a count outside 1-1024 raises for the whole call. `lines` starts with
  the function's signature, then the HLIL body; the signature counts toward `max_lines`.
- `rex_disasm_at`: `function`, `instructions` (`{address, text}`), `truncated`.
  `rex_disasm_many`: `windows` of `{address, index, function, instructions, truncated}`,
  `errors` of `{index, address, error: {code, message}}`, `truncated`, `next_offset` (an
  index into the input addresses, null unless `truncated`; continue from it). A bad address
  is an `errors` row and does not fail other items.
- `rex_eval_python`: `stdout`, `stdout_truncated`, `stdout_key`, `stdout_length`, `result`,
  `result_truncated`, `result_key`, `result_length`, `error`, `error_truncated`,
  `error_location`. `rex_eval_result`: `key`, `value`, `total`, `truncated`, `next_offset`.
- `rex_export_disasm`: `function`, `path`, `bytes_written`, `lines`, `truncated`.
  `rex_export_symbols`: `path`, `bytes_written`, `rows`, `truncated`, `total`.
- `rex_find_functions_by_pattern`: `total`, `truncated`, and `functions` of `{start, name,
  match_count, addresses, addresses_truncated}`.
- `rex_function_constraints`: `function`, `total`, `truncated`, and `constraints` of
  `{address, operator, constant, char, subject, subject_text}`. `operator` is `==` or `!=`.
  `constant` and a `load` `offset` render the value the expression computes: a zero or sign
  extension of a constant is applied at its outer width first, then shown at that width.
  `constant` is unsigned hex (-1 is `0xffffffff` in four bytes and `0xffffffffffffffff` in
  eight; `sx.q` of a four-byte -1 is `0xffffffffffffffff`, `zx.q` of `0xffffffff` is
  `0xffffffff`). `char` is the printable ASCII character of that value, else null. A constant
  with no core size (width 0, such as `true`) keeps its value as stated. `subject` is
  `{kind: "load", base, offset}`. `base` is null for an absolute address, whose `offset` is
  unsigned hex at its width like every address. For a base variable plus a displacement,
  `offset` is the displacement as signed two's complement at its width: a four-byte
  `0xfffffff8` prints `-0x8`, but `zx.q` of it prints `0xfffffff8`. Both are null, and `text`
  is added, when the address is not a base variable plus a constant. Other subjects are
  `{kind: "variable", variable, definition?}` with `definition` `{address, load}` when the
  variable's only definition is a load, or `{kind: "expression", text}`.
- `rex_function_containing`: `functions` (at most 64, ascending start) and `truncated`.
  `rex_function_define`: `start`, `name`, `analyzed`, `waited_ms`.
  `rex_function_define_many`: `defined` of `{start, name, analyzed}`, `failed` (addresses the
  core refused), `pending` (addresses not yet analyzed), `waited_ms`.
  `rex_function_undefine`: the removed function's resolved entry.
- `rex_hlil_grep`: `scanned`, `truncated`, `scan_incomplete`, `skipped_no_hlil`, `functions`
  of `{start, name, lines}`, and `next_offset`: the index of the first function the next call
  should start from, set when `truncated` or `scan_incomplete` is true, null when the scan
  reached the end of the view.
- `rex_hlil_statements`: `function`, `total`, `truncated`, and `statements` of `{address,
  index, text}`.
- `rex_kv_delete`: `key`. `rex_kv_get`: `key`, `value`, `truncated`. `rex_kv_set`: `key`,
  `length`, `value` (preview), `truncated`. `rex_kv_set` stores under the `rex/` metadata
  prefix with the core's persistent-flag default, so values serialize into the BNDB snapshot
  and survive reload.
- `rex_memory_write`: `address`, `bytes_written`, `analysis_complete`.
- `rex_mlil_uses`: `function`, `definition_site` (the queried address), and `variables`, each
  `variable`, `storage`, `type`, `definitions` (addresses of every definition the core records
  for it, ascending), `total`, `truncated`, and `uses` of `{address, operation, text}`.
- `rex_parameter_variables`: `function`, `parameter`, `storage` (one entry per matching
  variable in the function's variable order), `definitions` (a flat list of addresses over
  all matching variables, ascending), and `carriers` of `{variable, address, text}`.
- `rex_redo`: `redone`, `actions`, `actions_truncated`, `undo_left`, `redo_left`,
  `analysis_complete`. `rex_undo`: `undone`, `actions`, `actions_truncated`, `undo_left`,
  `redo_left`, `analysis_complete`. `undone` and `redone` are false when the stack was empty
  and nothing changed. `actions` is the core's summary text of each action in the entry that
  was undone or redone, in the core's order, at most 32; `actions_truncated` says the entry
  had more. Both are empty and false when nothing changed.
- `rex_relocation_at`: `address`, `count`, and `relocations` of `{address, size, type,
  addend, implicit_addend, pc_relative, target, reloc, symbol}` (`symbol` is null when the
  relocation has none).
- `rex_report_show`: `title`, `length`, `preview`, `truncated`. The markdown can link into
  the view with `binaryninja://?expr=...`.
- `rex_string_read_at`: `address`, `length`, `type`, `value`, `truncated`.
  `rex_string_search`: `total`, `truncated`, and `strings` of `{address, length, type,
  value}`. `rex_string_refs`: `total`, `truncated`, and `strings` of `{value, location,
  derived, refs, refs_truncated}`, `location` being `{type, address, length}` or null and each
  ref `{function_start, function_name, address}` (the first two are null outside a function).
- `rex_struct_from_access`: `name`, `registered`, `width`, `member_count`, `members` of
  `{offset, name, type}`, `truncated`. It sees only offset accesses analysis has already
  recorded, and it registers the inferred struct under an auto type id.
- `rex_tag_list`: `total`, `truncated`, and `tags` of `{address, tag_type, data,
  data_truncated}`. `rex_tag_set`: `address`, `tag_type`, `data`, `data_truncated`, `length`.
  A missing `tag_type` is created when `create_missing` is true (the default), and raises
  `tag_type_not_found` otherwise.
- `rex_type_library_export`: `path` (the resolved file), `bytes_written`, `library`
  (truncated), `exported`, `failed` (`{requested, reason}`), `applied`,
  `failed_count`, `total`. `rex_type_library_import`: `library` (null when none loaded),
  `imported` of `{requested, resolved}`, `failed`, `applied`, `failed_count`, `total`.
- `rex_uidf_clear`: `function`, `variable` (null when clearing the whole function), `cleared`,
  `analysis_complete`, and, when a variable is named, `definition_sites`. A failure at any site
  rolls back the sites already cleared in that call. `rex_uidf_list`: `function` (resolved entry,
  null when listing the whole view), `total`, `truncated`, and `values` of `{function, variable,
  definition_site, architecture, state, value}`, where each value's `function` is a plain function
  entry. `rex_uidf_set`: `function`, `variable`, `definition_site`, `value` (`{state, rendered}`),
  `analysis_complete`, `lines`, `truncated`. `rex_uidf_set_many`: `function`, `applied`, `failed`,
  `total`, `results` of `{index, variable, ok, definition_site?, value?, error?}`,
  `analysis_complete`, `lines`, `truncated`.
- `rex_xrefs_to`: `total`, `truncated`, `code_refs` of `{function_start, function_name, arch,
  address, kind}` (`kind` is `call` or `code`; the first three are null outside a function),
  and `data_refs` of `{source}`.

### Parameters

- Numeric parameters such as `limit`, `length`, `offset`, `max_depth`, `max_paths`,
  `max_functions`, and `max_chars` are range-checked, not clamped; invalid values return
  `invalid_params`.
- Batch caps: `rex_annotate_many`, `rex_function_define_many`, `rex_uidf_set_many`, and
  `rex_component_add_functions` take 1-128 items, `rex_disasm_many` 1-64 addresses, and
  `rex_decompile_many` 1-1024 functions. `before` and `after` of `rex_disasm_at` and
  `rex_export_disasm` are 0-4096 instructions. `rx_multi_find` takes 1-64 patterns: an empty
  list returns `invalid_params`, a longer one `too_many_patterns`.
- Over-cap strings return parameter-specific codes such as `pattern_too_large`,
  `key_too_large`, `value_too_large`, `data_too_large`, `name_too_large`, or
  `library_name_too_large`. Each `rx_multi_find` entry is capped at 8,192 characters like
  `rex_data_find`'s `pattern`, and an over-cap entry returns `pattern_too_large` naming its
  index. Over-cap component paths, type-name list entries, and export filenames return
  `invalid_params` instead.
- An error a caller can act on names the next step in its message: `analysis_pending` names
  `rex_analysis_wait`, `no_function` for a mapped address names `rex_function_define` (except
  for `rex_function_undefine`, which gives only the diagnosis), `ambiguous_definition` names
  `def_address`, and `not_found` from `rex_eval_result` names the `stdout_key` and
  `result_key` fields of `rex_eval_python`.
- A string containing a NUL (U+0000) returns `invalid_params` with the message `<parameter>
  must not contain NUL bytes`. This covers key-value keys and values, report titles and
  markdown, tag types and data, annotation names, comments, prototypes and addresses,
  component, structure, and type-library names and paths, type names, the `value` and
  `def_address` string of each `rex_uidf_set_many` item and the `value` of `rex_uidf_set`,
  export filenames, and every entry of an address-expression list (named like
  `functions[1]`). A batch tool reports it in the row of the bad item. Scalar address
  parameters, including the `def_address` of `rex_uidf_set`, are parsed by the built-in server
  first, so this rule cannot cover them. Patterns, regular expressions, variable names, and
  eval code are unchanged.
- The `filename` of `rex_export_disasm`, `rex_export_symbols`, and `rex_type_library_export`
  is required with no default, and the schema lists it under `required`. It raises
  `invalid_params` for an empty name, an absolute path, a backslash, a NUL byte, a `..`
  component, a last path component that is `.` or empty (a trailing `/`), or a component over
  255 bytes. Before any data is computed it also raises `invalid_params` for a name that is
  an existing directory and for a name whose parent is not an existing directory (missing, or
  a regular file); only the export root itself is created on demand. `path_escape` is raised
  only after resolution, when a symlink inside the export root points outside it, and
  `export_failed` when the root or file cannot be written.
- `rex_type_library_export` raises `invalid_params` for an empty `library_name`, for `names`
  (not a list, not 1-128 entries, an empty or over-long entry, or a non-string entry), and
  for `kind`. `rex_uidf_set_many` raises `invalid_params` when no analyzed function contains
  `function` or the item list is invalid. Each item can fail in its `results` row with
  `invalid_params`, `no_mlil`, `no_variable`, `ambiguous_definition`, `definition_not_found`,
  or `set_failed`.
- A regular expression that does not compile returns `invalid_regex`; the message is
  `Invalid regular expression parameter '<name>': <reason>` and names the bad parameter:
  `pattern` (`rex_string_search` and `rex_string_refs` with `regex=true`), `regex`
  (`rex_hlil_grep`), or `function_filter` (`rex_hlil_grep`, `rex_constant_find`).
  `rex_hlil_grep` checks `regex` before `function_filter`.
- Hex byte patterns (`rex_data_find`, `rx_data_find`, `rex_find_functions_by_pattern`,
  `rx_multi_find`) are separator-delimited bytes written as exactly two ASCII hex digits, or
  `??` for any byte; separators inside a byte are ignored. A separator is any character
  Python's `str.isspace()` accepts: U+0009-U+000D, U+001C-U+001F, U+0020, U+0085, U+00A0,
  U+1680, U+2000-U+200A, U+2028, U+2029, U+202F, U+205F, and U+3000. Any other token (`+f`,
  `-1`, `0x`, `f_`, non-ASCII digits, `?5`) returns `invalid_pattern` naming the token. A
  `pattern` that is not a string returns `invalid_params`. A `section` name containing a NUL
  returns `section_not_found`, like any unknown name. The `section_not_found` and
  `invalid_pattern` messages show an echoed NUL as U+FFFD, because the core cuts a message at
  its first NUL. The `no_variable`, `unknown_tool`, `unknown_category`, and eval `not_found`
  messages, and the `kind` and `format` `invalid_params` messages, do the same; other tools'
  messages are not rewritten.
- `rex_constant_find` `value` is an integer (0 to 18446744073709551615) or a string: `0x` or
  `0X`, then 1-16 hex digits in either case. A client that reads JSON numbers as doubles
  rounds the integer maximum to 18446744073709552000, so send the hex string for values above
  2^53. A value that is not an integer or string (a boolean, float, null, list, or object),
  any other string, a sign, whitespace, an empty digit list, or more than 16 digits returns
  `invalid_params` naming the violation; strings are never coerced.
- `rex_constant_find` matches constants in the core's linear-view disassembly lines (Search >
  For Constant), never IL or raw bytes. A hit counts only on an instruction line (tokens
  include an instruction token); function header lines and the `{ Continuation of function
  ... }`, `{ Falls through into ... }`, and `{Case ...}` annotation lines never count. The core
  also matches `value` 0 on an instruction with no zero operand, for example `xor eax, eax
  {0x0}` (a register's known value in an annotation) or a line with a string annotation. For
  `value` 0 the tool keeps a hit only when a token that belongs to an operand and carries a
  number or address (integer, possible address, code-relative address, floating point,
  character constant, enumeration member, code or data symbol, import, or external symbol) is
  0; a line whose tokens carry no operand index is kept. The optional boolean
  `include_non_operand_hits` (default false) returns the dropped hits too; it is allowed only
  with `value` 0, else `invalid_params`. Dropped hits take no slot in `total`, paging, the
  address cap, or `truncated`. With it true, the extra hits depend on how much IL the view has
  generated, so counts can grow after decompiling; default results do not. Other values are
  not filtered. A hit is listed under the function the core attributes the line to, not by the
  lowest-start rule, so in overlapping code one address can appear under several functions. A
  rare or absent value makes the core scan the whole view.
