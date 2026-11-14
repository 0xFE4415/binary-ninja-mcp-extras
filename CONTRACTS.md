# Repository instructions

## MCP tool contract

Normative response and parameter contract for MCP tools. If implementation and contract differ, do not silently change the contract: fix the implementation or raise the discrepancy. Usage guidance lives in `README.md`.

Addresses are hex strings. Function entry: `{start, name}`. Resolved function entry: adds `also_containing`, `same_name`; every `function` field filled from an address is one. `?` marks a field present only on some rows.

### Shared rules

#### Listings and paging

- Stock `bn_*` listings return a Markdown table in `content`, not `structuredContent`. `rex_*` listings return structured data.
- Paged tools accept `limit`/`offset`, never echo them. Numeric parameters (`limit`, `length`, `offset`, `max_depth`, `max_paths`, `max_functions`, `max_chars`) are range-checked, never clamped; invalid returns `invalid_params`.

| Tools | Count fields | Rule |
| --- | --- | --- |
| `rex_string_search`, `rex_data_find`, `rx_data_find`, `rex_string_refs`, `rex_uidf_list` | `total`, `truncated` | Scan stops at first result past page; truncated `total` is a lower bound |
| `rex_xrefs_to` | `total`, `truncated` | Same lower bound, over fetched refs only |
| `rx_multi_find` | `total`, `truncated` | Lower bound per pattern; `total` is the sum; `truncated` if any pattern is |
| `rex_tag_list`, `rex_kv_list`, `rex_export_symbols` | `total`, `truncated` | Exact `total` |
| `rex_function_constraints`, `rex_hlil_statements`, `rex_mlil_uses` | `total`, `truncated` | Full list built; exact `total` |
| `rex_component_get` | `function_count` | Pages functions; exact `function_count` instead of `total` |
| `rex_constant_find`, `rex_find_functions_by_pattern` | `total`, `truncated` | Function scan, below |
| `rex_hlil_grep` | `truncated`, no `total` | Function scan, below |

- Function scans (`rex_constant_find`, `rex_find_functions_by_pattern`, `rex_hlil_grep`) stop at the first result past the page: `truncated` means exactly "another matching function exists beyond it".
  - `total` (not `rex_hlil_grep`): matching functions seen before the scan stopped; exact once `truncated` is false, so an empty page with `total` at or below `offset` is out of range, not an empty result.
  - While `truncated`: each function's `addresses` (`rex_constant_find`), `match_count` and `addresses` (`rex_find_functions_by_pattern`) are lower bounds (scan stopped before every hit of the page's functions, e.g. a cold block after its function).
  - Functions keyed by start address and architecture: rows can share a `start` across architectures.
  - Echoed `addresses` cap per function: 6 distinct for `rex_constant_find` (each at first occurrence), 5 for `rex_find_functions_by_pattern`; `addresses_truncated` true only when a further distinct address exists.
- `rex_xrefs_to` fetches at most 501 code and 501 data refs, sorts each by address, pages the combined list code refs first. Counts cover fetched refs only; omitted refs are not necessarily higher addresses; `truncated` can be false.
- `rex_hlil_grep`:
  - `scan_incomplete`: `max_functions` render budget ran out before the whole view was scanned; matches past the page may exist though `truncated` is false.
  - `skipped_no_hlil`: always an integer; functions in the scanned range that passed `function_filter` but had no HLIL (not in `scanned`, not searched), each counted in exactly one page; filtered-out functions never count.
  - `offset`/`next_offset` count functions in the view, not matches. Pass the cursor back as `offset`; keep paging while either flag is set. A call renders at most `max_functions` functions.
  - `limit=0`, `max_functions=0` are probes. `max_functions=0` scans nothing: `scan_incomplete` with `next_offset` equal to `offset` when `offset` is below the function count, else `scan_incomplete` false and null `next_offset`. `limit=0` scans to the first matching function and returns `next_offset` at it; with no match inside the budget it ends `scan_incomplete` at the first unscanned function. A paging loop must pass at least 1 for both, or it stalls at a match.

#### Strings and truncation

- Returned strings usually keep 512 characters, then append `... [N chars truncated]` (suffix is additional). Larger caps (characters):

| Field | Cap |
| --- | --- |
| `rex_eval_python.stdout`, `rex_kv_get.value` | 65,536 |
| `rex_eval_python.result` | 16,384 |
| `rex_string_read_at.value` | `max_chars`, up to 4,096 (default 512) |
| `rex_eval_python.error_location.text` | 200 |

| Flag | Meaning |
| --- | --- |
| `stdout_truncated`, `result_truncated`, `error_truncated` | Matching `rex_eval_python` field clipped |
| `data_truncated` | `data` clipped in `rex_tag_list`/`rex_tag_set` |
| `truncated` | Value clipped in `rex_kv_set`/`rex_kv_get`, `rex_report_show.preview`, `rex_string_read_at.value`; for `rex_eval_result`, more text remains to page; otherwise a tool-specific omission |
| `refs_truncated` | `rex_string_refs` returns at most 64 refs per string |
| `children_truncated` | `rex_component_get` returns at most 256 children |

#### Function resolution

Tools resolving an address expression to a function (`rex_function_constraints`, `rex_hlil_statements`, `rex_mlil_uses`, `rex_parameter_variables`, `rex_uidf_set`, `rex_uidf_set_many`, `rex_uidf_clear`, `rex_uidf_list`, `rex_disasm_at`, `rex_disasm_many`, `rex_decompile_many`, `rex_export_disasm`, `rex_call_paths`, `rex_function_undefine`, `rex_component_add_functions`, `rex_annotate_many`) pick the containing function with the lowest start; architecture name breaks ties between equal starts; never the core's undocumented order (an address can lie in several functions, e.g. a cold or outlined block and its parent).

- `rex_find_functions_by_pattern` credits each hit to the same pick, so overlapping code counts once.
- The result is a resolved entry: `also_containing` (other functions containing the address) and `same_name` (other functions with the chosen name), each `{start, name}` by ascending start, at most 64.
- `rex_function_containing` lists every containing function in that order; its first entry is the pick.
- A function name in an address expression is ambiguous too (the core resolves it silently to one address); `same_name` shows it.

#### Analysis state

- `no_mlil` (`rex_function_constraints`, `rex_mlil_uses`, `rex_parameter_variables`, uidf setters and clearers resolving a variable name) and `no_hlil` (`rex_hlil_statements`, per item `rex_decompile_many`) distinguish skipped from pending analysis.
  - Core reports `analysis_skipped`: message says skipped, names the cause from `analysis_skip_reason` (user override, size, time, or update-count limit, suppressed new-function analysis, `analysis.mode`, suspended pipeline), does not advise waiting.
  - Otherwise pending: message advises `bn_analysis_update_and_wait` or a bounded `rex_analysis_wait`.
- `analysis_complete` (`rex_annotate_many`, `rex_memory_write`, `rex_undo`, `rex_redo`, `rex_uidf_set`, `rex_uidf_set_many`, `rex_uidf_clear`): the tool reanalyzes after a change and waits up to 10 s for every function left stale. False: deadline passed; use `rex_analysis_wait` before reading IL. True when nothing changed.

#### NUL bytes

- A string containing NUL (U+0000) returns `invalid_params`, message `<parameter> must not contain NUL bytes`. Covers: key-value keys and values; report titles and markdown; tag types and data; annotation names, comments, prototypes, addresses; component, structure, type-library names and paths; type names; `value` and `def_address` of each `rex_uidf_set_many` item and `value` of `rex_uidf_set`; export filenames; every entry of an address-expression list (named like `functions[1]`).
- Batch tools report it in the bad item's row.
- Not covered: scalar address parameters, including `def_address` of `rex_uidf_set` (parsed first by the built-in server); patterns, regular expressions, variable names, eval code.
- A `section` name with NUL returns `section_not_found`, like any unknown name.
- The core cuts messages at the first NUL, so an echoed NUL shows as U+FFFD in: `section_not_found`, `invalid_pattern`, `no_variable`, `unknown_tool`, `unknown_category`, eval `not_found`, and the `invalid_params` messages for `kind`, `format`, `operators`. Other tools' messages are not rewritten.

#### Input limits

| Parameter | Limit |
| --- | --- |
| Items of `rex_annotate_many`, `rex_function_define_many`, `rex_uidf_set_many`, `rex_component_add_functions` | 1-128 |
| Addresses of `rex_disasm_many` | 1-64 |
| Functions of `rex_decompile_many` | 1-1024; a non-list or out-of-range count raises for the whole call |
| Patterns of `rx_multi_find` | 1-64; empty `invalid_params`, longer `too_many_patterns` |
| `before`, `after` of `rex_disasm_at`, `rex_export_disasm` | 0-4096 instructions |
| `max_lines` of `rex_export_disasm` | max 8193 (4096 + 4096 + anchor), default 200 |
| `names` of the type-library tools | 1-128 strings, none empty or over-long |
| `limit` of `rex_eval_result` | 1-65,536 characters (default 65,536) |
| `rex_data_find` `pattern`; each `rx_multi_find` entry | 8,192 characters |

- Over-cap strings return `pattern_too_large`, `key_too_large`, `value_too_large`, `data_too_large`, `name_too_large`, or `library_name_too_large`. Over-cap `rx_multi_find` entry: `pattern_too_large` naming its index. Over-cap component paths, type-name list entries, export filenames: `invalid_params`.

#### Error codes

Actionable errors name the next step in the message.

| Code | Raised when |
| --- | --- |
| `invalid_params` | Parameter out of range, malformed, or containing NUL |
| `invalid_regex` | Regex does not compile. Message `Invalid regular expression parameter '<name>': <reason>`; `<name>` is `pattern` (`rex_string_search`, `rex_string_refs` with `regex=true`), `regex` (`rex_hlil_grep`), or `function_filter` (`rex_hlil_grep`, `rex_constant_find`). `rex_hlil_grep` checks `regex` first |
| `analysis_pending` | Message names `rex_analysis_wait` |
| `no_function` | Mapped address has no function; message names `rex_function_define` (`rex_function_undefine` gives only the diagnosis) |
| `ambiguous_definition` | Message names `def_address` |
| `not_found` | `rex_eval_result` key missing or evicted; message names `stdout_key`, `result_key` of `rex_eval_python` |

Other codes live with their tool: `no_mlil`/`no_hlil` (Analysis state), `invalid_pattern` (Hex byte patterns), `section_not_found` (NUL bytes), `too_many_patterns`, `*_too_large` (Input limits), `no_variable`, `definition_not_found`, `set_failed` (Variables and storage, UIDF tools), `unknown_category`/`unknown_tool` (`rex_help`), `write_failed`/`relocation_overlap` (`rex_memory_write`), `path_escape`/`export_failed` (Export files), `close_failed` (`rex_binary_close`), `type_not_found`/`not_a_structure`/`create_failed` (`rex_struct_from_access`), `tag_type_not_found` (Tag tools), `no_string` (String tools).

#### Hex byte patterns

- `rex_data_find`, `rx_data_find`, `rex_find_functions_by_pattern`, `rx_multi_find`: separator-delimited bytes, each exactly two ASCII hex digits or `??` (any byte); separators inside a byte are ignored.
- Separator: any character Python's `str.isspace()` accepts: U+0009-U+000D, U+001C-U+001F, U+0020, U+0085, U+00A0, U+1680, U+2000-U+200A, U+2028, U+2029, U+202F, U+205F, U+3000.
- Any other token (`+f`, `-1`, `0x`, `f_`, non-ASCII digits, `?5`) returns `invalid_pattern` naming the token. Non-string `pattern`: `invalid_params`.

#### Export files

- Export root: `exports` inside `binaryninja.user_directory()`, resolved once at import; when that returns `None` or an empty string, `~/.binaryninja/exports`. It follows `user_directory()`, so exports can sit at a different path than before on macOS, Windows, and portable installs.
- `filename` of `rex_export_disasm`, `rex_export_symbols`, `rex_type_library_export`: required, no default, listed under `required` in the schema.
  - `invalid_params` for: empty name, absolute path, backslash, NUL byte, `..` component, last component `.` or empty (trailing `/`), component over 255 bytes.
  - Before any data is computed, `invalid_params` also for a name that is an existing directory, or whose parent is not an existing directory (missing, or a regular file). Only the export root is created on demand.
  - `path_escape`: only after resolution, when a symlink inside the root points outside it. `export_failed`: root or file cannot be written.

#### Variables and storage

- `storage` (`rex_mlil_uses`, `rex_parameter_variables`) is one of:
  - `{source: "register", register}`: register name from the function's architecture
  - `{source: "stack", stack_offset}`: signed core offset
  - `{source: "flag", flag}`: architecture's flag name; a temporary flag (storage with bit 31 set, variable `condN`) reads `temp flag N`, N = storage minus 0x80000000
  - `{source: "composite_return_value" | "composite_parameter", storage}`: raw core value
- `no_variable` for a name the function lacks (`rex_parameter_variables`, uidf setters and clearers): lists the function's variable names; names match exactly. A name the function has but the MLIL never defines (saved register, stack local): `no_variable` saying it has no definition sites.
- A declared parameter with no MLIL definition is defined at the function start, after the variables the entry instruction defines, in parameter order.
  - Uidf setters and clearers use it as the only site; `rex_uidf_set` reports it as `definition_site`; `$here` resolves to it; the value holds from before the entry instruction.
  - Any other `def_address` for it: `definition_not_found` naming the function start.
  - `rex_uidf_clear` clears every site, before or after the instruction, including values set outside the plugin.

### Tools

Top-level response fields and tool-specific rules. Shared rules apply to every entry.

#### Field-only tools

| Tool | Fields |
| --- | --- |
| `rex_analysis_wait` | `completed`, `elapsed_ms`, `progress` (`{state, count, total}`), `function_count`, `in_flight` (`{start, name, analysis_time_ms}`, at most 10), `truncated` (more in flight than listed); `timeout_ms` defaults to 10000 |
| `rex_binary_close` | `closed` (always true; failure raises `close_failed`), `path` (closed file's full filename per the core, truncated) |
| `rex_component_add_functions` | `path`, `applied`, `failed_count`, `total`, `results` of `{start, name, also_containing, same_name, added}` |
| `rex_component_create` | `path`, `display_name`, `guid` |
| `rex_component_get` | `path`, `guid`, `display_name`, `parent_path` (null for root), `functions`, `function_count`, `truncated`, `children` (`{path, display_name, guid}`), `children_truncated` |
| `rex_data_find`, `rx_data_find` | `total`, `truncated`, `matches` (addresses) |
| `rx_multi_find` | `total`, `truncated`, `results` of `{pattern, total, truncated, matches}` per input pattern; each `pattern` returned unchanged |
| `rex_data_read` | `address`, `length`, `bytes_read`, `data` (hex), `complete` (all requested bytes read); unmapped start returns zero bytes; short read gives no gap locations |
| `rex_disasm_at` | `function`, `instructions` (`{address, text}`), `truncated` |
| `rex_disasm_many` | `windows` of `{address, index, function, instructions, truncated}`, `errors` of `{index, address, error: {code, message}}`, `truncated`, `next_offset` (index into input addresses; null unless `truncated`; continue from it); a bad address is an `errors` row and fails no other item |
| `rex_export_disasm` | `function`, `path`, `bytes_written`, `lines`, `truncated`; file lines are `0x` lowercase hex address, two spaces, instruction text (`0x400084  sub     rsp, 0x18`); 4 MiB file cap drops trailing lines |
| `rex_find_functions_by_pattern` | `total`, `truncated`, `functions` of `{start, name, match_count, addresses, addresses_truncated}` |
| `rex_function_containing` | `functions` (at most 64, ascending start), `truncated` |
| `rex_function_define` | `start`, `name`, `analyzed`, `waited_ms` |
| `rex_function_define_many` | `defined` of `{start, name, analyzed}`, `failed` (addresses the core refused), `pending` (not yet analyzed), `waited_ms` |
| `rex_function_undefine` | the removed function's resolved entry |
| `rex_hlil_grep` | `scanned`, `truncated`, `scan_incomplete`, `skipped_no_hlil`, `functions` of `{start, name, lines}`, `next_offset` (first function the next call starts from; set when `truncated` or `scan_incomplete`, null at end of view) |
| `rex_hlil_statements` | `function`, `total`, `truncated`, `statements` of `{address, index, text}` |
| `rex_kv_get` | `key`, `value`, `truncated` |
| `rex_parameter_variables` | `function`, `parameter`, `storage` (one per matching variable, in variable order), `definitions` (flat ascending addresses over all matching variables), `carriers` of `{variable, address, text}` |
| `rex_relocation_at` | `address`, `count`, `relocations` of `{address, size, type, addend, implicit_addend, pc_relative, target, reloc, symbol}` (`symbol` null when none) |
| `rex_report_show` | `title`, `length`, `preview`, `truncated`; markdown can link into the view with `binaryninja://?expr=...` |
| `rex_string_search` | `total`, `truncated`, `strings` of `{address, length, type, value}` |
| `rex_tag_set` | `address`, `tag_type`, `data`, `data_truncated`, `length`; missing `tag_type` is created when `create_missing` is true (default), else `tag_type_not_found` |
| `rex_undo` | `undone`, `actions`, `actions_truncated`, `undo_left`, `redo_left`, `analysis_complete` |
| `rex_redo` | `redone`, `actions`, `actions_truncated`, `undo_left`, `redo_left`, `analysis_complete` |
| `rex_xrefs_to` | `total`, `truncated`, `code_refs` of `{function_start, function_name, arch, address, kind}` (`kind` is `call` or `code`; first three null outside a function), `data_refs` of `{source}` |

- `rex_undo`/`rex_redo`: `undone`/`redone` false when the stack was empty and nothing changed. `actions`: core's summary text of each action in the entry, core order, at most 32; `actions_truncated`: entry had more. Both empty and false when nothing changed.

#### `rex_annotate_many`

- Returns `applied`, `failed_count`, `total`, `analysis_complete`, `results` of `{addr, ok, function?, error?, prototype_name_ignored?}`. `function`: resolved entry read after the batch applies (new name, its `same_name`), present on every row that passed validation.
- `comment` lands at the exact `addr`; `name` and `prototype` apply to the whole function. Rename keeps the symbol's type, binding, namespace, ordinal.
- Item needs at least one of `name`, `comment`, `prototype` (an empty `comment` counts: it clears the comment); else an error row.
- `prototype` not parsing to a function type (e.g. `int`): error row naming the type class with an example (a typedef name also gets a hint to spell out the signature); nothing applied.
- A name inside a valid `prototype` is never applied. With no item `name` and a named prototype, the row carries `prototype_name_ignored` with that name; absent for an unnamed prototype (`int(int a)`) or when the item gave a `name`.

#### `rex_call_paths`

- Returns `from_function`, `to_function` (resolved entries for `from_addr`, `to_addr`), `reachable`, `paths` (lists of function entries), `truncated` (hit `max_paths`; more may exist), `depth_limited`, `explored` (functions expanded).
- `direction` defaults to `callers`; both directions bounded by `max_depth`, `max_paths`.
- `depth_limited`: true when the search stopped expanding at `max_depth` a function with an unvisited neighbor (the target counts; it is never marked visited), whether or not paths were found. Meaningful only when `truncated` is false.
- `reachable` false and `depth_limited` false: no path in the core's call graph. With `depth_limited` true, raise `max_depth`.
- Edges: core call graph, tail calls included; a function called from several sites is one edge, so no path is listed twice. Code pointers passed as data and imports with no function object are not edges.

#### `rex_constant_find`

- Returns `total`, `truncated`, `functions` of `{start, name, addresses, addresses_truncated}`; functions and example addresses in the core's hit order.
- `value`: integer 0-18446744073709551615, or string `0x`/`0X` plus 1-16 hex digits (either case). Clients reading JSON numbers as doubles round the integer maximum to 18446744073709552000: send the hex string above 2^53. Anything else (boolean, float, null, list, object, other string, sign, whitespace, empty digits, over 16 digits) returns `invalid_params` naming the violation; never coerced.
- Matches constants in the core's linear-view disassembly lines (Search > For Constant), never IL or raw bytes. A hit counts only on an instruction line (tokens include an instruction token); function header lines and `{ Continuation of function ... }`, `{ Falls through into ... }`, `{Case ...}` annotation lines never count.
- The core also matches `value` 0 on an instruction with no zero operand, e.g. `xor eax, eax {0x0}` (register's known value in an annotation) or a line with a string annotation. For `value` 0 a hit is kept only when a token that belongs to an operand and carries a number or address (integer, possible address, code-relative address, floating point, character constant, enumeration member, code or data symbol, import, external symbol) is 0; a line whose tokens carry no operand index is kept.
- `include_non_operand_hits` (boolean, default false) returns the dropped hits too; only with `value` 0, else `invalid_params`. Dropped hits take no slot in `total`, paging, the address cap, or `truncated`. When true, extra hits depend on how much IL the view has generated, so counts can grow after decompiling; default results do not. Other values are not filtered.
- A hit is listed under the function the core attributes the line to, not by the lowest-start rule: in overlapping code one address can appear under several functions.
- A rare or absent value makes the core scan the whole view.

#### `rex_decompile_many`

- Returns `functions` of `{index, start, name, also_containing, same_name, lines, truncated}`, `errors` of `{index, address, error: {code, message}}`; `index` is the request position.
- Every entry lands in exactly one list. An unresolvable address is an `errors` row, as is a function with no HLIL (`no_hlil`: skipped analysis, which waiting will not fix, or pending, which a retry may).
- `lines` starts with the signature, then the HLIL body; the signature counts toward `max_lines`.

#### Eval tools

- `rex_eval_python` returns `stdout` (always), `stdout_truncated`, `stdout_key`, `stdout_length`, `result`, `result_truncated`, `result_key`, `result_length`, `error`, `error_truncated`, `error_location`.
- Only tool reporting a whole-call exception in-band: sets `error`, nulls `result`, no tool error; captured output stays in `stdout`.
- Code runs with `bv`, `call`, `binaryninja`, `bn` in scope, compiled as `<rex_eval_python>`. Success returns an assigned `result` as Python `repr()`.
- `error` leads with the exception type: `Type: message` (bare `Type` when the message is empty).
  - `Type`: qualified name as `traceback.format_exception_only` writes it, `module.qualname`, `builtins` and `__main__` omitted: `KeyError: 'x'`, `json.decoder.JSONDecodeError: ...`, `binaryninja.mcp.ToolError: ...`.
  - Class defined in submitted code: bare qualname (`Custom: x`, `make.<locals>.Inner: n`).
  - `SystemExit`: `SystemExit: exit status <repr of code>`.
  - `ToolError`: `<type>: <code>: <message>` (just the code when the message is empty; the plain message when it has no usable string code).
  - Rendering never raises an `Exception`: an unrenderable message reads `<message unavailable>`, a type name `<unknown exception type>`, an unreadable chain link ends the chain.
  - Every `BaseException` the code raises (including `SystemExit`, `KeyboardInterrupt`, `GeneratorExit`) is reported in-band; one raised while rendering still propagates.
  - Chain follows the outermost, each link rendered like it, chosen as Python chooses: `; caused by <error>` for the explicit cause, else `; while handling <error>` for the implicit context unless suppressed (`raise X from Y`, `from None`). Stops at a repeat, or after 8 links with a final `; ...` when more follow.
  - Whole text capped like other echoes (`error_truncated`), never cutting the type.
- `error_location`: `{line, text}` for the innermost submitted-code line on the traceback (text stripped); null on success, for syntax errors (message already names the line), and when the traceback is unreadable.
- Non-null `stdout_key`/`result_key` let `rex_eval_result` page spilled text; null means no spill needed or text dropped.
  - Server keeps up to 8 spills (a call spilling both fields uses two slots), evicting oldest first; spills vanish when the server exits.
  - Each spill limited to 4,194,304 characters; larger text is dropped, key null, `*_length` still returned.
- `rex_eval_result` returns `key`, `value`, `total`, `truncated`, `next_offset`; pass the cursor as `offset` (non-negative). Missing or evicted key: `not_found`.

#### `rex_export_symbols`

- Writes the selected rows to a file; returns `path`, `bytes_written`, `rows` written, `total`, `truncated` (also covers rows dropped by the 4 MiB file cap).
- `start`, `end`: unsigned integer or address-expression string (`0x` hex included), like the built-in `IntegerExpression` type. Send a string above 2^53 (double-reading clients round). `end` must be greater than `start`.
- Negative or 2^64-or-larger `start`/`end`: rejected by the core's unsigned integer parse (`Invalid unsigned integer parameter ...`).

#### `rex_function_constraints`

- Returns `function`, `total`, `truncated`, `constraints` of `{address, operator, constant, char, subject, subject_text}`.
- `operators`: `"equality"` (default) or `"all"`; any other value returns `invalid_params` naming it. `"equality"`: `operator` is `==` or `!=`. `"all"` adds ordered comparisons spelled as in HLIL: `s<`, `s<=`, `s>=`, `s>` (signed), `u<`, `u<=`, `u>=`, `u>` (unsigned).
- Rows read subject, operator, constant: a constant on the left mirrors the operator (`5 s< x` is `s>` 5).
- Signed row adds `signed_constant`, the constant as signed two's complement at its width (`x s< -1` in four bytes: `constant` `0xffffffff`, `signed_constant` `-0x1`); other rows lack the key.
- `constant` and a `load` `offset` render the computed value: zero or sign extension of a constant applies at its outer width first, then shows at that width.
- `constant`: unsigned hex (-1 is `0xffffffff` in four bytes, `0xffffffffffffffff` in eight; `sx.q` of four-byte -1 is `0xffffffffffffffff`; `zx.q` of `0xffffffff` is `0xffffffff`). A constant with no core size (width 0, e.g. `true`) keeps its value as stated.
- `char`: printable ASCII character of that value, else null.
- `subject`:
  - `{kind: "load", base, offset}`: `base` null for an absolute address, whose `offset` is unsigned hex at its width like every address. For a base variable plus displacement, `offset` is the displacement as signed two's complement at its width (four-byte `0xfffffff8` prints `-0x8`; `zx.q` of it prints `0xfffffff8`). Both null, with `text` added, when the address is not a base variable plus a constant.
  - `{kind: "variable", variable, definition?}`: `definition` is `{address, load}` when the variable's only definition is a load.
  - `{kind: "expression", text}`.

#### `rex_help`

- No arguments: `categories`, one entry per tool module, plus `other` when it has tools, each `name`, `use_when`, `tools` names; no descriptions.
- `category`: `category`, `use_when`, `tools` with each `name`, `description`. Unknown: `unknown_category`.
- `tool_name`: `{name, description, parameters}`; each parameter `name`, `type`, `required`, `description`, schema bounds (`default`, `enum`, `minimum`, `maximum`, `items`, and the like). Unknown: `unknown_tool`.
- Passing both: `invalid_params`.
- Every `rex_*` tool is in exactly one category: its defining module, or `other` for a registered tool no category module defines. Index lists `other` only when it has tools; `category=other` is always valid.
- Reads the live registry: `rx_data_find`, `rx_multi_find` appear, under `scanning`, only while the native plugin is loaded (other `rx_` tools never listed); otherwise `tool_name` for one raises `unknown_tool`.

#### Key-value tools

- `rex_kv_delete`: `key`, `existed` (true when a value was stored before the delete; missing key is not an error and reports false; a stored value the core cannot read back still counts and is deleted).
- `rex_kv_set`: `key`, `length`, `value` (preview), `truncated`. Stores under the `rex/` metadata prefix with the core's persistent-flag default, so values serialize into the BNDB snapshot and survive reload.
- `rex_kv_list`: `total`, `truncated`, `keys` of `{key, length}`, sorted by key (code point order), paged by `limit`/`offset`.
  - Lists `bv.metadata` entries under `rex/` with the prefix stripped, skipping an empty stripped key; `prefix` keeps only keys starting with that text (no NUL).
  - `length`: character count of the full stored value; a non-string value stored by other code reports the length of its `str()` text, as `rex_kv_get` returns.
  - Reading `bv.metadata` copies every entry of the view: cost grows with all stored metadata, not just `rex/` keys.
  - A key over 512 characters is clipped with the usual suffix and unusable with the other kv tools. A key stored by foreign code with a NUL byte is listed, but `rex_kv_get` and `rex_kv_delete` reject it.
  - The core converts every entry of `bv.metadata` at once: one `rex/` or other entry of an unrecognised type makes `rex_kv_list` fail for the whole view (core raises `TypeError`); the tool does not work around it.

#### `rex_memory_write`

- Returns `address`, `bytes_written` (always equals the length of `hex_data`), `analysis_complete`.
- `write_failed`: core writes fewer bytes than requested, usually unmapped or not file-backed address. Message gives the address, requested and written counts, and says nothing was written: one undoable transaction reverts, so a short write leaves no bytes and no reanalysis runs.
- `relocation_overlap`: range overlaps a relocation; points to `rex_relocation_at`; no way to force such a write.

#### `rex_mlil_uses`

- `function` may be omitted or null: then the function containing `address`, by the lowest-start rule. `address` stays required.
- Definitions come from the core: a variable is defined at an instruction when `get_var_definitions` lists it there (assignments, split writes, field writes, call, syscall, tailcall, intrinsic outputs, forced versions). A declared parameter with no MLIL definition is defined at the function start (see Variables and storage).
- An address with no definition (call without outputs, store): `no_definition`; message lists up to 10 addresses that do define variables (`(+N more)` past that), or says the function defines no MLIL variables.
- Returns `function`, `definition_site` (the queried address), `variables`: one per defined variable, in `vars_written` order, then any further variable the core records (e.g. a field write's destination). Each: `variable`, `storage`, `type` (rendered, truncated), `definitions` (ascending addresses of every definition the core records; empty for a parameter defined at function start), `total`, `truncated`, `uses` of `{address, operation, text}`.
- Two variables can share a name; `storage` and `type` identify the entry. `limit`/`offset` page each entry's uses.
- `variable` keeps every variable with that name. `no_variable`: the instruction defines none; lists defined variables as `name (storage)`, `storage` short (register name, `stack +0x8` or `stack -0x8`, flag text, composite source and raw value).

#### String tools

- `rex_string_read_at`: `address`, `length`, `type`, `value`, `truncated`, `detected`.
  - `detected` true: analysis detected a string containing `addr`; it wins, so a mid-string `addr` returns the whole string with its own start as `address`.
  - Otherwise reads ASCII (bytes 0x01-0x7f) from `addr` (`detected` false, `type` `AsciiString`). A NUL after at most `max_chars` characters ends a complete string.
  - If the byte at `addr + max_chars` is also ASCII (0x01-0x7f): returns the first `max_chars` characters, `truncated` true, `length` equal to `max_chars`, without checking that a NUL follows, and with no `... [N chars truncated]` suffix (full length unknown).
  - Anything else (no ASCII, short run not followed by NUL, non-ASCII byte after the bound, unreadable memory): `no_string`. UTF-16 text reads as a one-character ASCII string.
- `rex_string_refs`: `total`, `truncated`, `strings` of `{value, location, derived, refs, refs_truncated}`; `location` is `{type, address, length}` or null; ref is `{function_start, function_name, address}` (first two null outside a function).
  - `only_referenced` (default false): when true skips strings with no code reference; they take no slot in `total`, paging, or `truncated`.
  - A detected string needs a code reference to its start address, so one reached only through data pointers shows none; a derived string counts its own code references.
  - The filter needs each string's references, so a call may scan every remaining string.

#### `rex_struct_from_access`

- Returns `name`, `registered`, `width`, `member_count`, `members` of `{offset, name, type}`, `truncated`.
- `name` must be an existing plain struct. Analysis records offset accesses only through variables typed as pointers to it; the tool sees only accesses already recorded.
- Redefines the type in place as a user type, in one undoable transaction, so code already using it shows the members; `registered` is `name`. An auto type (debug info, type library) becomes a user type.
- `type_not_found`: name is not a type. `not_a_structure`: not a plain struct (union, class, alias, any other type). Neither calls the core.
  - Union: message names `bn_type_union_modify`; class: `bn_type_struct_modify`.
  - Alias: names the target: to pass instead when the target is a plain struct, else as not a plain struct. An alias naming itself is reported as such.
- Inference keeps existing members. `create_failed`: the core inferred nothing, or nothing beyond the existing width and members (offset, name, type); nothing is written.

#### Tag tools

- `rex_tag_list`: `total`, `truncated`, `tags` of `{address, scope, tag_type, data, data_truncated}`.
  - Every scope: `data` (tag on a data address), `address` (one address inside a function), `function` (whole function; address is the function's start).
  - Sort: address, scope name (`address`, `data`, `function`), tag type name, tag data: stable order, `total` counts every row.
  - Scopes come from three separate core calls, not deduplicated: a tag in two scopes appears once per scope.
  - No auto/user filter: tags analysis creates are listed in `address` and `function` scopes, so a real binary can return many more rows than the data scope alone.

#### Type-library tools

- Both return `applied`, `failed_count`, `total`, `failed` list.
- `rex_type_library_export`: `path` (resolved file), `bytes_written`, `library` (truncated), `exported`, `failed` (`{requested, reason}`), `applied`, `failed_count`, `total`. `invalid_params` for empty `library_name`, bad `names` (Input limits), bad `kind`.
  - `kind="types"`: `exported` is `{name, type}` (`type` rendered, truncated); type names are unique in a view, so no `address` or `alternatives`.
  - `kind="objects"`: `{name, type, address, alternatives}`; `address` is the chosen object's hex address; `alternatives` lists other same-name candidates as `{address, type}`, empty when none.
  - Name resolves to a function first, else a data variable whose type is not void, else a void data variable (still exports, shows `void`), else a data variable at an import address slot (`ImportAddressSymbol`, e.g. a GOT entry; its type describes the slot, not the imported object). Ties within a tier go to the lowest address; `alternatives` follows the same order (functions, non-void data variables, void data variables, import slots, each by ascending address).
- `rex_type_library_import`: `library` (null when none loaded), `imported`, `failed`, `applied`, `failed_count`, `total`. `invalid_params` for bad `names` and a `kind` other than `types` or `objects`, before the library loads.
  - `kind="types"` (default): `imported` entries `{requested, resolved}`; `resolved` is the name the core inserted.
  - `kind="objects"`: names are the library's named objects as `rex_type_library_export(kind="objects")` writes them; entries `{requested, type}` (rendered, truncated). Importing an object adds the types it references to the view; it does not apply its type to any function or data variable.

#### UIDF tools

- `rex_uidf_set_many` stages every item, including each row's rendered `value`, before informing any value: an unexpected staging error (unrenderable value) raises for the whole call with nothing informed; expected item errors stay per-item rows. `rex_uidf_set` renders `value` first the same way.
- `rex_uidf_set_many`: `invalid_params` when no analyzed function contains `function` or the item list is invalid. Item rows can fail with `invalid_params`, `no_mlil`, `no_variable`, `ambiguous_definition`, `definition_not_found`, `set_failed`.

| Tool | Fields |
| --- | --- |
| `rex_uidf_clear` | `function`, `variable` (null when clearing the whole function), `cleared`, `analysis_complete`, `definition_sites` (when a variable is named); a failure at any site rolls back sites already cleared in the call |
| `rex_uidf_list` | `function` (resolved entry; null when listing the whole view), `total`, `truncated`, `values` of `{function, variable, definition_site, architecture, state, value}` (each `function` a plain entry) |
| `rex_uidf_set` | `function`, `variable`, `definition_site`, `value` (`{state, rendered}`), `analysis_complete`, `lines`, `truncated` |
| `rex_uidf_set_many` | `function`, `applied`, `failed_count`, `failed` (alias of `failed_count`, kept), `total`, `results` of `{index, variable, ok, definition_site?, value?, error?}`, `analysis_complete`, `lines`, `truncated` |
