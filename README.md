# binja-plugin

Extra MCP tools for Binary Ninja's built-in MCP server. The stock server exposes its `bn_*`
tools; this plugin registers additional tools alongside them for the workflows an AI agent
drives most: search, code/data transitions, triage annotations, and scratch state. The
Python half registers the `rex_*` tools; the Rust half (`native/`) registers the `rx_*`
tools, where native speed is measurably worth it.

## Requirements

- Binary Ninja (GUI or headless) with the built-in MCP server enabled (`ui.mcp.enabled`)
- Python 3.13+ (only for development and testing)
- The native `rx_*` tools are **opt-in**: building them additionally needs a Rust
  toolchain and clang

## Install

Clone the repository and symlink the Python package into Binary Ninja's plugin directory:

```bash
git clone git@github.com:0xFE4415/binja-plugin.git
ln -s "$(pwd)/binja-plugin/src/binja_plugin" ~/.binaryninja/plugins/binja_plugin
```

The native half is optional. To enable the `rx_*` tools as well, build and install it flat
next to the Python package:

```bash
binja-plugin/native/scripts/install.sh   # installs libbinja_plugin_native.so
```

Restart Binary Ninja and start the MCP server with `Plugins > MCP > Start Server`. MCP
clients that already connected must reconnect to see the registered tools.

## Tools

| Tool | Notes |
| --- | --- |
| `rex_string_search` | Substring/regex search over strings, with section and type filters. |
| `rex_data_find` | Hex byte pattern search (`??` wildcards) over mapped segments. |
| `rex_constant_find` | Finds constant references via the core's linear-view constant search. |
| `rex_hlil_grep` | Regular expression search across rendered HLIL text, with a resumable cursor. |
| `rex_find_functions_by_pattern` | Maps a byte pattern to the functions containing its matches. |
| `rx_data_find` | `rex_data_find` contract in native Rust (speed depends on scope; see below). |
| `rx_multi_find` | Many hex patterns in one pass via a multi-pattern automaton (Rust). |
| `rex_call_paths` | Bounded breadth-first call-path search between two functions. |
| `rex_disasm_at` | Address-anchored disassembly window, clipped at the function's edges. |
| `rex_decompile_many` | HLIL render for up to 16 functions in one batch call. |
| `rex_analysis_wait` | Bounded wait for background analysis; triage-style snapshot at expiry. |
| `rex_quick_main` | Entry point, main resolution, and main's HLIL in one fast-contact call. |
| `rex_export_disasm` | Write a function's disassembly window to a file. |
| `rex_export_symbols` | Write a symbol address range to a file in the export root. |
| `rex_type_library_import` | Attach a .bntl and import a bounded list of its type names into the view. |
| `rex_type_library_export` | Export view types/objects into a new .bntl in the export root. |
| `rex_struct_from_access` | Infer and define a struct from the view's recorded offset accesses. |
| `rex_function_containing` | List the functions containing an address. |
| `rex_function_define` | Turn the bytes at an address into a function. |
| `rex_function_undefine` | Remove the function covering an address (destructive). |
| `rex_string_read_at` | Read the detected string at an address. |
| `rex_derived_string_refs` | Code references for derived (recognizer-synthesized) strings, per-string ref cap. |
| `rex_memory_write` | Patch bytes in the binary view (destructive). |
| `rex_binary_close` | Discard unsaved changes and close the view programmatically (destructive). |
| `rex_tag_set` | Attach a GUI-visible tag at an address, creating the tag type on demand. |
| `rex_tag_list` | List the tags set on the binary view. |
| `rex_report_show` | Render a markdown report with `binaryninja://?expr=` links into the view. |
| `rex_kv_set` / `rex_kv_get` / `rex_kv_delete` | Persistent scratch key-value store. |
| `rex_component_create` | Create a component, optionally nested under an absolute path (destructive). |
| `rex_component_get` | Look up a component by path with its member functions and child components. |
| `rex_component_add_functions` | Put resolved functions into a component (destructive). |
| `rex_eval_python` | Arbitrary `binaryninja` Python scripting (destructive escape hatch). |
| `rex_undo` / `rex_redo` | Undo/redo the view's last transaction, with post-operation stack depths (destructive). |
| `rex_annotate_many` | Rename/comment/retype up to 100 functions in one undoable transaction (destructive). |

The `rx_data_find` row's speed depends on scan scope, per the project's own benchmark
([native/BENCH.md](native/BENCH.md)): ~7x when the scan covers the whole database with a
short pattern, but parity (~0.99x) on a section-scoped scan — `section` is a first-class
parameter of both tools, so for section-scoped work the native scan buys nothing.

Listing tools (`rex_string_search`, `rex_data_find`, `rex_derived_string_refs`,
`rex_tag_list`, `rex_export_symbols`, and `rex_component_get`, whose count is named
`function_count`) return `total`, `truncated`, and paginated results via `limit`/`offset`
so agents never need to page through unbounded listings. The early-stop scan tools
(`rex_constant_find`, `rex_find_functions_by_pattern`, `rex_hlil_grep`) accept
`limit`/`offset` too but return only `truncated` and the page, never a `total`: they stop
scanning as soon as the requested window is known to be complete (see the section on
scan bounds below; `rex_hlil_grep` pages through its `next_offset` cursor instead). Size
parameters (`limit`, `offset`, `max_depth`, `max_paths`, `max_functions`, `max_chars`)
are range-checked, not silently normalized: a value outside its documented range is
rejected with the MCP layer's `invalid_params` argument error. An over-cap string
argument is rejected per tool with a `*_too_large` code from the same family instead
(`pattern_too_large`, `key_too_large`, `value_too_large`, `data_too_large`,
`tag_type_too_large`, `title_too_large`, `content_too_large`, `name_too_large`,
`library_name_too_large`).

Echoed strings are capped in length with a `... [N chars truncated]` suffix. The suffix
alone marks most echoes (function names, rendered HLIL and disassembly lines, string
values, struct member types); a companion boolean flag marks the rest:
`rex_eval_python`'s `stdout_truncated`/`result_truncated`/`error_truncated`, tag data
(`data_truncated` in `rex_tag_list` and `rex_tag_set`), the stored kv value (`truncated`
in `rex_kv_set`/`rex_kv_get`), `rex_report_show`'s preview, and `rex_string_read_at`'s
value (both `truncated`). The `truncated` flags on the listing tools above mean results
were left out of the page (more past the window, or rows dropped to fit an export byte
cap), never a clipped string. `rex_eval_python` is also the one
tool that reports failure in-band: an exception comes back as the response's `error`
field (`error_truncated` when clipped) instead of raising a tool error.

Batch tools (`rex_annotate_many`, `rex_component_add_functions`,
`rex_type_library_export`, `rex_type_library_import`) answer a uniform
`applied`/`failed_count`/`total` summary alongside their per-tool detail fields.

## Bounds on database-wide scans

On a six-figure-function database the whole-database searches are bounded per
invocation:

- `rex_constant_find` runs the core's linear-view constant search (the engine behind
  Search > For Constant) instead of generating IL for every function. It matches values
  displayed as constant or pointer tokens in rendered instructions — the same reference a
  reader sees in the disassembly — and stops as soon as the requested `limit`/`offset`
  window is known to be complete. Only a value that never occurs in the view pays for a
  full sweep, which is a bounded, core-side pass.
- `rex_hlil_grep` renders HLIL for at most `max_functions` functions per invocation. The
  first render of a function's HLIL costs tens of milliseconds, so large databases are
  paged: each result carries `next_offset`, and callers pass it back as `offset` until
  `truncated` is false.
- `rex_find_functions_by_pattern` scans mapped memory with chunked reads and stops at the
  first matching function past the requested `limit`/`offset` window. Functions inside the
  window report a true match count, so every match inside an in-window function is still
  counted; the per-match work is a core containment query, and matches in data or between
  functions are skipped cheaply.

## Known limits

- `rex_string_search`, `rex_derived_string_refs`, and `rex_hlil_grep` compile
  model-supplied regular expressions with Python's `re`, which has no match timeout. A
  pattern prone to catastrophic backtracking (e.g. nested quantifiers like `(a+)+$`) can
  stall the tool invocation indefinitely; the MCP server processes invocations serially
  while it runs. Prefer substring mode (`regex=false`) when the input is not trusted, and
  keep regexes simple.

## Development

The project uses [nox](https://nox.thea.codes/) with `uv` as the default venv backend:

```bash
uvx nox -s check   # format, ruff, ty, and pytest with a 100% line-coverage gate
uvx nox -s test    # tests only
uvx nox -s native  # opt-in: cargo fmt, clippy -D warnings, and tests for native/
```

The `native` session gates the Rust crate in stub-core mode, so it needs a Rust toolchain,
clang, cmake, and ninja but no Binary Ninja install; CI runs it as its own job. See
[native/README.md](native/README.md) for the crate's build modes, the live benchmark
protocol ([native/BENCH.md](native/BENCH.md)), and the integration lessons the native half
already paid for (flat install layout, the reserved `binary` argument, the pinned API
revision).

Markdown is linted only in CI (`markdownlint-cli2`, config in `.markdownlint.yaml`): the
default rules plus MD013 at 100 characters per line — headings and code blocks included.
Keep Markdown lines at or under 100 columns; the local `check` session will not catch it.

Tests run against a fake `binaryninja` package installed by `tests/conftest.py`, so no
Binary Ninja installation or license is needed for the test suite.

## License

BSD 3-Clause. See [LICENSE](LICENSE).
