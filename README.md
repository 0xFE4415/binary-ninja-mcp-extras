# binja-plugin

Extra MCP tools for Binary Ninja's built-in MCP server. The stock server exposes its
`bn_*` tools; this plugin registers more alongside them, covering the moves an agent
session mostly consists of: search, code and data transitions, triage annotations, and
scratch state. The Python half registers the `rex_*` tools. The Rust half (`native/`)
adds two `rx_*` byte scanners for the scans where native speed measurably wins.

## Install

Binary Ninja (GUI or headless) with the built-in MCP server enabled (`ui.mcp.enabled`)
is the only runtime requirement. Python 3.13+ is only needed for development and
testing. Building the optional native half also needs a Rust toolchain and clang.

Clone the repo and symlink the Python package into Binary Ninja's plugin directory:

```bash
git clone git@github.com:0xFE4415/binja-plugin.git
ln -s "$(pwd)/binja-plugin/src/binja_plugin" ~/.binaryninja/plugins/binja_plugin
```

To enable the `rx_*` scanners as well, build and install the native half. The script
installs a flat `.so` into the plugins directory, which is the only layout the core's
plugin loader picks up:

```bash
binja-plugin/native/scripts/install.sh   # installs libbinja_plugin_native.so
```

Restart Binary Ninja, then start the server from `Plugins > MCP > Start Server`. MCP
clients that connected earlier must reconnect to see the registered tools.

## Quick start

Point an MCP client at the server with a binary open. The plugin's tools appear next
to the `bn_*` ones, and a first session usually runs the same arc:

1. `rex_quick_main` for fast contact: entry point, `main`, and `main`'s HLIL in one
   call.
2. Search. `rex_string_search` for strings, `rex_data_find` or `rx_multi_find` for
   byte patterns, `rex_hlil_grep` for code shape, `rex_constant_find` for magic
   numbers.
3. Zoom in with `rex_disasm_at` or `rex_decompile_many`.
4. Write down what you concluded with `rex_annotate_many`, and hand yourself a summary
   with `rex_report_show`.
5. Regret a batch? `rex_undo`.

## Tool reference

Every tool is pinned as read-only or destructive when it registers, and that marking
is the only approval-policy signal an MCP client gets. The tables below cover all 39
registered tools, split on that marking: 37 Python `rex_*` tools and 2 native `rx_*`
scanners. Read the destructive table before handing an agent free rein.

### Read-only tools

| Tool | Notes |
| --- | --- |
| `rex_string_search` | Search detected strings by substring or regex; section and type filters. |
| `rex_data_find` | Find every occurrence of a hex byte pattern (`??` wildcards) in mapped memory. |
| `rex_data_read` | Read mapped bytes with relocations applied; reports what it actually read. |
| `rx_multi_find` | Many hex patterns in one pass, via a multi-pattern automaton in Rust. |
| `rx_data_find` | `rex_data_find`'s contract with the byte scan running in native Rust. |
| `rex_hlil_grep` | Regex search over rendered HLIL text, paged with a `next_offset` cursor. |
| `rex_constant_find` | Find functions whose rendered instructions reference a constant value. |
| `rex_find_functions_by_pattern` | Map a byte pattern to the functions containing its matches. |
| `rex_string_refs` | Code refs to detected strings, synthesized included; filters. |
| `rex_disasm_at` | Address-anchored disassembly window, clipped at the function's edges. |
| `rex_decompile_many` | HLIL render for up to 16 functions in one batch call. |
| `rex_quick_main` | Entry point, `main`, and `main`'s HLIL in one call. |
| `rex_analysis_wait` | Bounded wait for background analysis; snapshot at expiry. |
| `rex_call_paths` | Bounded breadth-first search for call paths between two functions. |
| `rex_function_containing` | List the functions containing an address. |
| `rex_component_get` | Look up a component by path; report functions and child components. |
| `rex_string_read_at` | Read the detected string at an address. |
| `rex_relocation_at` | List the relocations covering an address, symbol names included. |
| `rex_tag_list` | List the tags set on the binary view. |
| `rex_report_show` | Render a markdown report with `binaryninja://` links into the view. |
| `rex_kv_get` | Read a stored scratch string from the view's database. |

### Destructive tools

| Tool | Notes |
| --- | --- |
| `rex_annotate_many` | Rename, comment, or retype up to 100 functions in one transaction. |
| `rex_memory_write` | Overwrite bytes in the binary view with a hex byte string. |
| `rex_function_define` | Turn the bytes at an address into a function. |
| `rex_function_undefine` | Remove the function covering an address. |
| `rex_struct_from_access` | Infer a struct from recorded offset accesses and define it. |
| `rex_type_library_import` | Attach a `.bntl` and import a bounded list of its type names. |
| `rex_type_library_export` | Export view types or objects into a new `.bntl` in the export root. |
| `rex_component_create` | Create a component, optionally nested under a parent path. |
| `rex_component_add_functions` | Put resolved functions into a component. |
| `rex_tag_set` | Attach a GUI-visible tag at an address, creating the tag type on demand. |
| `rex_kv_set` | Store a scratch string in the view's database; survives across sessions. |
| `rex_kv_delete` | Delete a previously stored scratch value. |
| `rex_export_disasm` | Write one function's disassembly window to a file. |
| `rex_export_symbols` | Write an address range's symbols to a CSV or JSON file. |
| `rex_eval_python` | Run arbitrary Binary Ninja Python; the escape hatch for everything else. |
| `rex_binary_close` | Discard unsaved changes and close the view. |
| `rex_undo` | Undo the view's last transaction; reports post-op stack depths. |
| `rex_redo` | Redo the last undone transaction; reports post-op stack depths. |

### Shared response contract

- Paged listings return `total`, `truncated`, and a `limit`/`offset` window:
  `rex_string_search`, `rex_data_find`, `rex_string_refs`, `rex_tag_list`, and
  `rex_export_symbols`. `rex_component_get` paginates the same way but names its count
  `function_count`.
- Early-stop scans (`rex_constant_find`, `rex_find_functions_by_pattern`,
  `rex_hlil_grep`) accept `limit`/`offset` too but never return a `total`: they stop
  scanning once the requested window is filled. `rex_hlil_grep` reports where it
  stopped with a `next_offset` cursor; pass it back as `offset` to get the next page.
- Size parameters (`limit`, `length`, `offset`, `max_depth`, `max_paths`, `max_functions`,
  `max_chars`) are range-checked, not clamped. Out of range fails with the MCP layer's
  `invalid_params`; an over-cap string argument fails with a per-parameter
  `*_too_large` code instead (`pattern_too_large`, `key_too_large`, `value_too_large`,
  `data_too_large`, `tag_type_too_large`, `title_too_large`, `content_too_large`,
  `name_too_large`, `library_name_too_large`). Path and list-entry parameters
  (component paths, `rex_type_library_*` names, export filenames) fail with
  `invalid_params` even when over their cap.
- Echoed strings clip at 512 characters with a `... [N chars truncated]` suffix. Most
  echoes signal truncation with the suffix alone; these also return a boolean flag:
  `rex_eval_python`'s `stdout_truncated`/`result_truncated`/`error_truncated`,
  `data_truncated` in `rex_tag_list` and `rex_tag_set`, `truncated` on the stored value
  in `rex_kv_set`/`rex_kv_get`, `rex_report_show`'s preview, and `rex_string_read_at`'s
  value. On the listing tools, `truncated` means rows were left out, never a clipped
  string.
- `rex_data_read` returns `bytes_read` (what was actually read) and `complete` (whether
  that equals the requested `length`). A range extending past mapped memory comes back
  short instead of failing.
- `rex_eval_python` is the one tool that reports failure in-band: an exception comes
  back in the response's `error` field instead of raising a tool error.
- Batch tools (`rex_annotate_many`, `rex_component_add_functions`,
  `rex_type_library_export`, `rex_type_library_import`) return a uniform
  `applied`/`failed_count`/`total` summary alongside their per-tool fields.

### Bounds on database-wide scans

On a database with hundreds of thousands of functions, the whole-database searches
stay bounded per call:

- `rex_constant_find` reuses the core's linear-view constant search (the engine behind
  Search > For Constant) instead of generating IL for every function. The search is a
  bounded, core-side pass that stops once the requested window is filled; a value that
  occurs rarely or never requires scanning the whole view.
- `rex_hlil_grep` renders at most `max_functions` functions per call. The first render
  of a function's HLIL costs tens of milliseconds, so on a large database, page through
  the `next_offset` cursor.
- `rex_find_functions_by_pattern` reads memory in chunks and stops as soon as it finds
  a matching function past the requested window. Functions inside the window still
  report their full match count.

### Known limits

- `rex_string_search`, `rex_string_refs`, and `rex_hlil_grep` compile
  model-supplied regular expressions with Python's `re`, which has no match timeout. A
  pattern prone to catastrophic backtracking (nested quantifiers like `(a+)+$`) can
  stall the invocation indefinitely, and the server processes calls serially while it
  runs. Prefer substring mode (`regex=false`) for untrusted input, and keep regexes
  simple.
- `rx_data_find`'s speed advantage depends on scan scope, per the project's own
  benchmark ([native/BENCH.md](native/BENCH.md)): about 7.5x on a whole-database scan
  with a short pattern, and parity (0.99x) when the scan covers one section. The
  multi-pattern scanner won at every scope measured (12.6x on the full view, against
  8 sequential Python calls). Both tools register whenever both halves are installed;
  there is no switch between them, so pick per scan.

## Development and testing

The project uses [nox](https://nox.thea.codes/) with `uv` as the default venv backend:

```bash
uvx nox -s check   # format, ruff, size, ty, and pytest with a 100% coverage gate
uvx nox -s test    # tests only
uvx nox -s native  # opt-in: cargo fmt, clippy -D warnings, and tests for native/
```

Tests never touch Binary Ninja: `tests/conftest.py` installs a fake `binaryninja`
package before the plugin imports, so the suite runs anywhere Python 3.13 runs.

The two mutation gates are opt-in locally and always run in CI, one job per language:

```bash
uvx nox -s mutation          # mutmut; fails when any Python mutant survives or times out
uvx nox -s mutation_native   # cargo-mutants; fails when any Rust mutant is missed or times out
```

The `native` session gates the Rust crate in stub-core mode, so it needs a Rust
toolchain, clang, cmake, and ninja but no Binary Ninja install. See
[native/README.md](native/README.md) for the crate's build modes and the integration
lessons the native half already paid for, and [native/BENCH.md](native/BENCH.md) for
the live benchmark protocol.

CI (`.github/workflows/check.yml`) runs four jobs: `check` (markdownlint-cli2 plus
the format, ruff, size, ty, and test sessions), `native`, and one mutation job per
language. Markdown is linted only in CI: default rules plus MD013 at 100 characters
per line, headings and code blocks included. Keep Markdown at or under 100 columns;
the local `check` session will not catch it.

## License

BSD 3-Clause. See [LICENSE](LICENSE).
