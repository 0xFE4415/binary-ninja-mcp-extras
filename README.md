# binja-plugin

Extra MCP tools for Binary Ninja's built-in MCP server. The stock server exposes its
`bn_*` tools, and this plugin registers more alongside them, covering the moves an
agent session mostly consists of: search, code and data transitions, triage
annotations, and scratch state. The Python half registers the `rex_*` tools. The Rust
half (`native/`) adds two `rx_*` byte scanners for the scans where native speed
measurably wins.

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
installs a flat `.so` into the plugins directory, and that is the only layout the
core's plugin loader picks up:

```bash
binja-plugin/native/scripts/install.sh   # installs libbinja_plugin_native.so
```

Restart Binary Ninja, then start the server from `Plugins > MCP > Start Server`. MCP
clients that connected earlier must reconnect to see the registered tools.

## Quick start

Point an MCP client at the server with a binary open. The plugin's tools appear next
to the `bn_*` ones, and a first session usually runs the same arc:

1. `rex_help` for discovery: the tool categories, each with a "use when" line. Open one
   with `rex_help(category=...)`, or one tool's parameters with `rex_help(tool_name=...)`.
   It also lists the `rx_*` scanners, under `scanning`, once the native half is loaded.
2. `bn_binary_triage` for fast contact: the entry point and the size of the binary.
3. Search. `rex_string_search` for strings, `rex_data_find` or `rx_multi_find` for
   byte patterns, `rex_hlil_grep` for code shape, and `rex_constant_find` for magic
   numbers.
4. Zoom in with `rex_disasm_at` or `rex_decompile_many`.
5. Record what you concluded with `rex_annotate_many`, and hand yourself a summary
   with `rex_report_show`.
6. Undo a batch with `rex_undo`.

## Tool reference

Each tool registers as read-only or destructive. That mark is the only approval signal an
MCP client gets, so read the destructive table before you let an agent run those tools.
The tables list all 51 tools: 49 Python `rex_*` tools and 2 native `rx_*` scanners.
CONTRACTS.md holds the exact rules for every response field and limit.

### Read-only tools

| Tool | What it does |
| --- | --- |
| `rex_string_search` | Search detected strings by substring or regex. |
| `rex_data_find` | Find a hex byte pattern (`??` wildcards) in mapped memory. |
| `rex_data_read` | Read mapped bytes with relocations applied. |
| `rx_multi_find` | Find up to 64 hex patterns in one native pass. |
| `rx_data_find` | Same as `rex_data_find`, with the scan in native Rust. |
| `rex_hlil_grep` | Regex search over HLIL text, one page of functions at a time. |
| `rex_hlil_statements` | List a function's HLIL statements with their addresses. |
| `rex_function_constraints` | List branch comparisons against a constant. |
| `rex_mlil_uses` | Show every read of the MLIL variables defined at an address. |
| `rex_parameter_variables` | Map a parameter to its storage, variables, and copies. |
| `rex_constant_find` | Find functions that use a constant in a disassembly line. |
| `rex_find_functions_by_pattern` | Map a byte pattern to the functions that contain it. |
| `rex_string_refs` | List code references to detected strings. |
| `rex_xrefs_to` | List code and data references to an address. |
| `rex_disasm_at` | Disassemble the lines around an address. |
| `rex_disasm_many` | Disassemble up to 64 addresses in one call. |
| `rex_decompile_many` | Decompile up to 1024 functions in one call. |
| `rex_analysis_wait` | Wait for analysis, with a time limit. |
| `rex_uidf_list` | List user variable values for one function or the whole view. |
| `rex_call_paths` | Find call paths; `from_addr` reaching `to_addr` needs `direction=callees`. |
| `rex_function_containing` | List every function that contains an address. |
| `rex_component_get` | Show a component's functions and child components. |
| `rex_string_read_at` | Read the detected string at an address. |
| `rex_relocation_at` | List the relocations that cover an address. |
| `rex_tag_list` | List the tags in the view. |
| `rex_report_show` | Show a markdown report inside Binary Ninja. |
| `rex_kv_get` | Read a scratch string stored in the database. |
| `rex_eval_result` | Page through a long `rex_eval_python` result. |
| `rex_help` | List tool categories, a category's tools, or one tool's parameters. |

### Destructive tools

| Tool | What it does |
| --- | --- |
| `rex_annotate_many` | Rename, retype, or comment up to 128 items in one undoable batch. |
| `rex_memory_write` | Overwrite bytes in the view with a hex string. |
| `rex_function_define` | Make a function at an address; can wait for analysis. |
| `rex_function_define_many` | Define up to 128 functions and wait for their first blocks. |
| `rex_function_undefine` | Remove the function that covers an address. |
| `rex_uidf_set` | Set an MLIL variable's value at its definition; returns the new HLIL. |
| `rex_uidf_set_many` | Set up to 128 values, then reanalyze and render once. |
| `rex_uidf_clear` | Clear one variable's set values, or all values in a function. |
| `rex_struct_from_access` | Infer a struct from recorded offset accesses and define it. |
| `rex_type_library_import` | Attach a `.bntl` and import a list of its types. |
| `rex_type_library_export` | Write view types or objects to a new `.bntl` file. |
| `rex_component_create` | Create a component, optionally under a parent path. |
| `rex_component_add_functions` | Add functions to a component. |
| `rex_tag_set` | Add a tag at an address; creates the tag type if needed. |
| `rex_kv_set` | Store a scratch string in the view's database. |
| `rex_kv_delete` | Delete a stored scratch string. |
| `rex_export_disasm` | Write a function's disassembly window to a file. |
| `rex_export_symbols` | Write the symbols in an address range to a CSV or JSON file. |
| `rex_eval_python` | Run Binary Ninja Python with `bv`, `bn`, `binaryninja`, and `call`. |
| `rex_binary_close` | Discard unsaved changes and close the view. |
| `rex_undo` | Undo the view's last transaction. |
| `rex_redo` | Redo the last undone transaction. |

### Addresses inside several functions

A cold block can sit inside its parent and inside a function of its own. A tool that takes
an address picks the containing function with the lowest start. It reports that function as
`function`, with `also_containing` and `same_name` listing the others.
`rex_function_containing` lists all of them in the same order.

### Bounds on database-wide scans

Three searches stop early, so one call stays fast on a large database.

- `rex_constant_find` searches disassembly with the core's constant search and stops once
  the page is full. It returns up to 6 distinct addresses per function, in the core's hit
  order. While `truncated` is set, each function's addresses are a lower bound.
  `value` is an integer or a `0x` hex string; send the string for values above 2^53, which
  JavaScript clients cannot hold as numbers. For `value` 0 it drops hits with no zero
  operand, such as `xor eax, eax`; set `include_non_operand_hits` to keep them.
- `rex_hlil_grep` renders at most `max_functions` functions per call. Page with
  `next_offset` while `truncated` or `scan_incomplete` is set. `skipped_no_hlil` counts
  functions with no HLIL.
- `rex_find_functions_by_pattern` stops at the first match past the page. While
  `truncated` is set, `match_count` and addresses are lower bounds. It returns up to 5
  addresses per function.

### Known limits

- `rex_string_search`, `rex_string_refs`, and `rex_hlil_grep` compile regular expressions
  with Python's `re`, which has no timeout. A pattern like `(a+)+$` can stall the server,
  and it handles calls one at a time. Use substring mode (`regex=false`) for untrusted
  input where the tool has it, and keep `rex_hlil_grep` patterns simple.
- `rx_data_find` beats `rex_data_find` by about 7.5x on a whole-view scan and ties it
  (0.99x) on `.text`; on `.rodata` it was about 30x faster in one diagnostic run.
  `rx_multi_find` won at every scope, up to 12.6x on the full view. Both register
  whenever the native half is installed, so pick per scan. The numbers come from
  [native/BENCH.md](native/BENCH.md).

## Development and testing

The project uses [nox](https://nox.thea.codes/) with `uv` as the default venv backend:

```bash
uvx nox -s check   # format, ruff, size, ty, and pytest with a 100% coverage gate
uvx nox -s test    # tests only
uvx nox -s native  # opt-in: cargo fmt, clippy -D warnings, and tests for native/
```

The unit tests never touch Binary Ninja. `tests/conftest.py` installs a fake `binaryninja`
package before the plugin imports, so the suite runs anywhere Python 3.13 runs. Only the
opt-in `live` session talks to a real Binary Ninja.

The mutation gates are opt-in locally, and CI always runs them in separate jobs:

```bash
uvx nox -s mutation          # mutmut; fails when any Python mutant survives or times out
uvx nox -s mutation_native   # cargo-mutants; fails when any Rust mutant is missed or times out
```

The `native` session gates the Rust crate in stub-core mode, so it needs a Rust
toolchain, clang, cmake, and ninja but no Binary Ninja install. See
[native/README.md](native/README.md) for the crate's build modes and the integration
lessons the native half already paid for, and [native/BENCH.md](native/BENCH.md) for
the live benchmark protocol.

The `live` session checks a running Binary Ninja through its MCP server. Start Binary Ninja
with the plugin and the native half loaded, then run `uvx nox -s live`. It opens
`tests/live/fixture.o` (a compiled object, never linked), runs `tests/live/playbook.json`
against `http://127.0.0.1:24642/mcp`, and closes its view again. Pass `-- --url URL` to use
another server. CI does not run it.

CI (`.github/workflows/check.yml`) runs four jobs: `check` (markdownlint-cli2 plus
the format, ruff, size, ty, and test sessions), `native`, and one mutation job per
language. Markdown is linted only in CI: default rules plus MD013 at 100 characters
per line, headings and code blocks included. Keep Markdown at or under 100 columns;
the local `check` session will not catch it.

## License

BSD 3-Clause. See [LICENSE](LICENSE).
