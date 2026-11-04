# BENCH — live benchmark protocol for the native tools

This protocol compares the Rust plugin's tools (`rx_data_find`, `rx_multi_find`)
against the Python plugin's `rex_data_find` on the **live** Binary Ninja MCP
server. Run it after every engine change; the field-for-field verification is
the cross-language contract test.

## Prerequisites

1. The plugin is installed flat at `~/.binaryninja/plugins/libbinja_plugin_native.so`.
   Rebuild/reinstall any time with:

   ```sh
   native/scripts/install.sh   # from the repository root
   ```

2. **Restart Binary Ninja.** Native plugins are dlopened at startup and register
   their MCP tools from `CorePluginInit`; they cannot load into the running
   process. Do not remove or modify `~/.binaryninja/plugins/binja_plugin` (the
   Python plugin); both load together and are benchmarked against each other.
3. Open the benchmark database in the GUI and leave it open. The MCP server runs
   at `http://127.0.0.1:24642/mcp`.

## Step 1 — verify the plugin loaded

```sh
python3 native/bench_mcp.py --check-only   # from the repository root
```

Expected output on success:

```text
handshake ok; <count> tools registered; rx_* and rex_* both present
```

If it reports `rx_data_find, rx_multi_find missing`, the .so did not load:

- verify the install layout: the core scans `~/.binaryninja/plugins` for **flat
  `*.so` files only** — subdirectories are silently skipped (this bit us once;
  see the layout note in `native/README.md`);
- verify the export and linkage:

  ```sh
  nm -D --defined-only ~/.binaryninja/plugins/libbinja_plugin_native.so | grep CorePluginInit
  ldd ~/.binaryninja/plugins/libbinja_plugin_native.so | grep binaryninjacore
  ```

- the .so must resolve `libbinaryninjacore.so.1` (RUNPATH points at the BN
  install directory recorded by `~/.binaryninja/lastrun`).

## Step 2 — run the benchmark

```sh
python3 native/bench_mcp.py --binary <handle> --repeat 5   # from the repository root
```

Take the handle from `bn_binary_list` — it changes on every restart, and the
script's built-in default is only a last resort. What it measures, on the same
database, interleaved `--repeat` times:

1. **Single pattern, head-to-head.** `rex_data_find("48 8b 05")` vs
    `rx_data_find("48 8b 05")`, readable mapped segments, `limit=50`, `offset=0`.
   Reports min/median/max ms and the min-based speedup.
2. **Multi-pattern headliner.** `rx_multi_find` with 8 code patterns in one
   call vs 8 sequential `rex_data_find` calls (summed), same pagination.
   Reports both timings and the speedup.
3. **Correctness verification (always runs).** `rx_data_find` is compared
    field-for-field with `rex_data_find`; each `rx_multi_find` result is compared
    per pattern on `total`, `truncated`, and `matches`. The final line reports
    pass or mismatch.

Useful variations:

```sh
# A longer pattern (the Python side pays per-chunk read inflation for length):
python3 native/bench_mcp.py --binary <handle> --pattern "48 8b ?? 05 ?? ?? ?? ?? 48 8b ?? 05"

# Restrict to a section (smaller scan; pass a section name that exists):
python3 native/bench_mcp.py --binary <handle> --section .text

# A bigger signature-set slice for the headliner:
python3 native/bench_mcp.py --binary <handle> --patterns "48 8b 05" "e8 ?? ?? ?? ??" \
    "0f 1f 44 00 00" "48 89 ?? 24 ??" "4c 8b ?? ??" "cc cc cc cc" "48 83 ?? ??" "48 8d ?? ??"
```

## Safety constraints (already encoded in the script)

- The server runs tool handlers **serially** and **cannot cancel** them. Do not
  run other MCP clients or commands against the same server while the benchmark
  is in progress.
- Every call is bounded client-side at 30 s (`CALL_TIMEOUT` in
  `bench_mcp.py`); a hung call raises instead of stalling forever.

## Historical results (2026-11-01, promotion benchmark)

Database: libclang-cpp.so.22.1 (62 MB bndb, ~111k functions, fresh full
reanalysis), readable mapped segments (~61.2 MB), `--repeat 5`.

| Measurement | min | median | max |
| --- | --- | --- | --- |
| `rex_data_find` "48 8b 05" | 110.1 ms | 114.9 ms | 122.5 ms |
| `rx_data_find` "48 8b 05" | 14.6 ms | 15.5 ms | 17.0 ms |
| **single-pattern speedup (min)** | **7.5x** | | |
| 8× sequential `rex_data_find` | 919.1 ms | 938.6 ms | 969.9 ms |
| `rx_multi_find`, 8 patterns, one pass | 72.8 ms | 78.0 ms | 95.3 ms |
| **multi-pattern speedup (min)** | **12.6x** | | |

Verification: all 9 payload comparisons identical (`RESULT: all verifications
passed`), including the all-wildcard and `cc cc cc cc` patterns.

These are short-pattern results; the variations below cover longer patterns
and section-scoped scans.

## Variations (2026-11-01)

Measured on the same day, database, and protocol (`--repeat 5`, payload
verification on).

### Long pattern (20 bytes, wildcards, readable mapped segments)

```sh
# from the repository root
python3 native/bench_mcp.py --binary <handle> --repeat 5 \
    --pattern "48 8b 05 ?? ?? ?? ?? 48 8b ?? ?? 4c 8b ?? ?? 0f 1f 44 00 00"
```

| Measurement | min | median | max |
| --- | --- | --- | --- |
| `rex_data_find`, 20-byte pattern | 414.9 ms | 485.6 ms | 536.3 ms |
| `rx_data_find`, 20-byte pattern | 34.7 ms | 43.2 ms | 44.3 ms |
| **single-pattern speedup (min)** | **11.9x** | | |

Verification passed; the default scenarios reproduced the 12.6x multi-pattern
result. With the same literal prefix, the 20-byte pattern widened the gap:
Python slowed ~4x, Rust ~2.4x.

### Section-scoped (`.text`)

```sh
python3 native/bench_mcp.py --binary <handle> --repeat 5 --section .text
```

`.text` is 0x280590f bytes (~42 MB) on this database — essentially the whole
executable segment, so this isolates a contiguous code-only scan.

| Measurement | min | median | max |
| --- | --- | --- | --- |
| `rex_data_find` "48 8b 05" | 10.9 ms | 11.5 ms | 13.0 ms |
| `rx_data_find` "48 8b 05" | 11.0 ms | 11.7 ms | 14.6 ms |
| **single-pattern speedup (min)** | **0.99x** | | |
| 8× sequential `rex_data_find` | 184.2 ms | 190.7 ms | 205.8 ms |
| `rx_multi_find`, 8 patterns, one pass | 47.3 ms | 53.1 ms | 62.0 ms |
| **multi-pattern speedup (min)** | **3.9x** | | |

Verification: all 9 payload comparisons identical, `RESULT: all verifications
passed`; a second run reproduced the parity (0.93x, the Rust side marginally
behind) — it is real, not noise.

Honest margins: the single-pattern advantage tracks **where** the scan runs,
not how long the pattern is. Inside executable code both tools cost ~0.26
ms/MB and short patterns are a wash; the full-view gap lives in the
non-executable segments. Same day, same protocol, scoped to `.rodata`
(~5.96 MB) as a one-run diagnostic:

```text
== single pattern '48 8b 05' (section=.rodata, limit=50) ==
  rex_data_find : min   38.7  median   43.2  max   47.9 ms
  rx_data_find  : min    1.3  median    1.4  max    1.5 ms
  speedup (min) : 30.03x
```

That is ~6.5 ms/MB on the Python side against ~0.22 ms/MB on the Rust side —
~25x its own `.text` per-byte cost, while the Rust per-byte cost stays flat
across both segments. Why the Python chunked-read path is so much slower per
byte on the read-only segment is unprofiled; the effect is what matters for
reading these tables: the promotion run's 7.5x headline prices in segments a
code-scoped scan never touches. The multi-pattern win (one call, one walk over
the bytes) is the only advantage that held at every scope measured: 12.6x full
view, 3.9x `.text`, 28x `.rodata`.
