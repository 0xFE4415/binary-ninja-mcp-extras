//! binja_plugin_native: native-speed MCP tools for Binary Ninja.
//!
//! Registers two BinaryView-scoped MCP tools:
//!
//! - `rx_data_find`: the Python plugin's `rex_data_find` contract with the
//!   byte scan running in native Rust (SIMD memchr prefilter + verification).
//! - `rx_multi_find`: many hex patterns in one pass via a multi-pattern
//!   automaton, a capability the Python plugin cannot offer.
//!
//! The plugin links against the core at the exact `api_REVISION.txt` commit of
//! the Binary Ninja this targets and registers its tools from `CorePluginInit`
//! so clients that cached the tool list before startup still see them.

// Public only so benches/ can drive the engine; not a supported API.
#[doc(hidden)]
pub mod hexpattern;
#[doc(hidden)]
pub mod multi;
#[doc(hidden)]
pub mod scan;
mod tools;

/// Seeded LCG for the differential tests (no rand dependency): Knuth's MMIX
/// multiplier/addend, high 33 bits as the output.
#[cfg(test)]
pub(crate) fn test_rng(seed: u64) -> impl FnMut() -> u32 {
    let mut state: u64 = seed;
    move || {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (state >> 33) as u32
    }
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "C" fn CorePluginInit() -> bool {
    let registered = tools::register();
    if !registered {
        binaryninja::logger::bn_log(
            "binja_plugin_native",
            binaryninja::logger::BnLogLevel::ErrorLog,
            "failed to register rx_data_find / rx_multi_find MCP tools",
        );
    }
    registered
}
