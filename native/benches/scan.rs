use binja_plugin_native::hexpattern::HexPattern;
use binja_plugin_native::multi::MultiMatcher;
use binja_plugin_native::scan::{Pagination, RunningScan, scan_pattern};
use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

const SIZES: [usize; 3] = [64 << 10, 4 << 20, 64 << 20];

const PATTERNS: [&str; 12] = [
    "48 8b 05",
    "48 8b 05 ?? ?? ?? ?? 48 8b ?? ?? 4c 8b ?? ?? 0f 1f 44 00 00",
    "e8 ?? ?? ?? ??",
    "48 ?? 8b ?? 05",
    "?? ?? 48 8b 05",
    "ff 15 ?? ?? ?? ??",
    "0f 1f 44 00 00",
    "00 00 00 00",
    "cc cc cc cc",
    "90",
    "de ad be ef",
    "?? ??",
];

// Counts every match without recording any: offset u64::MAX is never reached.
const FULL_SCAN: Pagination = Pagination {
    offset: u64::MAX,
    limit: 0,
};

/// Skewed x86-like bytes: heavy 00/48/8b/e8/ff, the rest uniform. xorshift, no rand dependency.
fn synthetic_haystack(size: usize) -> Vec<u8> {
    let hot = [0x00u8, 0x48, 0x8b, 0xe8, 0xff, 0x05, 0x89, 0x0f];
    let mut state = 0x9e3779b97f4a7c15u64;
    (0..size)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            if state & 3 != 0 {
                hot[(state >> 8) as usize % hot.len()]
            } else {
                (state >> 16) as u8
            }
        })
        .collect()
}

fn bench_single(criterion: &mut Criterion) {
    for size in SIZES {
        let haystack = synthetic_haystack(size);
        let mut group = criterion.benchmark_group(format!("scan_pattern/{}KiB", size >> 10));
        group.throughput(Throughput::Bytes(size as u64));
        for text in PATTERNS {
            let pattern = HexPattern::parse(text).unwrap();
            group.bench_with_input(
                BenchmarkId::from_parameter(text),
                &pattern,
                |bench, pattern| {
                    bench.iter(|| {
                        let mut running = RunningScan::new();
                        scan_pattern(black_box(&haystack), 0, pattern, &FULL_SCAN, &mut running);
                        running.total
                    });
                },
            );
        }
        group.finish();
    }
}

fn bench_multi(criterion: &mut Criterion) {
    let patterns: Vec<HexPattern> = PATTERNS[..8]
        .iter()
        .map(|text| HexPattern::parse(text).unwrap())
        .collect();
    let matcher = MultiMatcher::new(&patterns);
    for size in SIZES {
        let haystack = synthetic_haystack(size);
        let mut group = criterion.benchmark_group("multi_scan_segment");
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(
            BenchmarkId::new("8_patterns", format!("{}KiB", size >> 10)),
            |bench| {
                bench.iter_batched(
                    || {
                        patterns
                            .iter()
                            .map(|_| RunningScan::new())
                            .collect::<Vec<_>>()
                    },
                    |mut buckets| {
                        matcher.scan_segment(
                            black_box(&haystack),
                            0,
                            &patterns,
                            &mut buckets,
                            &FULL_SCAN,
                        );
                        buckets.iter().map(|bucket| bucket.total).sum::<u64>()
                    },
                    BatchSize::SmallInput,
                );
            },
        );
        group.finish();
    }
}

criterion_group!(benches, bench_single, bench_multi);
criterion_main!(benches);
