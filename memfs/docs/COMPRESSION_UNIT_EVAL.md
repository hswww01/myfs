# Compression Unit Evaluation

Date: 2026-09-30

## Goal

Evaluate whether memfs should decouple its 4 KiB logical sparse-page granularity
from a larger compression unit. This is an experiment only; it does not change
the on-disk/in-memory storage format.

The benchmark keeps the logical write size at 4 KiB and compares Zstd level 1
compression units of 4 KiB, 16 KiB, and 64 KiB.

## Benchmark

Target:

```powershell
cmake --build --preset x64-release --target memfs_compression_unit_bench
.\build\x64-release\memfs_compression_unit_bench.exe
```

Dataset size: 16 MiB.

Workloads:

- `zero`: fully compressible control case;
- `cross_page`: each 64 KiB region contains sixteen near-identical
  pseudo-random 4 KiB pages. A 4 KiB page is individually almost
  incompressible, while a larger unit can discover cross-page redundancy;
- `random`: incompressible control case.

The random-rewrite test changes one logical 4 KiB page, but must decode and
re-encode the entire selected compression unit. Each operation starts from the
same steady-state encoded dataset so results are not distorted by cumulative
randomization.

The concurrency test uses eight independent Zstd contexts.

## Results

| Pattern | Unit | Stored ratio | Encode MiB/s | 4K rewrite ns | Raw CPU amplification | Encoded write amplification | 8-thread MiB/s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| zero | 4 KiB | 0.004639 | 3100.9 | 3111.3 | 1x | 1.000x | 31014.1 |
| zero | 16 KiB | 0.001160 | 7466.9 | 5388.7 | 4x | 1.009x | 63385.2 |
| zero | 64 KiB | 0.000305 | 13021.9 | 11656.4 | 16x | 1.010x | 53461.4 |
| cross_page | 4 KiB | 1.000000 | 1062.0 | 2762.1 | 1x | 1.000x | 7356.7 |
| cross_page | 16 KiB | 0.252107 | 2651.9 | 5808.1 | 4x | 2.008x | 21740.2 |
| cross_page | 64 KiB | 0.064135 | 6675.6 | 8947.2 | 16x | 2.028x | 48927.8 |
| random | 4 KiB | 1.000000 | 1135.2 | 2800.7 | 1x | 1.000x | 8935.9 |
| random | 16 KiB | 1.000000 | 1476.3 | 6764.7 | 4x | 4.000x | 9890.0 |
| random | 64 KiB | 1.000000 | 2492.3 | 9660.2 | 16x | 16.000x | 34616.6 |

These are local microbenchmark numbers, not a promise of end-to-end filesystem
throughput.

## Interpretation

A global 64 KiB compression unit is not appropriate.

For cross-page redundant data, 64 KiB is compelling: it reduces stored payload
from effectively uncompressed to about 6.4% of plaintext, roughly a 15.6x
payload reduction relative to 4 KiB units. Larger units also amortize Zstd call
overhead and substantially improve bulk/concurrent compression throughput.

However, a single random 4 KiB rewrite of a 64 KiB extent requires decoding and
re-encoding sixteen logical pages. On incompressible data it provides no memory
benefit and turns one logical 4 KiB write into roughly 16x encoded output.

## Recommended design

Keep `MEMFS_PAGE_SIZE = 4096` and the current sparse allocation bitmap/page
semantics.

If larger compression units are implemented, make them optional adaptive
compression extents, initially 64 KiB (16 logical pages):

1. A sparse hole remains a missing 4 KiB logical page. The larger compression
   unit must never increase sparse allocation granularity.
2. A 64 KiB compression extent is only considered after enough pages in the
   16-page window are present to make coalescing useful.
3. Probe the whole extent once. Keep it coalesced only when its encoded size
   beats a minimum ratio threshold (for example <= 75% of the sum of current
   per-page stored sizes).
4. A failed larger-unit probe records negative feedback so random data is not
   repeatedly re-tested.
5. Track rewrite heat. Repeated partial-page/4 KiB rewrites should split a
   coalesced extent back into normal 4 KiB page objects instead of paying a
   permanent 16x CPU amplification.
6. Sequential/full-extent rewrites may remain coalesced.
7. Encryption authentication boundaries must remain explicit; a coalesced
   compression extent needs one well-defined nonce/tag scheme and must not
   weaken per-file nonce uniqueness.
8. PageGroup lookup should expose either individual page entries or an extent
   descriptor without adding another global index.

## Decision

Do not change the production storage format in this task.

The measurements justify a follow-up prototype of adaptive 64 KiB compression
extents, but they also reject an unconditional 64 KiB compression unit.
