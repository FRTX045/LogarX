# ADR-0009: Parallelise ingest rather than rewrite the parser in another language

- **Status:** Accepted
- **Date:** 2026-08-12

## Context

Ingest throughput has missed its target since it was first measured: **31,000 lines/s against a
stated 100,000**. [CHANGELOG 0.1.0](../../CHANGELOG.md) recorded the shortfall and named parallel
ingest as the remedy without measuring where the time actually went.

That gap mattered more once the project stopped being pure Python. [ADR-0008](0008-crs-as-a-signature-layer-beside-the-rule-packs.md)
brought in a Go sidecar for CRS, so "rewrite the hot loop in Go" was no longer a hypothetical — the
toolchain, the build and the cross-language boundary already existed. The question became a real
choice rather than a rhetorical one, and it deserved evidence.

## What was measured

On `samples/mixed.log`, 50,000 lines, before deciding anything:

| Stage | Time | Throughput | Share |
|---|---:|---:|---:|
| Read only — decode, strip, SHA-256 | 0.08 s | 611,000 lines/s | **4%** |
| Read and parse | 1.92 s | 26,000 lines/s | **96%** |

I/O is free. Inside `parse_line`, by `cProfile` self-time:

| Part | Share |
|---|---:|
| `parse_line` body | 27% |
| `re.Pattern.match` | **25%** |
| `_parse_timestamp` | 17% |
| `dict.get` — 800,000 calls, 16 per line | 7% |
| `_split_request_line` | 8% |
| `_clean` (500,000 calls), `groupdict` | 6% |

**The regex is a quarter of the cost.** The rest is CPython moving fields between dictionaries.
That single number decided the ADR: a faster pattern engine — `re2`, `regex`, a hand-written
matcher — has at most 25% to give, and only by replacing the part that is already C.

## Decision

**Parallelise across processes. Keep the parser in Python.**

Each worker takes a byte range and parses it independently; parsing a line depends on nothing but
that line. Threads were not an option — the parse is Python bytecode holding the GIL throughout, so
threads would take turns rather than run at once.

### Why not a native parser

A Go or Rust parser would plausibly give 5–10×, more than parallelism does. It was rejected on
what it costs rather than what it gives:

- **A second cross-language boundary, on the critical path.** The CRS sidecar is optional and
  enrichment-only; a case is complete without it. A native parser would sit in the one path every
  case must take, so a build or platform problem would stop the tool rather than degrade it.
- **`NormalizedEvent` would have to cross it, per line.** The sidecar exchanges JSON at batch
  granularity for an optional pass. A parser returning fourteen fields several hundred thousand
  times a second would spend much of the win on marshalling — the same trap that rules out sending
  events back from the worker processes.
- **It moves the code away from the people the project is for.** Adding a log format is a
  `LogParser` implementation, and the `LogFormat` compiler means most formats need no code at all.
  Putting the parser in Go would make the most commonly extended part the least approachable.
- **The measurement does not support it yet.** 40% of parse time is field marshalling that can be
  removed *within* Python — positional groups instead of `groupdict`, fewer `dict.get` calls. That
  work is cheaper, reversible, and has to be done before "Python is too slow" is an honest claim.

## Consequences

Measured on 400,000 lines (75 MB), ingest only, `finalize` excluded:

| | Ingest | Lines/s | Speedup |
|---|---:|---:|---:|
| Sequential | 14.7 s | 27,265 | 1.00× |
| 2 workers | 8.5 s | 46,964 | 1.72× |
| 4 workers | 6.1 s | 65,864 | 2.42× |
| 8 workers | 5.7 s | **69,655** | **2.55×** |

**The 100,000 target is still not met.** The plan behind this work predicted 124,000 from four
workers by assuming throughput scales with the worker count. It does not: the machine has four
physical cores behind eight logical ones, and hyperthreading adds perhaps a quarter to CPU-bound
work rather than doubling it. 2.55× is close to what this hardware has to give.

Reporting that plainly matters more than the improvement does. The remedy CHANGELOG 0.1.0 named has
now been implemented and measured, and it closes about two thirds of the gap. The rest is in the
parse itself, and the profile above says where.

### Costs accepted

- **Memory rises with the worker count.** Each worker holds a batch of its own, so four cost
  roughly four times one. This is why `--workers` defaults to 1 rather than to the core count: the
  memory is the user's to spend, and the flat-memory property is one of the design's stronger
  claims.
- **Compressed logs cannot be split.** gzip and bzip2 have no random access. They fall back to
  sequential rather than failing, so the flag never breaks a file the tool otherwise reads.
- **Small logs are slower in parallel.** Below 32 MB, spawning costs more than parsing saves, so
  the fallback applies there too.
- **Cancellation is not offered in parallel.** A stop would have to reach several processes and
  leave the case in a state all of them agreed on. A cancel that only sometimes arrives is worse
  than none, so `--workers` and a cancellable ingest are mutually exclusive; the sequential path,
  which the GUI uses, keeps the cancel.

### What it forced

Three latent defects had to be fixed before parallelism was safe, all of which would have corrupted
a case quietly:

- Staged Parquet files were numbered per store instance, so every worker wrote `part-000000.parquet`
  and all but the last were **silently replaced**.
- `Quarantine` appended to one shared file from several processes, which Windows does not guarantee
  is atomic — a torn write in the record of lines already too damaged to parse.
- The worker entry point must be a module-level function taking a picklable argument. A spawned
  worker imports the module and looks the function up by name; a closure cannot be found that way,
  and the failure is quiet.

The tests therefore assert that a parallel ingest stores byte-identical results to a sequential one
— same events, same line numbers, same digest, same quarantine count — and the timings are only
read afterwards. **A parallel ingest that loses a line looks exactly like a fast one.**
