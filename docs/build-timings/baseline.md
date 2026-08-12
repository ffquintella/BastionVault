# Build-cost baseline

Appended by `make bench-build` (`scripts/bench-build.sh`). One row per run.
Every phase of [the decomposition](../../roadmaps/workspace-decomposition.md)
reports its delta against this table.

Read the script's header comment for what each column means and why it was
chosen. In short: `check-*` is front-end only, `test-build-leaf` includes the
link that `cargo check` never does, and none of these use the Makefile's
`-Z threads` escape hatch, so they are slower than `make build` and comparable
to each other.

Numbers are INCREMENTAL on a warm `target/`. A cold-build picture is a separate
artefact — see the `--timings` HTML in this directory.

## Noise floor — read before claiming a win

Each cell is the **median of 3 samples**. The measured run-to-run spread on this
tree is wide, because rustc's incremental cache is warmer or colder depending on
what ran immediately before. Observed raw samples for the baseline row:

| scenario | samples | spread |
|---|---|---|
| check-noop | 1.22 / 0.45 / 0.48 | 2.7x (first run pays the fingerprint scan) |
| check-leaf | 8.35 / 6.97 / 6.58 | ±13% |
| check-core | 6.45 / 7.65 / 8.65 | ±15% |
| test-build-leaf | 27.86 / 22.70 / 20.43 | ±16% |

**A phase must move a number by more than ~25% before the change is real.**
For anything closer than that, re-run with `--repeat 7` or more.

## Why `leaf` and `core` are the same number today

`check-leaf` (6.97s) and `check-core` (7.65s) are indistinguishable — their sample
ranges overlap almost completely. That is not a measurement failure, it is *the
finding*:

> `src/modules/transit/mod.rs` and `src/core.rs` are in the same crate, so
> touching either invalidates the same compilation unit. The build system cannot
> tell a self-contained 3,155-line secret engine apart from the 1,699-line object
> that every module depends on.

These two columns are in the table precisely so they can be watched **diverging**
as Phase 2 (breaking the `Core` ↔ `modules` cycle) and Phase 3 (engines into
crates) land. Until then, any gap between them is noise.

## Get comparable numbers — the harness is state-sensitive

Run this from a *settled* `target/`: right after a normal `make build` or
`make test`, and **not** right after building other package or feature subsets
(`cargo check -p <other>`, `--workspace`, `--all-features`). Those leave
additional build configurations in the cache, which changes both the
fingerprint-scan cost and how much rustc's incremental cache can reuse.

Row 2 below is a worked example of getting this wrong, kept as a warning rather
than deleted.

| date | commit | noop | leaf | core | test+link | rlib | lock | members | src lines | cores | notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 2026-08-12 17:34 UTC | `d04a72c` (dirty) | 0.48s | 6.97s | 7.65s | 22.70s | 245 MB | 1195 | 12 | 173938 | 10 | **Phase 0 baseline — use this row for comparison.** Tree carries the Cloudsmith + FerroGate-0.21.3 work uncommitted; no `src/` restructuring yet. |
| 2026-08-12 17:57 UTC | `d04a72c` (dirty) | 0.52s | 11.79s | 13.37s | 27.57s | 245 MB | 1195 | 12 | 173938 | 10 | ⚠ **NOT COMPARABLE — do not read this as a regression.** Taken immediately after a `--workspace` build and a series of `cargo check -p <crate>` feature-unification experiments, which contaminated the target dir. One `check-core` sample hit 31.42s. Kept as an example of the state-sensitivity described above. |

### What Phase 0 did and did not move

Phase 0 dropped five dead direct dependencies (`foreign-types`, `glob`,
`serde_derive` from the root; `serde` from `bv-plugin-pack`; `futures-util` and
`ironrdp-pdu` from the GUI). **`lock` did not budge: 1195 before and after.**

That is the expected result, and worth stating plainly so nobody looks for a win
that is not there: every one of those crates is still in the graph
*transitively*. Removing a direct dependency edge tidies the manifest, restores
`cargo machete` to a clean signal, and removes the risk of a stale edge pinning
a feature nobody intended — it does not remove compilation work. **No build-time
improvement should be attributed to Phase 0.** Phase 0's deliverable is the
instrument, not a speedup.
