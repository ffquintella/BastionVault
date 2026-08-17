# Agent Instructions

Moved. The full agent instructions — architecture map, build and test strategy,
security standards, change discipline, HTTP API versioning, testing requirements
and the changelog/roadmap tracking rules — now live in one authoritative file:

**→ [`AGENTS.md`](AGENTS.md)**

This file is kept only so that existing references to `agent.md` in `features/*.md`
and `roadmaps/*.md` still lead somewhere correct. Do not add rules here; they
would drift from `AGENTS.md`.

---

## Before you run tests — read this much, at least

The one rule that costs the most when it is missed: **do not run `make test`
after every edit.** It is `cargo nextest run --workspace --lib --bins`, which
links ~40 test harnesses, five of them over 200 MB. Almost all of that work is
on tests your change cannot reach.

Scoped, in the order you should reach for them:

```bash
cargo check -p <pkg>          # while editing — front-end only, one crate
cargo nextest run -p <pkg> --lib   # that crate's own tests

make test-plan                # which packages a change affects — no build at all
make test-changed             # run exactly those (git diff + cargo dep graph)
make test-changed DIRECT=1    # ...changed packages only, skip dependents
make test-changed BASE=main   # ...widen to everything since merge-base(main)

make test                     # whole workspace — what CI runs
make test-release             # EVERY suite — releases and high-risk merges only
```

`make test-changed` walks the reverse-dependency closure (dev-dependencies
included) so you do not have to work the blast radius out by hand. It reports
`tests/`, doctests and the GUI rather than running them, and forces a full run
when you touch `Cargo.toml`, `Cargo.lock`, `.cargo/config.toml`,
`rust-toolchain.toml` or `.config/nextest.toml`.

Never run two `cargo` commands at once — they share one `target/` build lock and
the second blocks for as long as the first takes.

Commands only. The reasoning, the blast-radius table, the validation levels and
every exclusion live in [`AGENTS.md`](AGENTS.md) §3–§5 and in the header of
`scripts/test-changed.sh` — read those before overriding any of this.
