# Downloads-server fixtures

One directory per fixture release *root* — i.e. each subdirectory here is a
complete `--root` in the layout the container expects:

```
v0.4.0/                 <- the fixture root
├── manifest.json
└── v0.4.0/             <- the release directory the manifest names
    ├── <artefact>
    ├── <artefact>.sig
    └── <artefact>.pem
```

The artefacts are **placeholder text files**, not real packages, and the
`.sig` / `.pem` files are placeholder text, not real Cosign material. They
exist so the server has something to hash, list and serve; nothing here is
signed and nothing here should ever be installed.

Used by:

- the acceptance run in `features/packaging-distribution-website.md` Phase 1:
  `cargo run -p bv-downloads-server -- --root ./cmd/bv-downloads-server/fixtures/v0.4.0`
- `tests/downloads_server.rs` (spawns the real binary against it)
- the container smoke check in `deploy/downloads/README.md`

Regenerate with `python3 cmd/bv-downloads-server/fixtures/make-fixture.py`
after changing the artefact set — the manifest carries real SHA-256 digests of
the placeholder bodies, so hand-editing one file breaks `--verify-hashes`.
