# RDP session performance

Companion to [features/resource-connect.md](../features/resource-connect.md)
Phase 4 (the RDP session window). That phase got a correct RDP client on
screen; this one is about making it feel fast.

Everything lives in two files:
[gui/src-tauri/src/session/rdp.rs](../gui/src-tauri/src/session/rdp.rs) (the
pump) and
[gui/src/routes/SessionRdpWindow.tsx](../gui/src/routes/SessionRdpWindow.tsx)
(the canvas), plus
[gui/src/lib/rdpFrames.ts](../gui/src/lib/rdpFrames.ts) for the wire format
they share.

## The diagnosis

The RDP *library* was never the bottleneck. ironrdp already advertises
RemoteFX by default (`bitmap: None` in the connector config falls through to
`client_codecs_capabilities(&[])`, which enables `remotefx`). What cost the
session was everything around it:

1. **The frame transport.** Every server graphics PDU was packed to RGBA,
   base64-encoded, wrapped in JSON, and pushed through `app.emit`. Tauri
   serializes an event payload into a JavaScript `eval` string, so a
   full-desktop repaint at 1024×600 became a ~3.2 MB string literal that the
   webview parsed and the frontend then decoded one `charCodeAt` at a time.
2. **One IPC round trip per PDU.** Damage was unioned *within* a single PDU
   only. RDP fast-path sends bursts of small update PDUs, so a busy screen
   produced a burst of separate messages.
3. **No bulk compression.** `compression_type` was hardcoded `None`.
4. **No Graphics Pipeline.** The mechanism that makes modern RDP fast was
   never negotiated.
5. **No way to tell what the server chose.** Nothing logged the negotiated
   codec or the throughput, so "it feels slow" could not be turned into a
   number.

## What landed

| # | Change | Where |
|---|---|---|
| 1 | Per-session throughput telemetry (`PumpStats`) | `session/rdp.rs` |
| 2 | Bulk compression advertised (MPPC-64K default) + reactivation fix | `session/rdp.rs` |
| 3 | Binary `ipc::Channel` frame transport, replacing base64-over-events | `session/rdp.rs`, `SessionRdpWindow.tsx`, `lib/rdpFrames.ts` |
| 4 | Time-based dirty-rect coalescing (`Dirty`, 16 ms flush) | `session/rdp.rs` |
| 5 | Graphics Pipeline / H.264 client — **partial, see below** | `session/rdp.rs`, `Cargo.toml` |

### 1. Telemetry

`PumpStats` logs one line per session every 10 s, and a final line at close.
The number to read is `codec`: server wire bytes divided by the RGBA bytes
those updates painted.

- **~1.0 or higher** — the server is sending essentially raw bitmaps. No
  bitmap codec is in play.
- **~0.05–0.20** — RemoteFX and/or bulk compression is working.

`saved` is what the coalescing bought — the share of painted pixels never
forwarded to the webview because a later update superseded them inside the
same flush window.

For the authoritative record of what was negotiated, run with
`RUST_LOG=ironrdp_connector=debug`. ironrdp logs the server's
`ServerDemandActive` PDU, including its `BitmapCodecs` capability set. (It
uses `tracing` with the `log` feature, so `env_logger` picks it up with no
extra wiring.) `ConnectionResult` does not expose the server capability sets,
which is why this is a log-level answer rather than a field.

### 2. Bulk compression

`DEFAULT_BULK_COMPRESSION` is `CompressionType::K64` — MPPC with a 64 KB
history buffer, the RDP 5.0 baseline every Windows server supports. Override
per connection profile with `rdp_bulk_compression`:

| Value | Meaning |
|---|---|
| `off` / `none` | advertise no bulk compression |
| `default` | `DEFAULT_BULK_COMPRESSION` |
| `mppc8k` / `k8` | MPPC 8 KB (RDP 4.0) |
| `mppc64k` / `k64` | MPPC 64 KB (RDP 5.0) — the default |
| `rdp6` | NCRUSH |
| `rdp61` / `rdp6.1` | XCRUSH |

An unrecognised value is an error, not a fallback to the default — a typo in
a profile must not silently change a session's wire behaviour.

This is advertised, not imposed: the server echoes what it will use, and
`ActiveStage` builds a decompressor only for that. If we advertise and the
server declines, the pump logs a warning.

**The bug this exposed.** `run_reactivation` rebuilt the fast-path processor
with `bulk_decompressor: None`, silently discarding the decompressor after
every DisplayControl resize. Harmless while `compression_type` was hardcoded
`None`; a corrupt screen the moment it wasn't. It now rebuilds from the
negotiated type. (A fresh `BulkCompressor` starts with an empty history
buffer, which is correct here: MS-RDPBCGR has the server reset its own
history across a Deactivation-Reactivation and flag the first packet
`PACKET_AT_FRONT`.)

**Note on compression inside TLS.** RDP bulk compression sits inside the TLS
tunnel, which is the CRIME/BREACH shape. It is not a practical concern here —
the compressed stream is server→client graphics, not a mixture of attacker
input and secrets — and it is what `mstsc` and FreeRDP do by default. It is
nonetheless a deliberate, negotiated, per-profile-disableable choice rather
than a silent one.

### 3. Binary frame transport

`tauri::ipc::Channel<InvokeResponseBody>` carrying `InvokeResponseBody::Raw`.
Tauri routes a raw body over the `ipc://` custom protocol as a real binary
response (above a 1 KB threshold it goes through the fetch path; below it,
a small `Uint8Array` literal). Either way the frontend receives an
`ArrayBuffer`, and `rdpFrames.ts` builds `ImageData` from *views* into it —
no copy, no base64, no JSON, no `eval` of the pixel payload.

The channel is created by the window, not the host: `SessionRdpWindow` calls
`session_attach_rdp_frames` once its canvas is mounted. The pump starts
before the `WebviewWindow` exists, so `FrameSink` starts with no channel and
`needs_full` set; the first flush after attach carries the whole desktop.
The same mechanism covers a window reload and the post-resize repaint.

Wire format (little-endian), one message per flush:

```text
  0      u8    version
  1      u8    flags   (bit 0: full-desktop repaint)
  2..4   u16   rect count
  4..6   u16   desktop width
  6..8   u16   desktop height
  8..    rect count × { u16 x, u16 y, u16 w, u16 h }
  ...          row-packed RGBA for each rect, in rect order
```

The desktop size is in every frame deliberately. The `resize` Tauri event and
the frame channel are separate transports, so the event can lose the race
against the first frame at the new size; a header the canvas can size itself
from cannot. Bump `FRAME_WIRE_VERSION` on any layout change — the frontend
rejects a version it does not speak rather than painting a partial parse.

### 4. Coalescing

`Dirty` accumulates damage between flushes and the pump flushes at most once
per `FRAME_INTERVAL` (16 ms ≈ 60 Hz). Rects are clamped to the desktop and
deduplicated by containment, which is what real sessions produce: a caret, a
spinner or a hovered button repaints the same few pixels over and over.

Past `MAX_DIRTY_RECTS` (8) the list collapses to its bounding union, and if
that union covers ≥90% of the desktop it is promoted to a full repaint. A
short list beats a single union because one bounding box over scattered
damage (cursor top-left, clock bottom-right) degenerates to the whole screen.

All rects in a flush are packed from the same framebuffer at the same
instant, so overlapping rects carry identical pixels and apply order does not
matter.

The flush timer sits in the same `select!` as `Framed::read_pdu`. That is
legal because `read_pdu` documents itself as cancel safe — dropping the read
future leaves partial data in the `Framed` buffer.

### 5. Graphics Pipeline (MS-RDPEGFX) — **partial**

**Status: implemented, feature-gated, and inert until one connector change
is pushed.** See below.

Behind the `rdp_egfx` cargo feature (off by default) and the per-profile
`rdp_egfx` key (off by default):

- `EgfxHandler` implements `ironrdp_egfx::client::GraphicsPipelineHandler`,
  tracks the surface→output-origin mapping, and forwards decoded RGBA to the
  pump over an unbounded channel.
- `EgfxFramebuffer` composites those surfaces. It exists because ironrdp's
  `DecodedImage` exposes no mutation API from outside `ironrdp-session`, so
  EGFX cannot paint into the buffer the bitmap path uses. `current_surface`
  picks which of the two the frame packer reads.
- The frame source switches to the EGFX buffer on the first blit that
  actually *landed*, not on `CapabilitiesConfirm`. Confirming capabilities
  only means the server may use the pipeline; if it then sends nothing we can
  decode, flipping early would blank the desktop.

**H.264 is loaded, never bundled.** `ironrdp-egfx` is pulled with
`openh264-libloading`, and the decoder is loaded at run time from the path in
`BASTION_RDP_OPENH264`. Three reasons, in order of weight:

1. An H.264 decoder parses server-controlled bitstreams. Keeping it out of
   the default build keeps that attack surface out of every install
   (AGENTS.md §7 — minimize the trusted computing base).
2. `openh264-libloading` verifies the library against known Cisco release
   hashes before loading, so what gets loaded is a Cisco build.
3. Cisco's patent grant covers their prebuilt binaries, not a source build.

If the library is missing or fails to load, EGFX is not registered at all and
the session falls back to the RemoteFX path — logged, not hidden. A V8-only
EGFX session would get RFX Progressive from Windows, which we cannot decode,
so "no decoder" must mean "no EGFX" rather than "EGFX without AVC".

#### What is left

A Windows server only opens the `Microsoft::Windows::RDS::Graphics` DVC when
the client sets `RNS_UD_CS_SUPPORT_DYNVC_GFX_PROTOCOL` (0x0100) in the Client
Core Data early capability flags. ironrdp's connector never sets it — the
flag is defined in `ironrdp-pdu` and referenced nowhere else — so registering
the channel is necessary but not sufficient, and the EGFX path is currently
inert.

The connector change is written and compiles. It adds
`Config::enable_egfx: bool` (defaulting false, because advertising the flag
can make a server abandon Bitmap Updates for a pipeline the client may not be
able to decode) and sets the flag when it is on. It touches four files in the
fork: the `Config` struct, the flag site in `connection.rs`, and the three
`Config` literals in `ironrdp-viewer`, `ironrdp-web` and the `screenshot`
example.

It is sitting **uncommitted in the `IronRDP/` submodule working tree**. To
finish:

1. Review and commit it in `IronRDP/`, then push to
   `ffquintella/IronRDP` branch `fix-deps`.
2. `cargo update -p ironrdp-connector` in this repo.
3. Add `enable_egfx: args.enable_egfx,` to `build_connector_config` — the
   site is marked `EGFX ACTIVATION SITE`.
4. Flip `EGFX_EARLY_CAPABILITY_AVAILABLE` to `true` in `session/rdp.rs`.

Until step 4, a build with `rdp_egfx` that is asked for EGFX logs a warning
saying exactly this, rather than failing to build or silently doing nothing.

**Unverified.** The EGFX path has unit coverage for compositing, clipping,
payload validation, the frame-source switch and `ResetGraphics` handling, but
it has never run against a real Windows Graphics Pipeline — it cannot, until
the flag lands. Treat it as untested against a live server.

## What was considered and rejected

- **Swapping ironrdp for FreeRDP.** Buys nothing against the dominant cost
  (the IPC hop, which is ours either way), and costs a C library to build and
  ship on three platforms, an unsafe FFI surface in a security product, and
  the CredSSP smartcard work in `session/sk_signer.rs`. Runs against
  AGENTS.md §7 on the trusted computing base and Rust-native dependencies.
- **`ironrdp-web` / `iron-remote-desktop`.** A WASM client decoding and
  painting inside the webview deletes the Rust→JS frame hop entirely, which
  is architecturally the most interesting option. But WASM cannot open TCP,
  so it needs a WebSocket / RDCleanPath proxy (Rustion could terminate one),
  and credential handling would have to be redone on the JS/WASM side. Worth
  revisiting if the frame path is ever the bottleneck again.
- **Enabling the server pointer and drawing the cursor as an overlay.** Would
  be a win if the cursor were composited into the framebuffer, but
  `enable_server_pointer: false` already makes ironrdp *discard* pointer PDUs
  and rely on the local OS cursor, so cursor motion generates no frames at
  all. Already optimal.
- **QOI / QOIZ codecs.** ironrdp supports them, but they are an IronRDP-server
  extension; no Windows server offers them.

## Next

- Finish the EGFX activation (four steps above) and measure against a real
  Windows host.
- Consider RFX Progressive decode. `ironrdp-graphics` has the transform
  primitives (`progressive.rs`, `dwt_extrapolate.rs`, `rlgr.rs`) but no
  tile-level decoder, so a V8 EGFX session cannot be served today.
- Revisit `MAX_DIRTY_RECTS` and `FRAME_INTERVAL` against the telemetry from a
  real session; both were chosen from first principles, not measurement.
