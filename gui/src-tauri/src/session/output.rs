//! Per-session SSH output buffering (features/session-workspace.md §6,
//! T38 Phase 6).
//!
//! One fixed-size store per SSH session, owned by the session's pump task,
//! with two jobs:
//!
//! * **Pending output — always on.** Bytes the remote produced while no
//!   window was listening: before the first window's listener handshake
//!   (the prompt and MOTD; this replaces the pre-T38 `early_buf`), and
//!   while a session is being moved to another window. Delivered — and
//!   then zeroed — at the next listener handshake.
//! * **Replay ring — opt-in** (`session_workspace.replay_buffer`, off by
//!   default). Keeps the most recent output *after* it was delivered too,
//!   so a window that takes the session over can redraw recent scrollback.
//!   Without it a moved session's new window starts with an empty screen.
//!
//! Security (the review the spec asked for; also recorded in the spec):
//!
//! * **Bounded.** [`OUTPUT_BUFFER_CAPACITY`] bytes per SSH session,
//!   allocated once when the session opens and never reallocated, so no
//!   copy of session output is left behind in a freed, un-zeroed
//!   allocation by growth. The oldest bytes are overwritten first.
//! * **Per session, memory only.** Owned by the pump task; never written to
//!   disk, never shared between sessions, never exposed by a command. The
//!   only way out is the holder window's handshake replay, which goes
//!   through the same holder-gated delivery as live output.
//! * **Zeroed.** The whole allocation is zeroed when the session ends (the
//!   pump task drops it), and the pending region is zeroed as soon as it is
//!   delivered when the ring is off. Snapshots are `Zeroizing`.
//! * **Opt-in for anything already shown.** Without the preference the
//!   buffer only ever holds output no window has displayed yet — the same
//!   class of data the pre-T38 early-bytes buffer held, now bounded and
//!   zeroed.
//!
//! What it does not cover: the transient copies made to deliver any output
//! (the base64 string, the serialised event, the webview's JS heap) are not
//! zeroed — the same as for live output before this phase.

use zeroize::{Zeroize, Zeroizing};

/// Bytes kept per SSH session (the spec's proposal: 256 KiB).
pub const OUTPUT_BUFFER_CAPACITY: usize = 256 * 1024;

/// A fixed-capacity byte ring that zeroes itself.
pub struct OutputRing {
    buf: Box<[u8]>,
    start: usize,
    len: usize,
    /// Bytes overwritten since the ring was last cleared.
    dropped: u64,
}

impl OutputRing {
    pub fn with_capacity(capacity: usize) -> Self {
        assert!(capacity > 0, "an output ring needs a non-zero capacity");
        Self { buf: vec![0u8; capacity].into_boxed_slice(), start: 0, len: 0, dropped: 0 }
    }

    #[cfg(test)]
    fn capacity(&self) -> usize {
        self.buf.len()
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.len
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Bytes overwritten (lost) since the last [`Self::clear`].
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Append, overwriting the oldest bytes once full.
    pub fn push(&mut self, data: &[u8]) {
        let cap = self.buf.len();
        if data.len() >= cap {
            self.dropped += (self.len + data.len() - cap) as u64;
            self.buf.copy_from_slice(&data[data.len() - cap..]);
            self.start = 0;
            self.len = cap;
            return;
        }
        let overflow = (self.len + data.len()).saturating_sub(cap);
        if overflow > 0 {
            self.start = (self.start + overflow) % cap;
            self.len -= overflow;
            self.dropped += overflow as u64;
        }
        let end = (self.start + self.len) % cap;
        let first = (cap - end).min(data.len());
        self.buf[end..end + first].copy_from_slice(&data[..first]);
        let rest = data.len() - first;
        if rest > 0 {
            self.buf[..rest].copy_from_slice(&data[first..]);
        }
        self.len += data.len();
    }

    /// The buffered bytes, oldest first, in a copy that zeroes itself.
    pub fn snapshot(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(self.len));
        let first = (self.buf.len() - self.start).min(self.len);
        out.extend_from_slice(&self.buf[self.start..self.start + first]);
        out.extend_from_slice(&self.buf[..self.len - first]);
        out
    }

    /// Zero the whole allocation and forget its contents.
    pub fn clear(&mut self) {
        self.buf.as_mut().zeroize();
        self.start = 0;
        self.len = 0;
        self.dropped = 0;
    }

    #[cfg(test)]
    fn raw(&self) -> &[u8] {
        &self.buf
    }
}

impl Drop for OutputRing {
    fn drop(&mut self) {
        self.buf.as_mut().zeroize();
    }
}

/// What a listener handshake delivers to the window that made it.
pub struct Replay {
    pub bytes: Zeroizing<Vec<u8>>,
    /// Host-composed text the pane shows before the bytes (never remote
    /// data): what was dropped, or that earlier output was not kept.
    pub notice: Option<String>,
}

impl Replay {
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty() && self.notice.is_none()
    }
}

/// The pump's output state: the buffer plus which holder epoch has
/// completed the listener handshake.
///
/// The rule the pump follows: output is delivered live only to the holder
/// of `live_epoch()`, through a delivery that re-checks the epoch under the
/// attachment lock (`routing::SessionEvents::emit_if_epoch`). Anything not
/// delivered is kept for the next handshake. A handshake is the first
/// `session_resize` a holder sends at a given epoch — every pane sends it
/// only once both its listeners are live, exactly as the pre-T38
/// early-bytes flush assumed.
pub struct SessionOutput {
    ring: OutputRing,
    retain_delivered: bool,
    ready_epoch: Option<u64>,
    handshakes: u32,
}

impl SessionOutput {
    pub fn new(capacity: usize, retain_delivered: bool) -> Self {
        Self { ring: OutputRing::with_capacity(capacity), retain_delivered, ready_epoch: None, handshakes: 0 }
    }

    /// The holder epoch output may go to live, once a window has
    /// completed its handshake.
    pub fn live_epoch(&self) -> Option<u64> {
        self.ready_epoch
    }

    /// Account for one chunk of remote output. Kept when it was not
    /// delivered, and also when it was if the replay ring is on.
    pub fn record(&mut self, data: &[u8], delivered: bool) {
        if self.retain_delivered || !delivered {
            self.ring.push(data);
        }
    }

    /// A `session_resize` authorised at `epoch`. `Some` when it is the
    /// listener handshake of a holder not yet served at that epoch — the
    /// caller delivers the replay (gated on `epoch`) and, if it arrived,
    /// calls [`Self::handshake_done`]. `None` for an ordinary resize.
    pub fn handshake(&self, epoch: u64) -> Option<Replay> {
        if self.ready_epoch == Some(epoch) {
            return None;
        }
        let mut bytes = self.ring.snapshot();
        let dropped = self.ring.dropped();
        let took_over = self.handshakes > 0;
        let notice = if self.retain_delivered {
            if dropped > 0 {
                // The ring wrapped, so it starts mid-stream: begin at the
                // next line rather than inside an escape sequence.
                if let Some(nl) = bytes.iter().position(|b| *b == b'\n') {
                    bytes.drain(..=nl);
                }
            }
            match (took_over, bytes.is_empty()) {
                (true, false) => Some(format!(
                    "replaying the last {} KiB of output the host kept for this session{}",
                    bytes.len().div_ceil(1024),
                    if dropped > 0 { "; older output was not kept" } else { "" }
                )),
                (false, false) if dropped > 0 => {
                    Some(format!("{dropped} bytes of output were dropped before this window was ready"))
                }
                _ => None,
            }
        } else if took_over {
            let mut n = "this window took the session over; output shown before is not kept (Settings → General → \
                         Session layout → Keep recent terminal output)"
                .to_string();
            if dropped > 0 {
                n.push_str(&format!("; {dropped} bytes produced while no window showed the session were dropped"));
            }
            Some(n)
        } else if dropped > 0 {
            Some(format!("{dropped} bytes of output were dropped before this window was ready"))
        } else {
            None
        };
        Some(Replay { bytes, notice })
    }

    /// The handshake replay for `epoch` reached its holder.
    pub fn handshake_done(&mut self, epoch: u64) {
        self.ready_epoch = Some(epoch);
        self.handshakes = self.handshakes.saturating_add(1);
        if !self.retain_delivered {
            self.ring.clear();
        }
    }

    #[cfg(test)]
    fn buffered(&self) -> usize {
        self.ring.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ring_keeps_the_newest_bytes_in_order() {
        let mut r = OutputRing::with_capacity(8);
        r.push(b"abc");
        r.push(b"defg");
        assert_eq!(&r.snapshot()[..], b"abcdefg");
        assert_eq!(r.dropped(), 0);
        // Wraps: the three oldest bytes go.
        r.push(b"hijk");
        assert_eq!(&r.snapshot()[..], b"defghijk");
        assert_eq!(r.dropped(), 3);
        assert_eq!(r.len(), r.capacity());
        // A chunk larger than the ring keeps only its own tail.
        r.push(b"0123456789");
        assert_eq!(&r.snapshot()[..], b"23456789");
        assert_eq!(r.dropped(), 3 + 8 + 2);
    }

    /// Bounded: however much is pushed, the store never grows.
    #[test]
    fn the_ring_never_grows() {
        let mut r = OutputRing::with_capacity(16);
        for _ in 0..1000 {
            r.push(b"0123456789abcdef0123");
        }
        assert_eq!(r.len(), 16);
        assert_eq!(r.raw().len(), 16);
        assert_eq!(r.snapshot().len(), 16);
    }

    /// Cleared means zeroed, not just forgotten.
    #[test]
    fn clearing_zeroes_the_whole_allocation() {
        let mut r = OutputRing::with_capacity(8);
        r.push(b"secret!!");
        r.push(b"pw");
        assert!(r.raw().iter().any(|b| *b != 0));
        r.clear();
        assert!(r.raw().iter().all(|b| *b == 0));
        assert!(r.is_empty());
        assert_eq!(r.dropped(), 0);
    }

    /// Ring off (the default): output nobody saw is held until the first
    /// handshake, delivered once, then zeroed; delivered output is not
    /// kept, and a later holder is told so.
    #[test]
    fn without_the_ring_only_undelivered_output_is_held() {
        let mut out = SessionOutput::new(64, false);
        out.record(b"motd\r\n$ ", false);
        assert_eq!(out.live_epoch(), None);
        let first = out.handshake(1).expect("first resize is the handshake");
        assert_eq!(&first.bytes[..], b"motd\r\n$ ");
        assert!(first.notice.is_none());
        out.handshake_done(1);
        assert_eq!(out.buffered(), 0);
        assert_eq!(out.live_epoch(), Some(1));
        // An ordinary resize at the same epoch is not a handshake.
        assert!(out.handshake(1).is_none());

        // Delivered live: not kept.
        out.record(b"ls\r\nfile\r\n", true);
        assert_eq!(out.buffered(), 0);

        // Moved: output while the new window is not yet listening is held.
        out.record(b"tail\r\n", false);
        let replay = out.handshake(3).unwrap();
        assert_eq!(&replay.bytes[..], b"tail\r\n");
        assert!(replay.notice.as_deref().unwrap().contains("not kept"), "{:?}", replay.notice);
        out.handshake_done(3);
        assert_eq!(out.buffered(), 0);
    }

    /// Ring on: a window that takes the session over gets recent output,
    /// delivered or not, and the replay starts at a line once the ring has
    /// wrapped.
    #[test]
    fn with_the_ring_a_new_holder_replays_recent_output() {
        let mut out = SessionOutput::new(16, true);
        out.record(b"$ ", false);
        let first = out.handshake(1).unwrap();
        assert_eq!(&first.bytes[..], b"$ ");
        assert!(first.notice.is_none());
        out.handshake_done(1);
        out.record(b"echo hi\r\nhi\r\n", true);
        assert_eq!(out.buffered(), 15);

        let replay = out.handshake(2).unwrap();
        assert_eq!(&replay.bytes[..], b"$ echo hi\r\nhi\r\n");
        assert!(replay.notice.as_deref().unwrap().starts_with("replaying"), "{:?}", replay.notice);
        out.handshake_done(2);
        assert_eq!(out.buffered(), 15, "the ring keeps what it replayed");

        // Wrap: the replay skips the partial first line.
        out.record(b"partial-line\nnext\r\n", true);
        let wrapped = out.handshake(4).unwrap();
        assert_eq!(&wrapped.bytes[..], b"next\r\n");
        assert!(wrapped.notice.unwrap().contains("older output was not kept"));
    }

    /// A handshake whose delivery missed (the session moved on before it
    /// arrived) leaves everything in place for the next holder.
    #[test]
    fn an_undelivered_handshake_changes_nothing() {
        let mut out = SessionOutput::new(32, false);
        out.record(b"prompt", false);
        let _ = out.handshake(1).unwrap();
        // Not delivered: no handshake_done.
        assert_eq!(out.live_epoch(), None);
        assert_eq!(out.buffered(), 6);
        let again = out.handshake(2).unwrap();
        assert_eq!(&again.bytes[..], b"prompt");
        assert!(again.notice.is_none(), "still the first window to be served");
    }

    #[test]
    fn overflow_before_the_first_window_is_reported() {
        let mut out = SessionOutput::new(4, false);
        out.record(b"0123456789", false);
        let r = out.handshake(1).unwrap();
        assert_eq!(&r.bytes[..], b"6789");
        assert!(r.notice.unwrap().starts_with("6 bytes of output were dropped"));
    }
}
