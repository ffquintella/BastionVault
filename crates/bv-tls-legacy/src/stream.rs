//! The established connection as a tokio `AsyncRead + AsyncWrite` stream.
//! After the handshake only application data, `close_notify` and fatal
//! alerts are accepted; a handshake record (renegotiation) is fatal.

use std::{
    io,
    pin::Pin,
    task::{ready, Context, Poll},
};

use rustls_pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{
    error::{alert, TlsError},
    handshake::{alert_error, client_handshake, msg, ClientConfig, ConnectionInfo, RecordIo},
    record::{content, Decryptor, Encryptor, HEADER_LEN, MAX_CIPHERTEXT, MAX_PLAINTEXT, TLS12},
    verify::TrustAnchors,
};

/// Consecutive empty application-data records tolerated (a peer looping on
/// empty records must not spin the reader forever).
const MAX_EMPTY_RECORDS: u32 = 32;

/// Run the TLS 1.2 client handshake over `io` and return the protected
/// stream. Certificate, name and key-exchange verification always run.
pub async fn connect<IO>(
    io: IO,
    server_name: ServerName<'static>,
    trust: &TrustAnchors,
    config: &ClientConfig,
) -> Result<LegacyTlsStream<IO>, TlsError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let mut rio = RecordIo::new(io);
    match tokio::time::timeout(config.handshake_timeout, client_handshake(&mut rio, &server_name, trust)).await {
        Err(_) => Err(TlsError::HandshakeTimeout),
        Ok(Err(e)) => {
            if let Some(description) = e.alert() {
                rio.send_alert(description).await;
            }
            Err(e)
        }
        Ok(Ok(info)) => {
            let (io, rx, decryptor, encryptor) = rio.into_parts();
            match (decryptor, encryptor) {
                (Some(d), Some(e)) => Ok(LegacyTlsStream::new(io, rx, d, e, info)),
                _ => Err(TlsError::Internal("handshake finished without record keys")),
            }
        }
    }
}

/// A TLS 1.2 CBC connection. Reading yields application data until the
/// peer's `close_notify`; a transport EOF without one is an error.
pub struct LegacyTlsStream<IO> {
    io: IO,
    rx: Vec<u8>,
    plaintext: Vec<u8>,
    plaintext_pos: usize,
    decryptor: Decryptor,
    pub(crate) encryptor: Encryptor,
    tx: Vec<u8>,
    tx_pos: usize,
    received_close_notify: bool,
    sent_close_notify: bool,
    failed: Option<(io::ErrorKind, String)>,
    empty_records: u32,
    info: ConnectionInfo,
}

impl<IO> LegacyTlsStream<IO> {
    pub(crate) fn new(io: IO, rx: Vec<u8>, decryptor: Decryptor, encryptor: Encryptor, info: ConnectionInfo) -> Self {
        Self {
            io,
            rx,
            plaintext: Vec::new(),
            plaintext_pos: 0,
            decryptor,
            encryptor,
            tx: Vec::new(),
            tx_pos: 0,
            received_close_notify: false,
            sent_close_notify: false,
            failed: None,
            empty_records: 0,
            info,
        }
    }

    /// What was negotiated (suite, EMS, secure renegotiation).
    pub fn connection_info(&self) -> ConnectionInfo {
        self.info
    }

    /// Whether the peer has sent `close_notify`.
    pub fn received_close_notify(&self) -> bool {
        self.received_close_notify
    }

    #[cfg(test)]
    pub(crate) fn get_mut(&mut self) -> &mut IO {
        &mut self.io
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> LegacyTlsStream<IO> {
    /// Process one complete record from `rx`, if there is one. `Ok(false)`
    /// means more bytes are needed.
    fn process_record(&mut self) -> Result<bool, TlsError> {
        if self.rx.len() < HEADER_LEN {
            return Ok(false);
        }
        let content_type = self.rx[0];
        let version = u16::from_be_bytes([self.rx[1], self.rx[2]]);
        let len = usize::from(u16::from_be_bytes([self.rx[3], self.rx[4]]));
        if version != TLS12 {
            return Err(TlsError::PeerMisbehaved {
                alert: alert::PROTOCOL_VERSION,
                what: "record carries a protocol version other than TLS 1.2",
            });
        }
        if len > MAX_CIPHERTEXT {
            return Err(TlsError::RecordOverflow);
        }
        if self.rx.len() < HEADER_LEN + len {
            return Ok(false);
        }
        let mut fragment = self.rx[HEADER_LEN..HEADER_LEN + len].to_vec();
        self.rx.drain(..HEADER_LEN + len);
        let payload = self.decryptor.open(content_type, &mut fragment)?;
        match content_type {
            content::APPLICATION_DATA if payload.is_empty() => {
                self.empty_records += 1;
                if self.empty_records > MAX_EMPTY_RECORDS {
                    return Err(TlsError::PeerMisbehaved {
                        alert: alert::UNEXPECTED_MESSAGE,
                        what: "too many consecutive empty records",
                    });
                }
            }
            content::APPLICATION_DATA => {
                self.empty_records = 0;
                if self.plaintext_pos == self.plaintext.len() {
                    self.plaintext.clear();
                    self.plaintext_pos = 0;
                }
                debug_assert!(payload.len() <= MAX_PLAINTEXT);
                self.plaintext.extend_from_slice(payload);
            }
            content::ALERT => match payload {
                [_, alert::CLOSE_NOTIFY] => self.received_close_notify = true,
                other => return Err(alert_error(other)),
            },
            content::HANDSHAKE if payload.first() == Some(&msg::HELLO_REQUEST) => {
                return Err(TlsError::RenegotiationRefused)
            }
            content::HANDSHAKE => {
                return Err(TlsError::PeerMisbehaved {
                    alert: alert::UNEXPECTED_MESSAGE,
                    what: "handshake message after the handshake (renegotiation is not accepted)",
                })
            }
            _ => {
                return Err(TlsError::PeerMisbehaved {
                    alert: alert::UNEXPECTED_MESSAGE,
                    what: "unexpected record after the handshake",
                })
            }
        }
        Ok(true)
    }

    /// Record a fatal failure, queue the matching alert (best effort) and
    /// return the error to surface.
    fn fail(&mut self, cx: &mut Context<'_>, e: TlsError) -> io::Error {
        if let Some(description) = e.alert() {
            let mut out = Vec::new();
            if self.encryptor.seal(content::ALERT, &[2, description], &mut out).is_ok() {
                self.tx.extend_from_slice(&out);
                let _ = self.poll_flush_tx(cx);
            }
        }
        self.failed = Some((e.io_kind(), e.to_string()));
        io::Error::from(e)
    }

    fn failed_error(&self) -> Option<io::Error> {
        self.failed.as_ref().map(|(kind, message)| io::Error::new(*kind, message.clone()))
    }

    fn poll_flush_tx(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.tx_pos < self.tx.len() {
            let n = ready!(Pin::new(&mut self.io).poll_write(cx, &self.tx[self.tx_pos..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.tx_pos += n;
        }
        self.tx.clear();
        self.tx_pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncRead for LegacyTlsStream<IO> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.plaintext_pos < this.plaintext.len() {
                let n = buf.remaining().min(this.plaintext.len() - this.plaintext_pos);
                buf.put_slice(&this.plaintext[this.plaintext_pos..this.plaintext_pos + n]);
                this.plaintext_pos += n;
                return Poll::Ready(Ok(()));
            }
            if let Some(e) = this.failed_error() {
                return Poll::Ready(Err(e));
            }
            if this.received_close_notify {
                return Poll::Ready(Ok(()));
            }
            match this.process_record() {
                Ok(true) => continue,
                Ok(false) => {}
                Err(e) => return Poll::Ready(Err(this.fail(cx, e))),
            }
            let mut chunk = [0u8; 8192];
            let mut chunk_buf = ReadBuf::new(&mut chunk);
            ready!(Pin::new(&mut this.io).poll_read(cx, &mut chunk_buf))?;
            if chunk_buf.filled().is_empty() {
                let e = TlsError::UnexpectedEof("after the handshake (possible truncation)");
                this.failed = Some((e.io_kind(), e.to_string()));
                return Poll::Ready(Err(io::Error::from(e)));
            }
            this.rx.extend_from_slice(chunk_buf.filled());
        }
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncWrite for LegacyTlsStream<IO> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let Some(e) = this.failed_error() {
            return Poll::Ready(Err(e));
        }
        if this.sent_close_notify {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        ready!(this.poll_flush_tx(cx))?;
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = data.len().min(MAX_PLAINTEXT);
        if let Err(e) = this.encryptor.seal(content::APPLICATION_DATA, &data[..n], &mut this.tx) {
            return Poll::Ready(Err(this.fail(cx, e)));
        }
        // The record is buffered, so the bytes are accepted even if the
        // transport is not ready yet; poll_flush finishes the write.
        let _ = this.poll_flush_tx(cx);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_flush_tx(cx))?;
        Pin::new(&mut this.io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.sent_close_notify && this.failed.is_none() {
            this.sent_close_notify = true;
            let mut out = Vec::new();
            if this.encryptor.seal(content::ALERT, &[1, alert::CLOSE_NOTIFY], &mut out).is_ok() {
                this.tx.extend_from_slice(&out);
            }
        }
        ready!(this.poll_flush_tx(cx))?;
        Pin::new(&mut this.io).poll_shutdown(cx)
    }
}
