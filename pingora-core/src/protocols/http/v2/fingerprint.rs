// Copyright 2026 Cloudflare, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Passive HTTP/2 client fingerprinting (Akamai-style), behind the default-off
//! `h2-fingerprint` cargo feature.
//!
//! # Why this exists
//!
//! A WAF/bot-management layer wants to know *which HTTP/2 implementation* is
//! talking to it. Unlike a `User-Agent` (a free-form string the client chooses)
//! or even a TLS fingerprint (increasingly forgeable with uTLS-style libraries),
//! the HTTP/2 connection preamble is emitted by the HTTP library itself: the
//! SETTINGS values, the connection-level WINDOW_UPDATE increment, whether the
//! client opens the tree with PRIORITY frames, and the *order* in which it emits
//! the pseudo-headers. Changing them means swapping HTTP stacks, not flipping a
//! flag. This is the "Akamai HTTP/2 fingerprint" described in Shapira & Bahrami,
//! *Passive Fingerprinting of HTTP/2 Clients* (Akamai, 2017).
//!
//! Detection context: MITRE ATT&CK **T1071.001** (Application Layer Protocol:
//! Web Protocols) — adversary tooling that mimics browser traffic at the
//! HTTP/UA level is distinguished here at the protocol-implementation level.
//! This code is *purely observational*: it classifies, it never blocks, and it
//! never modifies the byte stream.
//!
//! # Why a byte sniffer and not the `h2` crate
//!
//! The information is destroyed inside `h2` before Pingora can see it:
//!
//! * pseudo-header arrival order is written into the fixed named fields of
//!   `h2::frame::headers::Pseudo` during HPACK decode, so order is gone by the
//!   time `HeaderBlock::load_hpack` returns;
//! * the peer's SETTINGS map and connection-level WINDOW_UPDATE increments are
//!   not exposed by `h2::server::Connection`'s public surface, and not even by
//!   its `unstable` feature (the `Connection` fields stay private).
//!
//! Recovering them through `h2` would require forking `h2` itself. Instead we
//! read the bytes: after TLS termination the client preface, SETTINGS,
//! WINDOW_UPDATE and PRIORITY frames and the first HEADERS block are plaintext,
//! and they all arrive *before* any application data. See
//! `hjorr/docs/design/h2fp-pingora-integration-plan.md` §1 for the full
//! survey and the rejected alternatives.
//!
//! # Emitted format
//!
//! `S[settings]|WU[window_update]|P[priority]|PS[pseudo_header_order]`, e.g.
//!
//! ```text
//! 1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
//! ```
//!
//! * `S` — the first non-ACK SETTINGS frame, as `id:value` pairs joined by `;`,
//!   **in the order the client sent them** (the order is itself discriminating).
//! * `WU` — the increment of the first connection-level (stream 0) WINDOW_UPDATE,
//!   or `0` if the client sent none.
//! * `P` — PRIORITY frames as `streamid:exclusive:dependency:weight` joined by
//!   `,`, or `0` if none. Per RFC 9113 §6.3 the wire weight field is
//!   "weight minus one", so the reported weight is the wire byte `+ 1` (this
//!   matches the reference corpora, e.g. Firefox's `3:0:0:201`).
//! * `PS` — pseudo-header order, one letter each: `m` `:method`, `a`
//!   `:authority`, `s` `:scheme`, `p` `:path`. **Empty** when the order could not
//!   be determined with certainty (see fail-open below); consumers treat an empty
//!   `PS` as "unknown" and skip the order rule.
//!
//! # Reading pseudo-header order without HPACK state
//!
//! We do not run an HPACK decoder; we only walk the representations of the
//! *first* HEADERS block for order. On a fresh connection the dynamic table is
//! empty (RFC 7541 §2.3.2), so any index `<= 61` is a static-table entry, and the
//! pseudo-headers are exactly static indices 1 `:authority`, 2/3 `:method`,
//! 4/5 `:path`, 6/7 `:scheme` (RFC 7541 Appendix A). Literal representations
//! carry a length-prefixed name and value, so skipping keeps the walk in sync.
//! The walk stops at the first non-pseudo header (RFC 9113 §8.3 requires all
//! pseudo-headers to precede regular ones).
//!
//! # Safety / fail-open rules (FP-first)
//!
//! A *wrong* fingerprint is worse than no fingerprint, because it becomes a false
//! positive downstream. Therefore:
//!
//! * anything unexpected — non-HTTP/2 traffic, a truncated or malformed frame, a
//!   Huffman-coded literal pseudo-header name, an index we cannot resolve without
//!   dynamic-table state, a duplicate pseudo-header — **stops sniffing** and
//!   yields no fingerprint (or a fingerprint with an empty `PS`, when only the
//!   header block was ambiguous);
//! * the sniffer never writes, delays, reorders or rewrites anything; it copies
//!   bytes that have *already* been handed to the caller;
//! * the copy is bounded by [`SNIFF_LIMIT`] and the buffer is dropped the moment
//!   sniffing ends, after which the wrapper is a pure passthrough;
//! * no slice is indexed without a preceding length check, and there is no
//!   `unsafe` — a hostile client must not be able to panic the proxy.
//!
//! References: RFC 9113 (HTTP/2, frame layout §4/§6; obsoletes RFC 7540),
//! RFC 7541 (HPACK, integer §5.1, string §5.2, static table Appendix A),
//! Akamai passive HTTP/2 fingerprinting (2017).

use std::fmt;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_trait::async_trait;
use once_cell::sync::OnceCell;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::protocols::raw_connect::ProxyDigest;
use crate::protocols::tls::{SslDigest, TlsRef, ALPN};
use crate::protocols::{
    GetProxyDigest, GetSocketDigest, GetTimingDigest, Peek, Shutdown, SocketDigest, Ssl, Stream,
    TimingDigest, UniqueID, UniqueIDType,
};

/// Client connection preface, RFC 9113 §3.4.
const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Upper bound on the bytes copied for sniffing, per connection.
///
/// 32 KiB = 2x `SETTINGS_MAX_FRAME_SIZE`'s default of 16384 (RFC 9113 §6.5.2).
/// The preface (24 B) + SETTINGS + WINDOW_UPDATE + a handful of PRIORITY frames
/// are together well under 200 bytes, so this leaves room for a full
/// default-max-size first HEADERS frame plus margin, while capping the
/// per-connection memory a hostile client can pin at 32 KiB — and only until the
/// first HEADERS frame, since the buffer is freed as soon as sniffing ends.
/// Clients that negotiate a larger max frame size and then send a >32 KiB first
/// HEADERS block simply get no fingerprint (fail-open).
pub const SNIFF_LIMIT: usize = 32 * 1024;

/// Cap on recorded PRIORITY frames, so a client cannot grow the output string
/// without bound. Real clients send at most a handful (Firefox sends 5).
const MAX_PRIORITY_FRAMES: usize = 16;

/// Cap on pseudo-headers recorded. There are only four (plus `:protocol`), so
/// anything beyond this is malformed and we fail open.
const MAX_PSEUDO: usize = 8;

// Frame types, RFC 9113 §6.
const FRAME_HEADERS: u8 = 0x1;
const FRAME_PRIORITY: u8 = 0x2;
const FRAME_SETTINGS: u8 = 0x4;
const FRAME_WINDOW_UPDATE: u8 = 0x8;

// HEADERS flags, RFC 9113 §6.2.
const FLAG_PADDED: u8 = 0x8;
const FLAG_PRIORITY: u8 = 0x20;
// SETTINGS flags, RFC 9113 §6.5.
const FLAG_ACK: u8 = 0x1;

/// Wrap a downstream [`Stream`] in a passive HTTP/2 fingerprint sniffer.
///
/// Returns the wrapped stream (which is itself a `Stream`, since
/// `protocols::IO` has a blanket impl) and the cell the fingerprint will be
/// published into. The cell is filled at most once, before the first request on
/// the connection is dispatched, and stays empty if the client's preamble could
/// not be parsed with certainty.
pub fn wrap(inner: Stream) -> (Stream, Option<Arc<OnceCell<String>>>) {
    let out = Arc::new(OnceCell::new());
    let stream = H2FingerprintStream {
        inner,
        sniffer: Some(Box::new(Sniffer::new())),
        out: out.clone(),
    };
    (Box::new(stream), Some(out))
}

/// A tee wrapper that copies (never alters) the first bytes read from the
/// downstream connection and derives an HTTP/2 fingerprint from them.
pub struct H2FingerprintStream {
    inner: Stream,
    /// `None` once sniffing has finished or been abandoned; from then on this
    /// type is a pure delegating passthrough.
    sniffer: Option<Box<Sniffer>>,
    out: Arc<OnceCell<String>>,
}

impl fmt::Debug for H2FingerprintStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Transparent: downstream logging must keep showing the real connection.
        self.inner.fmt(f)
    }
}

impl AsyncRead for H2FingerprintStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let filled_before = buf.filled().len();
        let me = &mut *self;
        let res = Pin::new(&mut me.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &res {
            if let Some(sniffer) = me.sniffer.as_mut() {
                let new = &buf.filled()[filled_before..];
                if new.is_empty() {
                    // EOF before the preamble completed: nothing to report.
                    me.sniffer = None;
                } else {
                    match sniffer.feed(new) {
                        Feed::More => {}
                        Feed::Done(fp) => {
                            let _ = me.out.set(fp);
                            me.sniffer = None;
                        }
                        Feed::Abort => me.sniffer = None,
                    }
                }
            }
        }
        res
    }
}

impl AsyncWrite for H2FingerprintStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[async_trait]
impl Shutdown for H2FingerprintStream {
    async fn shutdown(&mut self) {
        self.inner.shutdown().await
    }
}

impl UniqueID for H2FingerprintStream {
    fn id(&self) -> UniqueIDType {
        self.inner.id()
    }
}

impl Ssl for H2FingerprintStream {
    fn get_ssl(&self) -> Option<&TlsRef> {
        self.inner.get_ssl()
    }

    fn get_ssl_digest(&self) -> Option<Arc<SslDigest>> {
        self.inner.get_ssl_digest()
    }

    fn selected_alpn_proto(&self) -> Option<ALPN> {
        self.inner.selected_alpn_proto()
    }
}

impl GetTimingDigest for H2FingerprintStream {
    fn get_timing_digest(&self) -> Vec<Option<TimingDigest>> {
        self.inner.get_timing_digest()
    }

    fn get_read_pending_time(&self) -> std::time::Duration {
        self.inner.get_read_pending_time()
    }

    fn get_write_pending_time(&self) -> std::time::Duration {
        self.inner.get_write_pending_time()
    }
}

impl GetProxyDigest for H2FingerprintStream {
    fn get_proxy_digest(&self) -> Option<Arc<ProxyDigest>> {
        self.inner.get_proxy_digest()
    }

    fn set_proxy_digest(&mut self, digest: ProxyDigest) {
        self.inner.set_proxy_digest(digest)
    }
}

impl GetSocketDigest for H2FingerprintStream {
    fn get_socket_digest(&self) -> Option<Arc<SocketDigest>> {
        self.inner.get_socket_digest()
    }

    fn set_socket_digest(&mut self, socket_digest: SocketDigest) {
        self.inner.set_socket_digest(socket_digest)
    }
}

#[async_trait]
impl Peek for H2FingerprintStream {
    async fn try_peek(&mut self, buf: &mut [u8]) -> io::Result<bool> {
        // Peeked bytes are not consumed, so they will be seen again by
        // `poll_read`; sniffing them here would double-count.
        self.inner.try_peek(buf).await
    }
}

/// Outcome of handing more bytes to the sniffer.
enum Feed {
    /// Need more bytes.
    More,
    /// Fingerprint complete.
    Done(String),
    /// Give up (fail-open); the caller drops the sniffer.
    Abort,
}

/// The frame walker. Holds only what the output needs.
struct Sniffer {
    buf: Vec<u8>,
    /// Parse cursor into `buf`; everything before it is fully consumed frames.
    pos: usize,
    preface_done: bool,
    seen_settings: bool,
    settings: Vec<(u16, u32)>,
    window_update: Option<u32>,
    priorities: Vec<String>,
}

impl Sniffer {
    fn new() -> Self {
        Sniffer {
            buf: Vec::new(),
            pos: 0,
            preface_done: false,
            seen_settings: false,
            settings: Vec::new(),
            window_update: None,
            priorities: Vec::new(),
        }
    }

    fn feed(&mut self, data: &[u8]) -> Feed {
        if self.buf.len() + data.len() > SNIFF_LIMIT {
            return Feed::Abort;
        }
        self.buf.extend_from_slice(data);
        match self.parse() {
            Ok(Some(fp)) => {
                self.buf = Vec::new();
                Feed::Done(fp)
            }
            Ok(None) => Feed::More,
            Err(()) => {
                self.buf = Vec::new();
                Feed::Abort
            }
        }
    }

    /// `Ok(None)` means "need more bytes", `Err(())` means "stop, fail open".
    fn parse(&mut self) -> Result<Option<String>, ()> {
        if !self.preface_done {
            if self.buf.len() < PREFACE.len() {
                // Bail out as early as the prefix diverges, so plain HTTP/1
                // traffic (`GET / HTTP/1.1`) costs one comparison, not a buffer.
                if !PREFACE.starts_with(&self.buf[..]) {
                    return Err(());
                }
                return Ok(None);
            }
            if &self.buf[..PREFACE.len()] != PREFACE {
                return Err(());
            }
            self.preface_done = true;
            self.pos = PREFACE.len();
        }

        loop {
            let rest = &self.buf[self.pos..];
            if rest.len() < 9 {
                return Ok(None);
            }
            // Frame header, RFC 9113 §4.1: 24-bit length, 8-bit type, 8-bit
            // flags, 1 reserved bit + 31-bit stream id.
            let len = u32::from_be_bytes([0, rest[0], rest[1], rest[2]]) as usize;
            let ftype = rest[3];
            let flags = rest[4];
            let stream_id = u32::from_be_bytes([rest[5], rest[6], rest[7], rest[8]]) & 0x7fff_ffff;
            if len > SNIFF_LIMIT {
                // Cannot be buffered within our bound; stop now rather than
                // accumulate until the limit trips.
                return Err(());
            }
            if rest.len() < 9 + len {
                return Ok(None);
            }
            let start = self.pos + 9;
            let payload = &self.buf[start..start + len];

            match ftype {
                FRAME_SETTINGS => {
                    if flags & FLAG_ACK == 0 && !self.seen_settings {
                        if len % 6 != 0 {
                            return Err(());
                        }
                        self.seen_settings = true;
                        for c in payload.chunks_exact(6) {
                            let id = u16::from_be_bytes([c[0], c[1]]);
                            let val = u32::from_be_bytes([c[2], c[3], c[4], c[5]]);
                            self.settings.push((id, val));
                        }
                    }
                }
                FRAME_WINDOW_UPDATE => {
                    if len != 4 {
                        return Err(());
                    }
                    if stream_id == 0 && self.window_update.is_none() {
                        let inc =
                            u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]])
                                & 0x7fff_ffff;
                        self.window_update = Some(inc);
                    }
                }
                FRAME_PRIORITY => {
                    if len != 5 {
                        return Err(());
                    }
                    if self.priorities.len() < MAX_PRIORITY_FRAMES {
                        let dep_raw =
                            u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                        let exclusive = dep_raw >> 31;
                        let dep = dep_raw & 0x7fff_ffff;
                        // RFC 9113 §6.3: the wire field is "weight minus one".
                        let weight = u16::from(payload[4]) + 1;
                        self.priorities
                            .push(format!("{stream_id}:{exclusive}:{dep}:{weight}"));
                    }
                }
                FRAME_HEADERS => {
                    // The first HEADERS ends the preamble: everything the
                    // fingerprint needs has arrived.
                    let order = pseudo_order(payload, flags).unwrap_or_default();
                    return Ok(Some(self.render(&order)));
                }
                _ => { /* PING, RST_STREAM, etc.: not part of the fingerprint */ }
            }
            self.pos = start + len;
        }
    }

    fn render(&self, pseudo: &str) -> String {
        let mut settings = String::new();
        for (i, (id, val)) in self.settings.iter().enumerate() {
            if i > 0 {
                settings.push(';');
            }
            settings.push_str(&format!("{id}:{val}"));
        }
        let wu = self.window_update.unwrap_or(0);
        let prio = if self.priorities.is_empty() {
            "0".to_string()
        } else {
            self.priorities.join(",")
        };
        format!("{settings}|{wu}|{prio}|{pseudo}")
    }
}

/// Extract the pseudo-header order letters from a HEADERS payload.
/// `None` means "could not determine with certainty" — emit an empty `PS`.
fn pseudo_order(payload: &[u8], flags: u8) -> Option<String> {
    let mut block = payload;
    if flags & FLAG_PADDED != 0 {
        let (&pad, rest) = block.split_first()?;
        let pad = usize::from(pad);
        if pad > rest.len() {
            return None;
        }
        block = &rest[..rest.len() - pad];
    }
    if flags & FLAG_PRIORITY != 0 {
        // 4-byte stream dependency + 1-byte weight, RFC 9113 §6.2.
        if block.len() < 5 {
            return None;
        }
        block = &block[5..];
    }
    hpack_pseudo_order(block)
}

/// What an HPACK index / literal name means for the pseudo-header walk.
enum Field {
    /// A pseudo-header, represented by its fingerprint letter.
    Pseudo(char),
    /// A regular header: the pseudo-header section is over (RFC 9113 §8.3).
    Regular,
}

/// Map a static-table index to a field kind. `None` = cannot resolve, fail open.
fn field_for_index(idx: u64) -> Option<Field> {
    // RFC 7541 Appendix A. Index 0 is invalid; 1..=7 are the pseudo-headers;
    // 8..=61 are regular headers; >61 would need dynamic-table state, which is
    // empty on a fresh connection, so we refuse to guess.
    match idx {
        1 => Some(Field::Pseudo('a')),     // :authority
        2 | 3 => Some(Field::Pseudo('m')), // :method GET/POST
        4 | 5 => Some(Field::Pseudo('p')), // :path / and /index.html
        6 | 7 => Some(Field::Pseudo('s')), // :scheme http/https
        8..=61 => Some(Field::Regular),
        _ => None,
    }
}

/// Map a literal (non-Huffman) header name to a field kind.
fn field_for_name(name: &str) -> Option<Field> {
    match name {
        ":method" => Some(Field::Pseudo('m')),
        ":authority" => Some(Field::Pseudo('a')),
        ":scheme" => Some(Field::Pseudo('s')),
        ":path" => Some(Field::Pseudo('p')),
        // `:protocol` (RFC 8441) and any unknown pseudo-header have no letter in
        // the Akamai format; rather than silently drop it and emit a subtly wrong
        // order, fail open.
        n if n.starts_with(':') => None,
        _ => Some(Field::Regular),
    }
}

/// Walk HPACK representations for pseudo-header *order only*, no decoder state.
fn hpack_pseudo_order(mut block: &[u8]) -> Option<String> {
    let mut order: Vec<char> = Vec::new();
    while let Some(&b) = block.first() {
        let field = if b & 0x80 != 0 {
            // Indexed Header Field, RFC 7541 §6.1. No value follows.
            let (idx, rest) = decode_int(block, 7)?;
            block = rest;
            field_for_index(idx)?
        } else if b & 0xE0 == 0x20 {
            // Dynamic Table Size Update, RFC 7541 §6.3. No name/value follows.
            let (_size, rest) = decode_int(block, 5)?;
            block = rest;
            continue;
        } else {
            // Literal Header Field: incremental indexing (§6.2.1, 6-bit prefix),
            // without indexing (§6.2.2) or never indexed (§6.2.3, 4-bit prefix).
            let prefix = if b & 0xC0 == 0x40 { 6 } else { 4 };
            let (idx, rest) = decode_int(block, prefix)?;
            block = rest;
            let field = if idx == 0 {
                let (name, rest) = decode_str(block)?;
                block = rest;
                // A Huffman-coded name yields `None` here: we do not decode
                // Huffman, so we cannot tell whether it was a pseudo-header.
                field_for_name(name?.as_str())?
            } else {
                field_for_index(idx)?
            };
            // Skip the value regardless of what the name was.
            let (_value, rest) = decode_str(block)?;
            block = rest;
            field
        };
        match field {
            Field::Regular => break,
            Field::Pseudo(letter) => {
                if order.contains(&letter) || order.len() >= MAX_PSEUDO {
                    return None; // duplicate/absurd pseudo-header: malformed
                }
                order.push(letter);
            }
        }
    }
    if order.is_empty() {
        return None;
    }
    let mut out = String::with_capacity(order.len() * 2);
    for (i, c) in order.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push(*c);
    }
    Some(out)
}

/// HPACK integer, RFC 7541 §5.1. Returns the value and the remaining bytes.
fn decode_int(buf: &[u8], prefix_bits: u32) -> Option<(u64, &[u8])> {
    let (&first, mut rest) = buf.split_first()?;
    let max_prefix = (1u64 << prefix_bits) - 1;
    let mut value = u64::from(first) & max_prefix;
    if value < max_prefix {
        return Some((value, rest));
    }
    let mut shift = 0;
    // A u32-sized value needs at most 5 continuation octets; more than that is
    // either malicious or unusable for us.
    for _ in 0..5 {
        let (&b, tail) = rest.split_first()?;
        rest = tail;
        value = value.checked_add(u64::from(b & 0x7f).checked_shl(shift)?)?;
        if b & 0x80 == 0 {
            return Some((value, rest));
        }
        shift += 7;
    }
    None
}

/// HPACK string literal, RFC 7541 §5.2. Returns `(None, rest)` for a
/// Huffman-coded string (we skip it rather than decode it) and the remaining
/// bytes in both cases.
fn decode_str(buf: &[u8]) -> Option<(Option<String>, &[u8])> {
    let huffman = buf.first()? & 0x80 != 0;
    let (len, rest) = decode_int(buf, 7)?;
    let len = usize::try_from(len).ok()?;
    if rest.len() < len {
        return None;
    }
    let (raw, tail) = rest.split_at(len);
    if huffman {
        Some((None, tail))
    } else {
        Some((Some(std::str::from_utf8(raw).ok()?.to_string()), tail))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- synthetic wire builders -------------------------------------------

    fn frame(ftype: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
        let len = payload.len();
        let mut v = vec![(len >> 16) as u8, (len >> 8) as u8, len as u8, ftype, flags];
        v.extend_from_slice(&stream_id.to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    fn settings(pairs: &[(u16, u32)]) -> Vec<u8> {
        let mut p = Vec::new();
        for (k, v) in pairs {
            p.extend_from_slice(&k.to_be_bytes());
            p.extend_from_slice(&v.to_be_bytes());
        }
        frame(FRAME_SETTINGS, 0, 0, &p)
    }

    fn window_update(inc: u32) -> Vec<u8> {
        frame(FRAME_WINDOW_UPDATE, 0, 0, &inc.to_be_bytes())
    }

    fn priority(stream_id: u32, exclusive: bool, dep: u32, weight: u16) -> Vec<u8> {
        let mut p = Vec::new();
        let raw = if exclusive { dep | 0x8000_0000 } else { dep };
        p.extend_from_slice(&raw.to_be_bytes());
        p.push((weight - 1) as u8);
        frame(FRAME_PRIORITY, 0, stream_id, &p)
    }

    /// Indexed Header Field (static index).
    fn indexed(idx: u8) -> Vec<u8> {
        vec![0x80 | idx]
    }

    /// Literal Header Field with Incremental Indexing, indexed name, plain value.
    fn literal_indexed_name(idx: u8, value: &str) -> Vec<u8> {
        let mut v = vec![0x40 | idx];
        v.push(value.len() as u8); // H=0
        v.extend_from_slice(value.as_bytes());
        v
    }

    /// Literal Header Field with Incremental Indexing, literal (plain) name.
    fn literal_new_name(name: &str, value: &str) -> Vec<u8> {
        let mut v = vec![0x40, name.len() as u8];
        v.extend_from_slice(name.as_bytes());
        v.push(value.len() as u8);
        v.extend_from_slice(value.as_bytes());
        v
    }

    fn headers(block: Vec<u8>) -> Vec<u8> {
        frame(FRAME_HEADERS, 0x4 | 0x1, 1, &block) // END_HEADERS|END_STREAM
    }

    fn sniff(bytes: &[u8]) -> Option<String> {
        let mut s = Sniffer::new();
        match s.feed(bytes) {
            Feed::Done(fp) => Some(fp),
            _ => None,
        }
    }

    // ---- tests -------------------------------------------------------------

    #[test]
    fn curl_like_connection() {
        // nghttp2/curl: SETTINGS(3,4), WINDOW_UPDATE, pseudo order m,p,s,a with
        // :method GET and :scheme https as static indices, :path and :authority
        // as literals with indexed names.
        let mut wire = Vec::from(PREFACE);
        wire.extend(settings(&[(3, 100), (4, 1073741824)]));
        wire.extend(window_update(1073741824 - 65535));
        let mut block = Vec::new();
        block.extend(indexed(2)); // :method GET
        block.extend(literal_indexed_name(4, "/index")); // :path
        block.extend(indexed(7)); // :scheme https
        block.extend(literal_indexed_name(1, "example.com")); // :authority
        block.extend(literal_indexed_name(58, "curl/8.4.0")); // user-agent
        wire.extend(headers(block));

        assert_eq!(
            sniff(&wire).as_deref(),
            Some("3:100;4:1073741824|1073676289|0|m,p,s,a")
        );
    }

    #[test]
    fn browser_like_connection_with_priority_frames() {
        // Firefox-shaped: SETTINGS, several PRIORITY frames, WINDOW_UPDATE,
        // pseudo order m,p,a,s.
        let mut wire = Vec::from(PREFACE);
        wire.extend(settings(&[(1, 65536), (4, 131072), (5, 16384)]));
        wire.extend(priority(3, false, 0, 201));
        wire.extend(priority(5, false, 0, 101));
        wire.extend(window_update(12517377));
        let mut block = Vec::new();
        block.extend(indexed(2)); // :method
        block.extend(literal_indexed_name(4, "/")); // :path
        block.extend(literal_indexed_name(1, "example.com")); // :authority
        block.extend(indexed(7)); // :scheme
        wire.extend(headers(block));

        assert_eq!(
            sniff(&wire).as_deref(),
            Some("1:65536;4:131072;5:16384|12517377|3:0:0:201,5:0:0:101|m,p,a,s")
        );
    }

    #[test]
    fn chrome_like_order_and_no_window_update() {
        let mut wire = Vec::from(PREFACE);
        wire.extend(settings(&[(1, 65536), (2, 0), (4, 6291456), (6, 262144)]));
        let mut block = Vec::new();
        block.extend(indexed(2)); // m
        block.extend(literal_indexed_name(1, "example.com")); // a
        block.extend(indexed(7)); // s
        block.extend(literal_indexed_name(4, "/")); // p
        wire.extend(headers(block));

        assert_eq!(
            sniff(&wire).as_deref(),
            Some("1:65536;2:0;4:6291456;6:262144|0|0|m,a,s,p")
        );
    }

    #[test]
    fn split_across_many_reads_is_identical() {
        let mut wire = Vec::from(PREFACE);
        wire.extend(settings(&[(1, 65536), (2, 0)]));
        wire.extend(window_update(15663105));
        let mut block = Vec::new();
        block.extend(indexed(2));
        block.extend(literal_indexed_name(1, "h.example"));
        block.extend(indexed(7));
        block.extend(literal_indexed_name(4, "/"));
        wire.extend(headers(block));

        let whole = sniff(&wire).unwrap();

        // Feed one byte at a time: the incremental parser must agree.
        let mut s = Sniffer::new();
        let mut got = None;
        for b in &wire {
            if let Feed::Done(fp) = s.feed(&[*b]) {
                got = Some(fp);
                break;
            }
        }
        assert_eq!(got.as_deref(), Some(whole.as_str()));
    }

    #[test]
    fn literal_new_name_pseudo_header_is_understood() {
        let mut wire = Vec::from(PREFACE);
        wire.extend(settings(&[(4, 65535)]));
        let mut block = Vec::new();
        block.extend(literal_new_name(":method", "GET"));
        block.extend(literal_new_name(":authority", "example.com"));
        block.extend(literal_new_name(":scheme", "https"));
        block.extend(literal_new_name(":path", "/"));
        block.extend(literal_new_name("accept", "*/*"));
        wire.extend(headers(block));

        assert_eq!(sniff(&wire).as_deref(), Some("4:65535|0|0|m,a,s,p"));
    }

    #[test]
    fn padded_and_prioritized_headers_frame() {
        let mut wire = Vec::from(PREFACE);
        wire.extend(settings(&[(4, 65535)]));
        let mut block = vec![3u8]; // pad length
        block.extend_from_slice(&0u32.to_be_bytes()); // stream dependency
        block.push(200); // weight
        block.extend(indexed(2));
        block.extend(indexed(7));
        block.extend(literal_indexed_name(4, "/"));
        block.extend(literal_indexed_name(1, "e.com"));
        block.extend_from_slice(&[0, 0, 0]); // padding
        wire.extend(frame(
            FRAME_HEADERS,
            0x4 | FLAG_PADDED | FLAG_PRIORITY,
            1,
            &block,
        ));

        assert_eq!(sniff(&wire).as_deref(), Some("4:65535|0|0|m,s,p,a"));
    }

    #[test]
    fn huffman_literal_pseudo_name_fails_open_to_empty_ps() {
        // A pseudo-header whose *name* is Huffman-coded cannot be identified
        // without a Huffman decoder: emit the frame components, no PS.
        let mut wire = Vec::from(PREFACE);
        wire.extend(settings(&[(4, 65535)]));
        let mut block = vec![0x40u8, 0x80 | 3, 0xb8, 0xdb, 0x2e]; // H=1, len=3
        block.push(3);
        block.extend_from_slice(b"GET");
        block.extend(indexed(7));
        wire.extend(headers(block));

        assert_eq!(sniff(&wire).as_deref(), Some("4:65535|0|0|"));
    }

    #[test]
    fn dynamic_table_index_fails_open_to_empty_ps() {
        let mut wire = Vec::from(PREFACE);
        wire.extend(settings(&[(4, 65535)]));
        let mut block = Vec::new();
        block.extend(indexed(62)); // first dynamic-table slot: unresolvable
        wire.extend(headers(block));

        assert_eq!(sniff(&wire).as_deref(), Some("4:65535|0|0|"));
    }

    #[test]
    fn duplicate_pseudo_header_fails_open_to_empty_ps() {
        let mut wire = Vec::from(PREFACE);
        wire.extend(settings(&[(4, 65535)]));
        let mut block = Vec::new();
        block.extend(indexed(2));
        block.extend(indexed(3)); // :method twice
        wire.extend(headers(block));

        assert_eq!(sniff(&wire).as_deref(), Some("4:65535|0|0|"));
    }

    #[test]
    fn http1_traffic_aborts_immediately() {
        let mut s = Sniffer::new();
        assert!(matches!(s.feed(b"GET / HTTP/1.1\r\n"), Feed::Abort));

        // Even a single divergent byte is enough.
        let mut s = Sniffer::new();
        assert!(matches!(s.feed(b"P"), Feed::More));
        assert!(matches!(s.feed(b"OST"), Feed::Abort));
    }

    #[test]
    fn truncated_input_never_completes_and_never_panics() {
        let mut wire = Vec::from(PREFACE);
        wire.extend(settings(&[(1, 65536)]));
        let mut block = Vec::new();
        block.extend(indexed(2));
        block.extend(literal_indexed_name(1, "example.com"));
        wire.extend(headers(block));

        for cut in 0..wire.len() {
            let mut s = Sniffer::new();
            // Any prefix must either want more or abort — never complete.
            assert!(
                !matches!(s.feed(&wire[..cut]), Feed::Done(_)),
                "prefix of {cut} bytes completed"
            );
        }
    }

    #[test]
    fn oversized_headers_frame_aborts() {
        let mut wire = Vec::from(PREFACE);
        wire.extend(settings(&[(1, 65536)]));
        // Declare a HEADERS frame larger than the sniff bound.
        let len = SNIFF_LIMIT + 1;
        wire.extend_from_slice(&[
            (len >> 16) as u8,
            (len >> 8) as u8,
            len as u8,
            FRAME_HEADERS,
            0x4,
        ]);
        wire.extend_from_slice(&1u32.to_be_bytes());
        let mut s = Sniffer::new();
        assert!(matches!(s.feed(&wire), Feed::Abort));
    }

    #[test]
    fn buffer_is_bounded() {
        let mut s = Sniffer::new();
        assert!(matches!(s.feed(PREFACE), Feed::More));
        // A stream of well-formed but useless frames must not grow the buffer
        // past the bound.
        let ping = frame(0x6, 0, 0, &[0u8; 8]);
        let mut fed = PREFACE.len();
        loop {
            match s.feed(&ping) {
                Feed::More => {
                    fed += ping.len();
                    assert!(s.buf.len() <= SNIFF_LIMIT);
                    assert!(fed < SNIFF_LIMIT + ping.len());
                }
                Feed::Abort => break,
                Feed::Done(_) => panic!("PING must not complete a fingerprint"),
            }
        }
    }

    #[test]
    fn garbage_after_preface_aborts() {
        let mut wire = Vec::from(PREFACE);
        // SETTINGS with a payload length that is not a multiple of 6.
        wire.extend(frame(FRAME_SETTINGS, 0, 0, &[0u8; 5]));
        let mut s = Sniffer::new();
        assert!(matches!(s.feed(&wire), Feed::Abort));
    }

    #[test]
    fn random_bytes_after_preface_never_panic() {
        // Cheap deterministic fuzz: LCG-generated payloads behind a valid preface.
        let mut state: u64 = 0x2545_F491_4F6C_DD1D;
        for _ in 0..2000 {
            let mut wire = Vec::from(PREFACE);
            let n = (state % 300) as usize;
            for _ in 0..n {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                wire.push((state >> 33) as u8);
            }
            let mut s = Sniffer::new();
            let _ = s.feed(&wire); // must not panic
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        }
    }

    #[tokio::test]
    async fn wrapper_publishes_fingerprint_and_passes_bytes_through() {
        use tokio::io::AsyncReadExt;

        let mut wire = Vec::from(PREFACE);
        wire.extend(settings(&[(1, 65536), (2, 0)]));
        wire.extend(window_update(15663105));
        let mut block = Vec::new();
        block.extend(indexed(2));
        block.extend(literal_indexed_name(1, "example.com"));
        block.extend(indexed(7));
        block.extend(literal_indexed_name(4, "/"));
        wire.extend(headers(block));

        let mock = tokio_test::io::Builder::new().read(&wire).build();
        let (mut stream, cell) = wrap(Box::new(mock));
        let cell = cell.unwrap();

        let mut got = Vec::new();
        stream.read_to_end(&mut got).await.unwrap();

        // The byte stream reaches the caller untouched.
        assert_eq!(got, wire);
        assert_eq!(
            cell.get().map(String::as_str),
            Some("1:65536;2:0|15663105|0|m,a,s,p")
        );
    }

    /// End-to-end against a *real* HTTP/2 client (the `h2` crate, a dev
    /// dependency): the sniffer sits under `h2::server::handshake` exactly as it
    /// does in `apps::mod`, and must both let the connection work and produce a
    /// fingerprint from the genuine wire bytes.
    #[tokio::test]
    async fn real_h2_client_against_h2_server_through_the_wrapper() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (stream, cell) = wrap(Box::new(server_io));
        let cell = cell.unwrap();

        let client = tokio::spawn(async move {
            let (mut send, conn) = h2::client::Builder::new()
                .initial_window_size(6291456)
                .initial_connection_window_size(15728640)
                .max_concurrent_streams(100)
                .handshake::<_, bytes::Bytes>(client_io)
                .await
                .unwrap();
            tokio::spawn(async move {
                let _ = conn.await;
            });
            let req = http::Request::builder()
                .method("GET")
                .uri("https://example.com/hello")
                .body(())
                .unwrap();
            let (resp, _) = send.send_request(req, true).unwrap();
            resp.await.unwrap().status()
        });

        let mut conn = h2::server::handshake(stream).await.unwrap();
        let (req, mut respond) = conn.accept().await.unwrap().unwrap();
        assert_eq!(req.method(), http::Method::GET);
        respond
            .send_response(http::Response::new(()), true)
            .unwrap();
        tokio::spawn(async move { while conn.accept().await.is_some() {} });

        assert_eq!(client.await.unwrap(), http::StatusCode::OK);

        let fp = cell.get().expect("fingerprint from a real h2 client");
        // Printed so `cargo test -- --nocapture` shows what a real stack emits.
        eprintln!("h2 crate client fingerprint: {fp}");
        // Structure: four `|`-separated components, and a plausible pseudo order.
        let parts: Vec<&str> = fp.split('|').collect();
        assert_eq!(parts.len(), 4, "unexpected fingerprint shape: {fp}");
        assert!(parts[0].contains(':'), "no SETTINGS in {fp}");
        assert!(parts[1].parse::<u32>().is_ok(), "bad WINDOW_UPDATE in {fp}");
        let mut letters: Vec<&str> = parts[3].split(',').collect();
        letters.sort_unstable();
        assert_eq!(letters, vec!["a", "m", "p", "s"], "bad PS in {fp}");
        // `h2` emits :method, :scheme, :authority, :path in that fixed order.
        assert_eq!(parts[3], "m,s,a,p", "h2 crate pseudo order changed: {fp}");
    }

    #[tokio::test]
    async fn wrapper_is_transparent_for_non_h2_traffic() {
        use tokio::io::AsyncReadExt;

        let wire = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
        let mock = tokio_test::io::Builder::new().read(&wire).build();
        let (mut stream, cell) = wrap(Box::new(mock));
        let cell = cell.unwrap();

        let mut got = Vec::new();
        stream.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, wire);
        assert!(cell.get().is_none());
    }
}
