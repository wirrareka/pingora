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

//! Tool-corpus validation harness for the passive HTTP/2 client fingerprint
//! (`h2-fingerprint` feature, `protocols::http::v2::fingerprint`).
//!
//! # Why this exists
//!
//! The sniffer's unit tests feed it *synthetic* frame bytes. That proves the
//! parser, but it cannot prove that the strings it emits are the strings a WAF
//! corpus (hjörr's `TOOL_FINGERPRINTS` / `BROWSER_PSEUDO_ORDERS`) is written
//! against — the corpus is derived from third-party observations (peet.ws /
//! Akamai), and a one-off discrepancy in field order, weight-encoding or
//! WINDOW_UPDATE handling would turn into a silent false negative (tool not
//! recognised) or, worse, a false positive on a real browser.
//!
//! This example therefore stands up a *real* Pingora HTTPS/h2 listener on
//! loopback and prints the fingerprint that real client tools produce, so the
//! corpus can be validated against ground truth.
//!
//! It deliberately goes through the full production path — `Service` ->
//! `HttpServerApp::process_new` -> `fingerprint::wrap` -> `h2::server::handshake`
//! — rather than driving `Sniffer` directly, so that the wiring in
//! `apps/mod.rs` (ALPN detection, digest construction) is covered too.
//!
//! # Security posture
//!
//! Binds **127.0.0.1 only**, on a caller-chosen high port. Serves a fixed
//! text/plain body and reads nothing from the request beyond what Pingora
//! already parsed. Purely a test fixture; not part of the shipped proxy.
//!
//! # How to run
//!
//! ```text
//! cargo run -p pingora-core -F openssl,h2-fingerprint --example h2fp_probe -- \
//!     --nocapture-port 18443
//! ```
//!
//! (the port is taken from the `H2FP_PORT` env var, default 18443, because
//! Pingora's own `Opt` owns the command line).
//!
//! Then, from another shell:
//!
//! ```text
//! curl -sk --http2 https://127.0.0.1:18443/    # h2 over TLS
//! curl -sk --http1.1 https://127.0.0.1:18443/  # fail-open: no fingerprint
//! ```
//!
//! Every request logs one line to stdout:
//!
//! ```text
//! H2FP\tALPN=h2\tFP=1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p\tUA=curl/8.7.1
//! ```
//!
//! and the same fields are echoed in the response body, so a client that cannot
//! read the server's stdout can still capture its own fingerprint.

#![cfg_attr(not(feature = "openssl"), allow(unused))]

use async_trait::async_trait;
use http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use http::{Response, StatusCode};
use pingora_core::apps::http_app::ServeHttp;
use pingora_core::protocols::http::ServerSession;

/// Echoes the connection's HTTP/2 fingerprint back to the client and logs it.
struct H2FpProbe;

#[async_trait]
impl ServeHttp for H2FpProbe {
    async fn response(&self, session: &mut ServerSession) -> Response<Vec<u8>> {
        // `Digest::h2_digest` is a `OnceCell` filled by the sniffer before the
        // first request is dispatched. `None` (or an unfilled cell) is the
        // fail-open case: HTTP/1.x, or an h2 preamble we refused to guess at.
        let fp = session
            .digest()
            .and_then(|d| d.h2_digest.as_ref())
            .and_then(|cell| cell.get())
            .cloned();

        let alpn = match session {
            ServerSession::H2(_) => "h2",
            _ => "http/1.1",
        };
        let ua = session
            .req_header()
            .headers
            .get(http::header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("<none>")
            .to_string();
        let path = session.req_header().uri.path().to_string();

        // One machine-readable line per request, for the driver script to grep.
        println!(
            "H2FP\tALPN={alpn}\tPATH={path}\tFP={}\tUA={ua}",
            fp.as_deref().unwrap_or("<none>")
        );
        use std::io::Write;
        let _ = std::io::stdout().flush();

        let body = format!(
            "alpn={alpn}\nfp={}\nua={ua}\n",
            fp.as_deref().unwrap_or("<none>")
        )
        .into_bytes();

        Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "text/plain")
            .header(CONTENT_LENGTH, body.len())
            .body(body)
            .unwrap()
    }
}

#[cfg(all(feature = "openssl", feature = "h2-fingerprint"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use pingora_core::apps::http_app::HttpServer;
    use pingora_core::apps::HttpServerOptions;
    use pingora_core::listeners::tls::TlsSettings;
    use pingora_core::server::Server;
    use pingora_core::services::listening::Service;

    env_logger::init();

    // Loopback only, high port. Never a privileged port, never 0.0.0.0.
    let port: u16 = std::env::var("H2FP_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(18443);
    let tls_addr = format!("127.0.0.1:{port}");
    // Cleartext h2c (prior knowledge) on port+1, so clients without a way to
    // skip certificate verification can still be fingerprinted. The sniffer is
    // post-TLS either way, so the string is identical.
    let h2c_addr = format!("127.0.0.1:{}", port + 1);

    // `Server::new(None)` would parse this process' argv as Pingora options;
    // pass an explicit default so the harness owns its own environment.
    let mut server = Server::new(None)?;
    server.bootstrap();

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let cert = format!("{manifest_dir}/examples/keys/server/cert.pem");
    let key = format!("{manifest_dir}/examples/keys/server/key.pem");

    // `h2c` lets the plaintext listener upgrade on the h2 preface, which is how
    // clients that refuse a self-signed certificate are still fingerprinted.
    let mut app = HttpServer::new_app(H2FpProbe);
    let mut server_options = HttpServerOptions::default();
    server_options.h2c = true;
    app.server_options = Some(server_options);

    let mut svc = Service::new("h2fp probe".to_owned(), app);
    let mut tls_settings = TlsSettings::intermediate(&cert, &key)?;
    // Advertise h2 in ALPN; without this the client falls back to HTTP/1.1 and
    // the sniffer is (correctly) never installed.
    tls_settings.enable_h2();
    svc.add_tls_with_settings(&tls_addr, None, tls_settings);
    svc.add_tcp(&h2c_addr);
    server.add_service(svc);

    eprintln!("h2fp_probe listening: https://{tls_addr} (h2) and http://{h2c_addr} (h2c)");
    server.run_forever();
}

#[cfg(not(all(feature = "openssl", feature = "h2-fingerprint")))]
fn main() {
    eprintln!("This example requires the 'openssl' and 'h2-fingerprint' features.");
}
