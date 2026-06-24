// kalista bench baseline — "pure pingora" reference for the beat-nginx comparison.
//
// The most minimal `ProxyHttp` possible: every request is forwarded to ONE fixed
// upstream, with NO features — no request_filter, no logging hook, no per-request
// Ctx (`type CTX = ()`), no header rewriting beyond the Host the upstream needs.
// Run it with the SAME ServerConf tuning as kalista's data plane (threads = 4,
// work_stealing = false → thread-per-core; SO_REUSEPORT_LB is automatic on FreeBSD
// via this fork's l4 patch) so the ONLY difference vs kalista in the bench is
// kalista's feature layer. This isolates:
//   gap(pure-pingora vs nginx)  = pingora's inherent architectural floor
//   gap(kalista vs pure-pingora) = kalista's feature overhead (optimizable in us)
//
// Build:  cargo build --release --example kalista_baseline -p pingora-proxy
// Run:    ./kalista_baseline -c kalista_baseline_conf.yaml   (conf below)
// conf.yaml:
//   ---
//   version: 1
//   threads: 4
//   work_stealing: false
//
// Point the load generator at 0.0.0.0:8080 and the upstream at 127.0.0.1:18081
// (the same loopback upstream the kalista bench uses). Adjust LISTEN/UPSTREAM to
// match the harness; keep the protocol (plain HTTP here) identical across all four
// proxies (nginx / pure-pingora / caddy / kalista) for a fair p99 comparison.

use async_trait::async_trait;
use pingora_core::server::configuration::Opt;
use pingora_core::server::Server;
use pingora_core::upstreams::peer::HttpPeer;
use pingora_core::Result;
use pingora_proxy::{ProxyHttp, Session};

const UPSTREAM: &str = "127.0.0.1:18081";
const LISTEN: &str = "0.0.0.0:8080";

pub struct Baseline;

#[async_trait]
impl ProxyHttp for Baseline {
    type CTX = ();
    fn new_ctx(&self) -> Self::CTX {}

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        // plain HTTP to the loopback upstream (false = no upstream TLS), empty SNI.
        Ok(Box::new(HttpPeer::new(UPSTREAM, false, String::new())))
    }
}

fn main() {
    // `-c <conf.yaml>` carries threads = 4 / work_stealing = false to match kalista.
    let opt = Opt::parse_args();
    let mut server = Server::new(Some(opt)).unwrap();
    server.bootstrap();

    let mut proxy = pingora_proxy::http_proxy_service(&server.configuration, Baseline);
    proxy.add_tcp(LISTEN);
    server.add_service(proxy);
    server.run_forever();
}
