/// reqs — blazing-fast HTTP/HTTPS benchmarking tool
///
/// ANSI color support: auto-disabled when NO_COLOR is set or stdout is not a TTY.
///
/// Architecture: raw TCP (no hyper), pre-built request bytes, zero-copy body
/// draining, per-worker HDR histograms, optional HTTP/1.1 pipelining.
use clap::Parser;
use hdrhistogram::Histogram;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
    BufWriter, ReadBuf,
};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

// ── CLI ───────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug, Clone)]
#[command(
    name = "reqs",
    about = "Blazing fast HTTP/HTTPS benchmarking tool",
    version,
    long_about = "High-performance HTTP/HTTPS load testing tool.\
        \nhttps://github.com/c0m4r/reqs\n\
        \nExamples:\
        \n  reqs -c 100 -d 30s https://example.com\
        \n  reqs -c 50 -n 10000 -t 4 http://localhost:8080\
        \n  reqs -c 10 -d 10s -p 16 http://localhost:8080   # pipelining"
)]
struct Args {
    /// Target URL (http:// or https://)
    url: String,

    /// Number of concurrent connections
    #[arg(short = 'c', long, default_value = "10")]
    connections: usize,

    /// Test duration (e.g. 10s, 1m30s). Conflicts with -n.
    #[arg(short = 'd', long, conflicts_with = "requests")]
    duration: Option<String>,

    /// Total requests to send. Conflicts with -d.
    #[arg(short = 'n', long, conflicts_with = "duration")]
    requests: Option<u64>,

    /// OS worker threads (default: CPU count)
    #[arg(short = 't', long)]
    threads: Option<usize>,

    /// Request timeout in seconds
    #[arg(long, default_value = "30")]
    timeout: u64,

    /// Request header, repeatable (e.g. -H "Accept: application/json")
    #[arg(short = 'H', long = "header")]
    headers: Vec<String>,

    /// HTTP method
    #[arg(short = 'X', long, default_value = "GET")]
    method: String,

    /// Show HTTP status code breakdown in results
    #[arg(short = 's', long)]
    status_codes: bool,

    /// Latency percentiles to display (comma-separated)
    #[arg(long, default_value = "50,75,90,95,99,99.9")]
    percentiles: String,

    /// Disable keep-alive (reconnect after each request)
    #[arg(long)]
    no_keepalive: bool,

    /// HTTP/1.1 pipeline depth — requests in-flight per connection
    #[arg(short = 'p', long, default_value = "1")]
    pipeline: usize,

    /// Skip TLS certificate verification (self-signed / internal CAs)
    #[arg(long)]
    insecure: bool,

    /// Disable colored output
    #[arg(long)]
    no_color: bool,

    /// Batch mode: suppress progress output and colors; only print final results (useful for scripting)
    #[arg(long)]
    batch: bool,
}

// ── Types ─────────────────────────────────────────────────────────────────────

struct Target {
    is_https: bool,
    host:     String,
    addr:     SocketAddr,
    path:     String,
}

struct SharedState {
    done:      AtomicU64,
    failed:    AtomicU64,
    bytes_rx:  AtomicU64,
    requested: AtomicU64, // pre-claim counter for -n mode
    stop:      AtomicBool,
}

impl Default for SharedState {
    fn default() -> Self {
        Self {
            done:      AtomicU64::new(0),
            failed:    AtomicU64::new(0),
            bytes_rx:  AtomicU64::new(0),
            requested: AtomicU64::new(0),
            stop:      AtomicBool::new(false),
        }
    }
}

struct WorkerResult {
    done:         u64,
    failed:       u64,
    bytes:        u64,
    histogram:    Histogram<u64>,
    status_counts: HashMap<u16, u64>,
}

struct RespInfo {
    status:           u16,
    content_length:   Option<u64>,
    is_chunked:       bool,
    connection_close: bool,
}

// ── Unified stream (HTTP or HTTPS) ────────────────────────────────────────────

enum AnyStream {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl AsyncRead for AnyStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Self::Tls(s)   => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for AnyStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Self::Tls(s)   => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_flush(cx),
            Self::Tls(s)   => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Self::Tls(s)   => Pin::new(s).poll_shutdown(cx),
        }
    }
}

// ── TLS certificate verifier (--insecure) ─────────────────────────────────────

#[derive(Debug)]
struct NoCertVerifier {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl NoCertVerifier {
    fn new() -> Self {
        Self { provider: Arc::new(rustls::crypto::ring::default_provider()) }
    }
}

impl ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer,
        _intermediates: &[CertificateDer],
        _server_name: &ServerName,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

// ── Connection helpers ────────────────────────────────────────────────────────

async fn tcp_connect(target: &Target, tls: Option<&TlsConnector>) -> io::Result<AnyStream> {
    let tcp = TcpStream::connect(target.addr).await?;
    tcp.set_nodelay(true)?;
    if target.is_https {
        let sn = ServerName::try_from(target.host.clone())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let tls_stream = tls
            .expect("TLS connector missing for HTTPS target")
            .connect(sn, tcp)
            .await?;
        Ok(AnyStream::Tls(Box::new(tls_stream)))
    } else {
        Ok(AnyStream::Plain(tcp))
    }
}

// ── HTTP/1.1 response parser (zero-alloc hot path) ───────────────────────────

async fn read_response_headers<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    line: &mut Vec<u8>,
) -> io::Result<RespInfo> {
    // Status line: "HTTP/1.x NNN ..."
    line.clear();
    if reader.read_until(b'\n', line).await? == 0 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionReset,
            "EOF on status line",
        ));
    }
    // Minimum valid status line: "HTTP/1.x NNN" = 12 bytes
    if line.len() < 12 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "short status line",
        ));
    }
    // Verify HTTP/1.x prefix before trusting any fixed offsets
    if !line.starts_with(b"HTTP/") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "response does not start with HTTP/",
        ));
    }
    let (d0, d1, d2) = (line[9], line[10], line[11]);
    if !d0.is_ascii_digit() || !d1.is_ascii_digit() || !d2.is_ascii_digit() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "non-numeric status code",
        ));
    }
    let status = (d0 - b'0') as u16 * 100
               + (d1 - b'0') as u16 * 10
               + (d2 - b'0') as u16;

    let mut content_length:   Option<u64> = None;
    let mut is_chunked        = false;
    let mut connection_close  = false;

    loop {
        line.clear();
        if reader.read_until(b'\n', line).await? == 0 {
            break;
        }
        if line == b"\r\n" || line == b"\n" {
            break;
        }
        // Branch on first byte to avoid lowercasing every header.
        // eq_ignore_ascii_case / windows comparison avoids heap allocation.
        match line[0].to_ascii_lowercase() {
            b'c' => {
                if line.len() >= 15 && line[..15].eq_ignore_ascii_case(b"content-length:") {
                    let v = std::str::from_utf8(&line[15..]).unwrap_or("").trim();
                    content_length = v.parse().ok();
                } else if line.len() >= 11 && line[..11].eq_ignore_ascii_case(b"connection:") {
                    connection_close =
                        line[11..].windows(5).any(|w| w.eq_ignore_ascii_case(b"close"));
                }
            }
            b't' => {
                if line.len() >= 18 && line[..18].eq_ignore_ascii_case(b"transfer-encoding:") {
                    is_chunked =
                        line[18..].windows(7).any(|w| w.eq_ignore_ascii_case(b"chunked"));
                }
            }
            _ => {}
        }
    }

    Ok(RespInfo {
        status,
        content_length,
        is_chunked,
        connection_close,
    })
}

/// Drain exactly `n` bytes without allocating.
async fn drain_exact<R: AsyncRead + Unpin>(
    reader: &mut R,
    mut n: u64,
    buf: &mut [u8],
) -> io::Result<()> {
    while n > 0 {
        let want = (n as usize).min(buf.len());
        let got = reader.read(&mut buf[..want]).await?;
        if got == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "body truncated",
            ));
        }
        n -= got as u64;
    }
    Ok(())
}

/// Drain a chunked-encoded body; returns total bytes consumed.
async fn drain_chunked<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    buf: &mut [u8],
    line: &mut Vec<u8>,
) -> io::Result<u64> {
    let mut total = 0u64;
    loop {
        line.clear();
        reader.read_until(b'\n', line).await?;
        let hex = std::str::from_utf8(line)
            .unwrap_or("")
            .trim()
            .split(';')
            .next()
            .unwrap_or("");
        let chunk_size = u64::from_str_radix(hex.trim(), 16)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid chunk size"))?;
        if chunk_size == 0 {
            // Drain optional trailer headers until the blank terminator line.
            // HTTP/1.1 chunked encoding allows trailers between "0\r\n" and
            // the final "\r\n"; reading only one line would leave them in the
            // BufReader and corrupt the next pipelined response.
            loop {
                line.clear();
                reader.read_until(b'\n', line).await?;
                if line == b"\r\n" || line == b"\n" || line.is_empty() {
                    break;
                }
            }
            break;
        }
        drain_exact(reader, chunk_size, buf).await?;
        drain_exact(reader, 2, buf).await?; // CRLF after chunk data
        total += chunk_size;
    }
    Ok(total)
}

// ── Worker ────────────────────────────────────────────────────────────────────

struct WorkerConfig {
    target:         Arc<Target>,
    req_bytes:      Arc<Vec<u8>>,
    tls:            Option<Arc<TlsConnector>>,
    timeout_dur:    Duration,
    state:          Arc<SharedState>,
    target_n:       Option<u64>,
    collect_status: bool,
    pipeline:       usize,
    no_keepalive:   bool,
}

async fn worker(cfg: WorkerConfig) -> WorkerResult {
    let WorkerConfig {
        target, req_bytes, tls, timeout_dur, state,
        target_n, collect_status, pipeline, no_keepalive,
    } = cfg;
    let mut hist = Histogram::<u64>::new_with_bounds(1, 60_000_000_000, 4).unwrap();
    let mut statuses: HashMap<u16, u64> = HashMap::new();
    let mut done   = 0u64;
    let mut failed = 0u64;
    let mut bytes  = 0u64;
    // Reusable drain buffer — 64 KB avoids most multi-read drains for small bodies
    let mut dbuf = vec![0u8; 64 * 1024];
    let mut line = Vec::<u8>::with_capacity(256);
    let pipeline = pipeline.max(1);

    // Requests that were in-flight when the server closed the connection.
    // Their slots are already claimed; we re-send them on the new connection
    // without claiming new slots, giving zero "spurious" failures.
    let mut conn_retries: usize = 0;

    'outer: loop {
        if state.stop.load(Ordering::Relaxed) {
            // stop is only set in duration mode (target_n is None),
            // so conn_retries hold no claimed -n slots — safe to discard.
            let _ = conn_retries;
            break;
        }

        // ── Establish connection ──────────────────────────────────────────
        let stream = match tcp_connect(&target, tls.as_deref()).await {
            Ok(s) => s,
            Err(_) => {
                // Discard retries — the connection itself is unavailable.
                conn_retries = 0;
                // In -n mode consume one slot so we make progress toward the
                // limit even when every connection attempt fails.
                if let Some(n) = target_n {
                    let slot = state.requested.fetch_add(1, Ordering::Relaxed);
                    if slot >= n {
                        break 'outer;
                    }
                }
                failed += 1;
                state.failed.fetch_add(1, Ordering::Relaxed);
                tokio::time::sleep(Duration::from_millis(5)).await;
                continue;
            }
        };

        let (rh, wh) = tokio::io::split(stream);
        // Large read buffer → fewer read() syscalls for many small responses
        let mut reader = BufReader::with_capacity(256 * 1024, rh);
        let mut writer = BufWriter::with_capacity(64 * 1024, wh);

        // Timestamps for in-flight requests (FIFO, matches HTTP/1.1 ordering)
        let mut inflight: VecDeque<Instant> = VecDeque::with_capacity(pipeline);
        let mut quota_done = false; // true when -n quota is exhausted

        // ── Initial pipeline fill ─────────────────────────────────────────
        // Retries (from a previous connection close) are sent first and do not
        // consume a new slot; remaining slots are claimed from the shared counter.
        let fill = if no_keepalive { 1 } else { pipeline };
        for _ in 0..fill {
            if state.stop.load(Ordering::Relaxed) {
                conn_retries = 0;
                break;
            }
            if conn_retries > 0 {
                conn_retries -= 1;
                // slot already claimed — just resend
            } else {
                if let Some(n) = target_n {
                    let slot = state.requested.fetch_add(1, Ordering::Relaxed);
                    if slot >= n {
                        quota_done = true;
                        break;
                    }
                }
            }
            if writer.write_all(&req_bytes).await.is_err() {
                failed += inflight.len() as u64;
                state.failed.fetch_add(inflight.len() as u64, Ordering::Relaxed);
                continue 'outer;
            }
            inflight.push_back(Instant::now());
        }
        // Send everything buffered in one syscall
        if writer.flush().await.is_err() {
            failed += inflight.len() as u64;
            state.failed.fetch_add(inflight.len() as u64, Ordering::Relaxed);
            continue 'outer;
        }

        if inflight.is_empty() {
            break 'outer; // quota already exhausted, nothing to do
        }

        // ── Read responses + refill pipeline ──────────────────────────────
        loop {
            let resp_result = tokio::time::timeout(
                timeout_dur,
                read_response_headers(&mut reader, &mut line),
            )
            .await;

            match resp_result {
                Ok(Ok(info)) => {
                    // Drain body without allocation
                    let body_len = if info.is_chunked {
                        match drain_chunked(&mut reader, &mut dbuf, &mut line).await {
                            Ok(n) => n,
                            Err(_) => {
                                failed += inflight.len() as u64;
                                state.failed.fetch_add(inflight.len() as u64, Ordering::Relaxed);
                                continue 'outer;
                            }
                        }
                    } else {
                        let n = info.content_length.unwrap_or(0);
                        if drain_exact(&mut reader, n, &mut dbuf).await.is_err() {
                            failed += inflight.len() as u64;
                            state.failed.fetch_add(inflight.len() as u64, Ordering::Relaxed);
                            continue 'outer;
                        }
                        n
                    };

                    // Record latency for this request
                    let t0 = inflight.pop_front().unwrap();
                    let us = t0.elapsed().as_micros() as u64;
                    done  += 1;
                    bytes += body_len;
                    let _ = hist.record(us.max(1));
                    state.done.fetch_add(1, Ordering::Relaxed);
                    state.bytes_rx.fetch_add(body_len, Ordering::Relaxed);
                    if collect_status {
                        *statuses.entry(info.status).or_insert(0) += 1;
                    }

                    let connection_closing = info.connection_close || no_keepalive;

                    if connection_closing {
                        // Server is closing after this response.  Any remaining
                        // in-flight requests were dropped by the server (e.g. nginx
                        // keepalive_requests limit).  Save them as retries so they
                        // are re-sent on the next connection without claiming new
                        // slots — this gives zero spurious failures.
                        // With no_keepalive, connection_closing is always true and the
                        // just-completed request was already popped from inflight, so
                        // inflight.len() == 0 here and conn_retries increases by 0.
                        conn_retries += inflight.len();
                        inflight.clear();
                        continue 'outer; // reconnect immediately
                    }

                    // Refill one pipeline slot on a healthy connection
                    if !quota_done && !state.stop.load(Ordering::Relaxed) {
                        let can_send = if conn_retries > 0 {
                            conn_retries -= 1;
                            true // retry slot already claimed
                        } else if let Some(n) = target_n {
                            let slot = state.requested.fetch_add(1, Ordering::Relaxed);
                            if slot >= n { quota_done = true; false } else { true }
                        } else {
                            true
                        };

                        if can_send {
                            if writer.write_all(&req_bytes).await.is_err()
                                || writer.flush().await.is_err()
                            {
                                failed += inflight.len() as u64;
                                state.failed.fetch_add(inflight.len() as u64, Ordering::Relaxed);
                                continue 'outer;
                            }
                            inflight.push_back(Instant::now());
                        }
                    }

                    if inflight.is_empty() {
                        break 'outer;
                    }
                }
                Ok(Err(_)) | Err(_) => {
                    // Genuine connection error / timeout — count as failures
                    failed += inflight.len() as u64;
                    state.failed.fetch_add(inflight.len() as u64, Ordering::Relaxed);
                    inflight.clear();
                    continue 'outer;
                }
            }
        }
    }

    WorkerResult {
        done,
        failed,
        bytes,
        histogram: hist,
        status_counts: statuses,
    }
}

// ── Color palette ────────────────────────────────────────────────────────────

struct Palette {
    bold:    &'static str,
    dim:     &'static str,  // charcoal — separators, secondary text
    accent:  &'static str,  // violet   — tool name, section titles
    cyan:    &'static str,  // lavender — metric values, URLs, percentiles
    green:   &'static str,  // mint     — success / completed
    yellow:  &'static str,  // amber    — req/s, warnings in progress
    red:     &'static str,  // coral    — errors, failures
    magenta: &'static str,  // gold     — throughput highlight
    reset:   &'static str,
}

impl Palette {
    fn colored() -> Self {
        Self {
            bold:    "\x1b[1m",
            dim:     "\x1b[38;5;240m",   // charcoal gray
            accent:  "\x1b[38;5;141m",   // soft violet
            cyan:    "\x1b[38;5;147m",   // lavender
            green:   "\x1b[38;5;114m",   // mint green
            yellow:  "\x1b[38;5;222m",   // warm amber
            red:     "\x1b[38;5;210m",   // coral / salmon
            magenta: "\x1b[38;5;214m",   // orange-gold
            reset:   "\x1b[0m",
        }
    }
    fn plain() -> Self {
        Self { bold: "", dim: "", accent: "", cyan: "", green: "", yellow: "", red: "", magenta: "", reset: "" }
    }
    fn detect(force_off: bool) -> Self {
        if force_off || std::env::var_os("NO_COLOR").is_some() || !isatty_stdout() {
            Self::plain()
        } else {
            Self::colored()
        }
    }
}

fn isatty_stdout() -> bool {
    // SAFETY: fileno is always valid, isatty is a pure query with no side effects.
    unsafe { libc::isatty(libc::STDOUT_FILENO) != 0 }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn contains_crlf(s: &str) -> bool {
    s.contains('\r') || s.contains('\n')
}

fn parse_headers(raw: &[String]) -> Result<Vec<(String, String)>, String> {
    raw.iter()
        .map(|h| {
            let (k, v) = h
                .split_once(':')
                .ok_or_else(|| format!("header missing ':' — {h:?}"))?;
            let name  = k.trim();
            let value = v.trim();
            if name.is_empty() {
                return Err(format!("empty header name in {h:?}"));
            }
            if contains_crlf(name) {
                return Err(format!("header name contains CR or LF: {name:?}"));
            }
            if contains_crlf(value) {
                return Err(format!("header value contains CR or LF: {value:?}"));
            }
            Ok((name.to_string(), value.to_string()))
        })
        .collect()
}

fn build_request(
    method: &str,
    path: &str,
    host: &str,
    extra: &[(String, String)],
    keepalive: bool,
) -> Result<Vec<u8>, String> {
    // Reject CR/LF in request-line components — they would corrupt the framing.
    if method.is_empty() || method.contains(['\r', '\n', ' ']) {
        return Err(format!("invalid HTTP method: {method:?}"));
    }
    if contains_crlf(path) {
        return Err(format!("path contains CR or LF: {path:?}"));
    }
    if contains_crlf(host) {
        return Err(format!("host contains CR or LF: {host:?}"));
    }
    let mut r = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\n");
    for (k, v) in extra {
        r.push_str(k);
        r.push_str(": ");
        r.push_str(v);
        r.push_str("\r\n");
    }
    if !keepalive {
        r.push_str("Connection: close\r\n");
    }
    r.push_str("\r\n");
    Ok(r.into_bytes())
}

fn fmt_bytes(b: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    if b >= GB      { format!("{:.2} GB", b as f64 / GB as f64) }
    else if b >= MB { format!("{:.2} MB", b as f64 / MB as f64) }
    else if b >= KB { format!("{:.2} KB", b as f64 / KB as f64) }
    else            { format!("{b} B") }
}

fn fmt_us(us: u64) -> String {
    if us >= 1_000_000      { format!("{:.3}s",  us as f64 / 1_000_000.0) }
    else if us >= 1_000     { format!("{:.3}ms", us as f64 / 1_000.0) }
    else                    { format!("{us}µs") }
}

// ── main ──────────────────────────────────────────────────────────────────────

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Resolve test mode
    let test_dur: Option<Duration> = match &args.duration {
        Some(d) => Some(humantime::parse_duration(d)?),
        None if args.requests.is_none() => {
            eprintln!("No -d or -n specified; defaulting to 10s");
            Some(Duration::from_secs(10))
        }
        None => None,
    };

    // Parse URL
    let url = &args.url;
    let (scheme, rest) = url.split_once("://").ok_or("URL missing ://")?;
    let is_https = match scheme.to_ascii_lowercase().as_str() {
        "https" => true,
        "http"  => false,
        other   => return Err(format!("unsupported scheme '{other}'; only http and https are supported").into()),
    };
    let (host_port, path_str) = rest.split_once('/').unwrap_or((rest, ""));
    let path = format!("/{path_str}");

    // Parse host and port with IPv6 literal support ([::1]:8080)
    let is_ipv6_literal = host_port.starts_with('[');
    let (host, port): (&str, u16) = if is_ipv6_literal {
        let end = host_port
            .find(']')
            .ok_or("IPv6 address missing closing ']'")?;
        let h = &host_port[1..end];
        let rest_after = &host_port[end + 1..];
        let p: u16 = if let Some(port_str) = rest_after.strip_prefix(':') {
            port_str.parse().map_err(|_| "invalid port in URL")?
        } else if rest_after.is_empty() {
            if is_https { 443 } else { 80 }
        } else {
            return Err(format!("unexpected characters after IPv6 address: {rest_after:?}").into());
        };
        (h, p)
    } else {
        match host_port.split_once(':') {
            Some((h, p)) => (h, p.parse().map_err(|_| "invalid port in URL")?),
            None => (host_port, if is_https { 443 } else { 80 }),
        }
    };

    // Use the tuple form of to_socket_addrs so IPv6 bare addresses are
    // passed correctly without any manual bracket/colon formatting.
    let addr = (host, port)
        .to_socket_addrs()?
        .next()
        .ok_or("DNS resolution failed")?;

    let target = Arc::new(Target {
        is_https,
        host: host.to_string(),
        addr,
        path,
    });

    // RFC 7230 §5.4: IPv6 literals in the Host header must be bracketed.
    let host_header = if is_ipv6_literal {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };

    let extra_headers = parse_headers(&args.headers)
        .map_err(|e| format!("invalid header: {e}"))?;
    let req_bytes = Arc::new(
        build_request(
            &args.method,
            &target.path,
            &host_header,
            &extra_headers,
            !args.no_keepalive,
        )
        .map_err(|e| format!("invalid request: {e}"))?,
    );

    let threads = args.threads.unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
    });
    let connections   = args.connections;
    let pipeline      = args.pipeline.max(1);
    let timeout_dur   = Duration::from_secs(args.timeout);
    let target_n      = args.requests;
    let collect_status = args.status_codes;
    let no_keepalive  = args.no_keepalive;
    let insecure      = args.insecure;
    let percentiles_str = args.percentiles.clone();
    let batch = args.batch;
    let palette = Palette::detect(args.no_color || batch);

    // Build TLS connector once (shared across all workers)
    let tls_connector: Option<Arc<TlsConnector>> = if is_https {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let base = ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()
            .map_err(|e| format!("TLS protocol config error: {e}"))?;
        let cfg = if insecure {
            base.dangerous()
                .with_custom_certificate_verifier(Arc::new(NoCertVerifier::new()))
                .with_no_client_auth()
        } else {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            base.with_root_certificates(roots).with_no_client_auth()
        };
        Some(Arc::new(TlsConnector::from(Arc::new(cfg))))
    } else {
        None
    };

    // Build multi-threaded tokio runtime
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(threads)
        .enable_all()
        .build()?;

    rt.block_on(async move {
        // ── Pre-flight connectivity check ─────────────────────────────────
        if let Err(e) = tcp_connect(&target, tls_connector.as_deref()).await {
            eprintln!("error: cannot connect to {}: {e}", args.url);
            if is_https && !insecure {
                eprintln!("hint:  for self-signed or internal certificates, add --insecure");
            }
            return Ok(());
        }

        let state = Arc::new(SharedState::default());
        let start = Instant::now();

        if !batch {
            let mode_str = match test_dur {
                Some(d) => format!("for {:.1}s", d.as_secs_f64()),
                None    => format!("{} requests", target_n.unwrap()),
            };
            println!(
                "{dim}╺╸{reset} {accent}{bold}reqs{reset}  {dim}{mode_str}{reset}  {dim}·{reset}  {cyan}{connections}{reset} conn  {dim}·{reset}  {cyan}{threads}{reset} thread(s)  {dim}·{reset}  pipeline {cyan}{pipeline}{reset}",
                dim = palette.dim, reset = palette.reset, accent = palette.accent,
                bold = palette.bold, cyan = palette.cyan,
            );
            println!("{dim}  ↪{reset}  {}",  args.url, dim = palette.dim, reset = palette.reset);
            println!();
        }

        // Spawn worker tasks
        let mut handles = Vec::with_capacity(connections);
        for _ in 0..connections {
            handles.push(tokio::spawn(worker(WorkerConfig {
                target:         Arc::clone(&target),
                req_bytes:      Arc::clone(&req_bytes),
                tls:            tls_connector.clone(),
                timeout_dur,
                state:          Arc::clone(&state),
                target_n,
                collect_status,
                pipeline,
                no_keepalive,
            })));
        }

        // Ctrl+C handler — sets stop flag so workers drain and results are printed
        let state_ctrlc = Arc::clone(&state);
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            state_ctrlc.stop.store(true, Ordering::Relaxed);
        });

        // Progress reporter + duration-based stop signal
        let state2 = Arc::clone(&state);
        let prog = tokio::spawn(async move {
            let mut iv = tokio::time::interval(Duration::from_secs(1));
            let mut last_done = 0u64;
            let mut tick = 0u64;
            loop {
                iv.tick().await;
                tick += 1;
                let done   = state2.done.load(Ordering::Relaxed);
                let failed = state2.failed.load(Ordering::Relaxed);
                let rps    = done.saturating_sub(last_done);
                last_done  = done;
                if !batch {
                    eprint!(
                        "\r  {dim}▪{reset} {yellow}{:>4}s{reset}  {dim}·{reset}  {magenta}{:>10} req/s{reset}  {dim}·{reset}  {green}{:>9} done{reset}  {dim}·{reset}  {red}{:>7} failed{reset}",
                        tick, rps, done, failed,
                        dim = palette.dim, yellow = palette.yellow, magenta = palette.magenta,
                        green = palette.green, red = palette.red, reset = palette.reset,
                    );
                }
                if state2.stop.load(Ordering::Relaxed) {
                    break;
                }
                if let Some(dur) = test_dur {
                    if start.elapsed() >= dur {
                        state2.stop.store(true, Ordering::Relaxed);
                        break;
                    }
                }
                if let Some(n) = target_n {
                    let req = state2.requested.load(Ordering::Relaxed);
                    if req >= n && done + failed >= n {
                        break;
                    }
                }
            }
        });

        // Collect worker results
        let mut results = Vec::with_capacity(connections);
        for h in handles {
            if let Ok(r) = h.await { results.push(r); }
        }
        prog.abort();
        let elapsed = start.elapsed();
        if !batch {
            eprint!("\r{:<72}\r", ""); // clear progress line
        }

        // Merge per-worker results
        let mut total_done   = 0u64;
        let mut total_failed = 0u64;
        let mut total_bytes  = 0u64;
        let mut hist = Histogram::<u64>::new_with_bounds(1, 60_000_000_000, 4).unwrap();
        let mut status_map: HashMap<u16, u64> = HashMap::new();

        for r in results {
            total_done   += r.done;
            total_failed += r.failed;
            total_bytes  += r.bytes;
            hist.add(&r.histogram).ok();
            if collect_status {
                for (code, cnt) in r.status_counts {
                    *status_map.entry(code).or_insert(0) += cnt;
                }
            }
        }

        let secs = elapsed.as_secs_f64();
        let rps  = total_done as f64 / secs;
        let tput = total_bytes as f64 / secs;

        // ── Report ────────────────────────────────────────────────────────
        let sep = format!("{dim}{}{reset}", "━".repeat(52), dim = palette.dim, reset = palette.reset);
        let b   = palette.bold;
        let c   = palette.cyan;
        let g   = palette.green;
        let r   = palette.red;
        let mg  = palette.magenta;
        let ac  = palette.accent;
        let rs  = palette.reset;
        println!("{sep}");
        println!("  {ac}{b}◆ reqs{rs}  {dim}v{}{rs}", env!("CARGO_PKG_VERSION"), dim = palette.dim);
        println!("{sep}");
        println!("  {b}Target    {rs} {c}{}{rs}", args.url);
        println!("  {b}Duration  {rs} {:.3}s", secs);
        println!("  {b}Threads   {rs} {}  {dim}·{rs}  {b}Connections{rs} {}  {dim}·{rs}  {b}Pipeline{rs} {}",
            threads, connections, pipeline, dim = palette.dim);
        println!("{sep}");
        println!("  {b}Requests  {rs} {}", total_done + total_failed);
        println!("  {b}Completed {rs} {g}{total_done}{rs}");
        let fail_pct = if total_done + total_failed > 0 {
            100.0 * total_failed as f64 / (total_done + total_failed) as f64
        } else { 0.0 };
        let fail_color = if total_failed > 0 { r } else { g };
        println!("  {b}Failed    {rs} {fail_color}{} ({:.2}%){rs}", total_failed, fail_pct);
        println!("  {b}Req/s     {rs} {mg}{rps:.2}{rs}");
        println!("  {b}Data recv {rs} {}", fmt_bytes(total_bytes));
        println!("  {b}Throughput{rs} {mg}{}/s{rs}", fmt_bytes(tput as u64));

        if !hist.is_empty() {
            // ── Latency (horizontal) ─────────────────────────────────
            let lat_cols: &[(&str, String)] = &[
                ("Min",   fmt_us(hist.min())),
                ("Avg",   fmt_us(hist.mean() as u64)),
                ("Max",   fmt_us(hist.max())),
                ("Stdev", fmt_us(hist.stdev() as u64)),
            ];
            // Column width = max(label len, value len) + 2 padding
            let lat_widths: Vec<usize> = lat_cols
                .iter()
                .map(|(lbl, val)| lbl.len().max(val.len()) + 2)
                .collect();

            println!("{sep}");
            // Header row
            print!("  {ac}{b}Latency{rs}   ");
            for ((lbl, _), w) in lat_cols.iter().zip(&lat_widths) {
                print!("  {b}{:^w$}{rs}", lbl, w = w);
            }
            println!();
            // Value row
            print!("              ");
            for ((_, val), w) in lat_cols.iter().zip(&lat_widths) {
                print!("  {c}{:^w$}{rs}", val, w = w, c = c, rs = rs);
            }
            println!();

            // ── Percentiles (horizontal) ─────────────────────────────
            let pct_cols: Vec<(String, String)> = percentiles_str
                .split(',')
                .filter_map(|s| s.trim().parse::<f64>().ok())
                .map(|p| (format!("p{p}"), fmt_us(hist.value_at_quantile(p / 100.0))))
                .collect();

            if !pct_cols.is_empty() {
                let pct_widths: Vec<usize> = pct_cols
                    .iter()
                    .map(|(lbl, val)| lbl.len().max(val.len()) + 2)
                    .collect();

                println!("{sep}");
                // Header row
                print!("  {ac}{b}Percentiles{rs}");
                for ((lbl, _), w) in pct_cols.iter().zip(&pct_widths) {
                    print!("  {b}{:^w$}{rs}", lbl, w = w);
                }
                println!();
                // Value row
                print!("               ");
                for ((_, val), w) in pct_cols.iter().zip(&pct_widths) {
                    print!("  {c}{:^w$}{rs}", val, w = w, c = c, rs = rs);
                }
                println!();
            }
        }

        if collect_status && !status_map.is_empty() {
            println!("{sep}");
            println!("  {ac}{b}Status Codes{rs}");
            let mut codes: Vec<_> = status_map.iter().collect();
            codes.sort_by_key(|(k, _)| *k);
            for (code, cnt) in codes {
                let code_color = match code / 100 {
                    2 => g,
                    3 => c,
                    4 | 5 => r,
                    _ => b,
                };
                println!("  {dim}·{rs}  {code_color}{code}{rs}  {dim}┈┈{rs}  {cnt}",
                    dim = palette.dim);
            }
        }

        println!("{sep}");
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;

    Ok(())
}
