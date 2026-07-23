//! A label-injecting Docker API proxy, run *inside* the sandbox as `lim __docker-proxy`.
//!
//! ## Why this exists
//!
//! A sandbox forwards the limes daemon socket, so anything inside that speaks the Docker API
//! — the `docker` CLI, `compose`, an SDK, a testcontainers-style library — creates *sibling*
//! containers on the shared daemon. Left alone those siblings have no tie to the sandbox that
//! spawned them: they outlive it, `lim ps` can't see them, and `lim prune` (stopped-only)
//! can't reap them. Binding their lifetime to the parent needs every container attributed to
//! its sandbox *at create time*, and the only place that catches **all** clients (not just the
//! CLI) is the API itself. So this proxy sits between the sandbox and the real socket and
//! stamps `limes.owner=<sandbox>` onto the body of every `POST …/containers/create`. Teardown
//! (`sandbox::release`) then reaps by that label.
//!
//! ## Why it lives in the container
//!
//! Every shell is a peer `docker exec`; the container outlives any single `lim` process (see
//! `sandbox`). A proxy in `lim run` would die mid-session if a `lim exec` shell outlived it,
//! taking the socket with it. Running it inside the container ties its life to the container's
//! — one proxy, shared by every shell, gone when the sandbox stops.
//!
//! ## What it does and doesn't parse
//!
//! Only `containers/create` is rewritten, and only its (small, `Content-Length`-framed) JSON
//! body is ever buffered. Every other request is forwarded head-first and then the connection
//! is spliced raw in both directions — which is what preserves the connection *hijacks* behind
//! `docker run -it` / `exec -it` and the open-ended streams behind `logs -f`, `events`, `pull`
//! and `build`. A create's response is `Content-Length`-framed, so after one we can resume
//! reading the next request on the same keep-alive connection and label it too (compose issues
//! several creates); anything without a length ends the connection instead of being buffered.

use std::io::{self, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::thread;

use anyhow::{Context, Result};

use crate::context::LABEL;

/// Serve until killed: accept on `listen`, and proxy each connection to `upstream`, stamping
/// `<LABEL>.owner=<owner>` onto every container-create that passes through.
pub fn serve(listen: &Path, upstream: &Path, owner: &str) -> Result<()> {
    // A stale socket from a previous life would make bind() fail with EADDRINUSE.
    let _ = std::fs::remove_file(listen);
    let l = UnixListener::bind(listen)
        .with_context(|| format!("binding proxy socket {}", listen.display()))?;

    let key = format!("{LABEL}.owner");
    for conn in l.incoming() {
        let client = match conn {
            Ok(c) => c,
            Err(_) => continue, // a single failed accept must not take the proxy down
        };
        // One upstream connection per client connection: a 1:1 mapping keeps the state
        // machine per-connection and needs no pooling.
        let up = match UnixStream::connect(upstream) {
            Ok(u) => u,
            Err(_) => continue, // daemon momentarily unreachable — drop this client, keep serving
        };
        let (key, owner) = (key.clone(), owner.to_string());
        // A panicking handler ends its own connection and nothing else: the accept loop above
        // is what must survive, so each connection gets its own thread and its own unwind.
        thread::spawn(move || {
            let _ = handle(client, up, &key, &owner);
        });
    }
    Ok(())
}

/// Proxy one client connection, labeling every create that crosses it.
fn handle(mut client: UnixStream, mut up: UnixStream, key: &str, owner: &str) -> Result<()> {
    loop {
        let Some(head) = read_head(&mut client)? else {
            return Ok(()); // clean EOF: the client closed between requests
        };
        let req = parse_head(&head);
        let is_head = req.method.eq_ignore_ascii_case("HEAD");

        // Requests we can neither frame nor safely buffer: a hijack (`run -it`/`exec -it`), a
        // streamed/chunked request body (`build`, `import`), or an `Expect: 100-continue`
        // handshake where reading the body first would deadlock. Forward the head and hand the
        // rest to a raw splice — correct, unlabeled, and it ends the connection. The docker CLI
        // does not pipeline a create after any of these, so nothing is missed.
        if req.is_upgrade() || req.is_chunked() || req.expects_continue() {
            up.write_all(&head).context("forwarding request head")?;
            splice(client, up);
            return Ok(());
        }

        // The rewrite: a create with a buffered, length-framed JSON body gets `limes.owner`.
        if req.is_create()
            && let Some(len) = req.content_length()
        {
            let mut body = vec![0u8; len];
            client.read_exact(&mut body).context("reading create body")?;
            match inject_label(&body, key, owner) {
                Some(nb) => {
                    up.write_all(&rebuild_head(&req, nb.len()))
                        .and_then(|_| up.write_all(&nb))
                        .context("forwarding rewritten create")?;
                }
                // Body wasn't the JSON object we expected — forward it untouched.
                None => up.write_all(&head).and_then(|_| up.write_all(&body))?,
            }
        } else {
            // Any other framed request: forward the head, then its (possibly empty,
            // length-framed) body. Nothing here streams — those left via the splice above.
            up.write_all(&head).context("forwarding request head")?;
            if let Some(len) = req.content_length() {
                copy_n(&mut client, &mut up, len)?;
            }
        }

        // Relay the response. If it is exactly framed we loop for the next request on this
        // keep-alive connection — which is the whole point: the CLI sends `/_ping` first and
        // *then* the create on the same connection, so we must survive the ping to see the
        // create. A streaming response (chunked/unframed: `logs -f`, `events`) has no end we
        // can wait for, so we splice the rest and stop.
        if !relay_response(&mut up, &mut client, is_head)? {
            splice(client, up);
            return Ok(());
        }
    }
}

/// Read one HTTP head (request or status line + headers) up to and including the blank line.
///
/// One byte at a time so we never read into the body — the create path then `read_exact`s the
/// body, and the splice path hands the still-untouched stream to the raw copy. Heads are tiny
/// and creates are infrequent, so the syscall cost is irrelevant here.
fn read_head(s: &mut UnixStream) -> Result<Option<Vec<u8>>> {
    const MAX: usize = 64 * 1024;
    let mut buf = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    loop {
        match s.read(&mut byte) {
            Ok(0) => {
                // EOF: clean only if it lands on a request boundary, not mid-head.
                return if buf.is_empty() { Ok(None) } else { Ok(Some(buf)) };
            }
            Ok(_) => {
                buf.push(byte[0]);
                if buf.ends_with(b"\r\n\r\n") {
                    return Ok(Some(buf));
                }
                if buf.len() > MAX {
                    anyhow::bail!("HTTP head exceeded {MAX} bytes");
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e).context("reading HTTP head"),
        }
    }
}

/// The parsed view of a head we actually use: the first line's method/path plus the header
/// lines, each kept verbatim so a non-rewritten forward is byte-preserving.
struct Head<'a> {
    method: &'a str,
    path: &'a str,
    /// `(name, value)` with original casing; `name` compared case-insensitively by callers.
    headers: Vec<(&'a str, &'a str)>,
}

fn parse_head(raw: &[u8]) -> Head<'_> {
    let text = std::str::from_utf8(raw).unwrap_or("");
    let mut lines = text.split("\r\n");
    let first = lines.next().unwrap_or("");
    let mut parts = first.split(' ');
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");
    let headers = lines
        .filter(|l| !l.is_empty())
        .filter_map(|l| l.split_once(':').map(|(k, v)| (k.trim(), v.trim())))
        .collect();
    Head { method, path, headers }
}

impl Head<'_> {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| *v)
    }

    fn content_length(&self) -> Option<usize> {
        self.header("content-length").and_then(|v| v.trim().parse().ok())
    }

    /// A POST whose path (minus any `?query` and any `/vX.Y` API-version prefix) is the
    /// container-create endpoint.
    fn is_create(&self) -> bool {
        self.method.eq_ignore_ascii_case("POST")
            && self.path.split('?').next().unwrap_or("").ends_with("/containers/create")
    }

    /// A client that will withhold the body until it sees `100 Continue`. Buffering the body
    /// here would deadlock, so such a create is passed through unrewritten instead.
    fn expects_continue(&self) -> bool {
        self.header("expect").is_some_and(|v| v.eq_ignore_ascii_case("100-continue"))
    }

    /// A hijacked connection (`docker run -it`, `exec -it`, `attach`): after the response the
    /// stream goes raw and bidirectional, so it must be spliced, never framed.
    fn is_upgrade(&self) -> bool {
        self.header("upgrade").is_some()
            || self.header("connection").is_some_and(|v| v.to_ascii_lowercase().contains("upgrade"))
    }

    /// A body whose length isn't declared up front — a chunked request (`build`/`import`
    /// context) or a streamed response. We forward these but never buffer them.
    fn is_chunked(&self) -> bool {
        self.header("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked"))
    }

    /// The status code from a *response* head's first line (`HTTP/1.1 204 …` → `204`).
    fn status_code(&self) -> u16 {
        self.path.parse().unwrap_or(0)
    }
}

/// Re-emit a create's head with `Content-Length` set to the rewritten body's size, every other
/// header kept verbatim. Order doesn't matter to the daemon; correctness of the length does.
fn rebuild_head(req: &Head<'_>, new_len: usize) -> Vec<u8> {
    let mut out = format!("{} {} HTTP/1.1\r\n", req.method, req.path);
    for (k, v) in &req.headers {
        if k.eq_ignore_ascii_case("content-length") {
            out.push_str(&format!("Content-Length: {new_len}\r\n"));
        } else {
            out.push_str(&format!("{k}: {v}\r\n"));
        }
    }
    out.push_str("\r\n");
    out.into_bytes()
}

/// Insert `key=val` into the create body's `Labels`, returning the re-serialized JSON — or
/// `None` if the body isn't the JSON object we can safely edit (in which case: forward as-is).
fn inject_label(body: &[u8], key: &str, val: &str) -> Option<Vec<u8>> {
    let mut v: serde_json::Value = serde_json::from_slice(body).ok()?;
    let obj = v.as_object_mut()?;
    let labels = obj.entry("Labels").or_insert_with(|| serde_json::json!({}));
    // Docker sends `"Labels": null` when there are none; treat that as an empty map.
    if labels.is_null() {
        *labels = serde_json::json!({});
    }
    labels.as_object_mut()?.insert(key.to_string(), serde_json::Value::String(val.to_string()));
    serde_json::to_vec(&v).ok()
}

/// Relay one response, returning `true` if it was exactly framed and fully consumed — so the
/// keep-alive connection can be reused for the next request — and `false` if it streams, in
/// which case the caller splices the rest and ends the connection.
///
/// `req_was_head` because a HEAD response carries headers but no body even when it announces a
/// `Content-Length`; reading that many bytes would eat into the *next* response.
fn relay_response(
    up: &mut UnixStream,
    client: &mut UnixStream,
    req_was_head: bool,
) -> Result<bool> {
    let Some(head) = read_head(up)? else {
        return Ok(false); // upstream hung up: nothing to loop for
    };
    let resp = parse_head(&head);
    client.write_all(&head)?;

    let status = resp.status_code();
    // Responses defined to carry no body: those to a HEAD, plus 1xx / 204 / 304.
    if req_was_head || status == 204 || status == 304 || (100..200).contains(&status) {
        return Ok(true);
    }
    match resp.content_length() {
        Some(len) => {
            copy_n(up, client, len)?;
            Ok(true)
        }
        // Chunked or close-delimited: a stream with no length to wait on — the caller splices.
        None => Ok(false),
    }
}

/// Copy exactly `n` bytes from `src` to `dst`.
fn copy_n(src: &mut UnixStream, dst: &mut UnixStream, n: usize) -> Result<()> {
    let mut left = n;
    let mut buf = [0u8; 16 * 1024];
    while left > 0 {
        let want = left.min(buf.len());
        let got = src.read(&mut buf[..want])?;
        if got == 0 {
            break; // upstream closed early; nothing more to relay
        }
        dst.write_all(&buf[..got])?;
        left -= got;
    }
    Ok(())
}

/// Splice two connections raw in both directions until the exchange ends. This is the whole
/// mechanism behind preserving hijacked (`-it`) and streaming (`logs -f`) connections: no
/// framing, no buffering, just bytes.
///
/// The two directions are *not* symmetric, and getting that wrong silently ate `docker run -i`
/// output:
///
/// - **client → upstream** is stdin. When it ends we half-close only upstream's *write*, so the
///   container sees stdin EOF but can still write its output back down the other direction. A
///   full shutdown here would kill that return path.
/// - **upstream → client** is the container's output. Its ending *is* the end of the exchange
///   (the container closed the stream / exited), so we tear both sockets down fully — which
///   also unblocks the stdin thread if it is still parked reading a client whose stdin never
///   closed (an interactive shell that just exited).
fn splice(client: UnixStream, up: UnixStream) {
    use std::net::Shutdown;
    let (mut c_rd, mut u_wr) = match (client.try_clone(), up.try_clone()) {
        (Ok(a), Ok(b)) => (a, b),
        _ => return, // can't clone the fds — better to drop the connection than half-proxy it
    };
    let mut u_rd = up;
    let mut c_wr = client;

    let t = thread::spawn(move || {
        let _ = io::copy(&mut c_rd, &mut u_wr);
        let _ = u_wr.shutdown(Shutdown::Write);
    });

    let _ = io::copy(&mut u_rd, &mut c_wr);
    let _ = c_wr.shutdown(Shutdown::Both);
    let _ = u_rd.shutdown(Shutdown::Both);
    let _ = t.join();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inject_into_empty_object() {
        let out = inject_label(b"{}", "limes.owner", "limes-w").unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["Labels"]["limes.owner"], "limes-w");
    }

    #[test]
    fn inject_merges_existing_labels() {
        let out = inject_label(
            br#"{"Image":"postgres:17","Labels":{"team":"db"}}"#,
            "limes.owner",
            "limes-w",
        )
        .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["Labels"]["team"], "db", "existing labels survive");
        assert_eq!(v["Labels"]["limes.owner"], "limes-w", "ours is added alongside");
        assert_eq!(v["Image"], "postgres:17", "the rest of the body is untouched");
    }

    /// Docker sends `"Labels": null` when a container has none; that must become a real map,
    /// not defeat the injection.
    #[test]
    fn inject_over_null_labels() {
        let out = inject_label(br#"{"Labels":null}"#, "limes.owner", "x").unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["Labels"]["limes.owner"], "x");
    }

    /// A non-object (or non-JSON) body is the signal to forward unrewritten, not to guess.
    #[test]
    fn inject_declines_non_object() {
        assert!(inject_label(b"[1,2,3]", "k", "v").is_none());
        assert!(inject_label(b"not json", "k", "v").is_none());
    }

    #[test]
    fn create_is_recognized_under_version_prefix_and_query() {
        let h = parse_head(b"POST /v1.45/containers/create?name=t HTTP/1.1\r\nHost: x\r\n\r\n");
        assert!(h.is_create());
    }

    #[test]
    fn non_create_paths_are_not_matched() {
        assert!(!parse_head(b"GET /containers/json HTTP/1.1\r\n\r\n").is_create());
        assert!(!parse_head(b"POST /containers/abc/start HTTP/1.1\r\n\r\n").is_create());
        // create is POST-only; the path alone isn't enough
        assert!(!parse_head(b"GET /containers/create HTTP/1.1\r\n\r\n").is_create());
    }

    #[test]
    fn header_lookup_is_case_insensitive() {
        let h =
            parse_head(b"POST /x HTTP/1.1\r\nContent-LENGTH: 42\r\nExpect: 100-continue\r\n\r\n");
        assert_eq!(h.content_length(), Some(42));
        assert!(h.expects_continue());
    }

    /// The rewritten head must carry the *new* length and drop the old, or the daemon reads the
    /// wrong number of body bytes.
    #[test]
    fn rebuild_head_replaces_content_length() {
        let h =
            parse_head(b"POST /containers/create HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\n");
        let out = rebuild_head(&h, 99);
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("Content-Length: 99"), "{s}");
        assert!(!s.contains("Content-Length: 2"), "old length gone: {s}");
        assert!(s.contains("Host: x"), "other headers preserved: {s}");
        assert!(s.ends_with("\r\n\r\n"), "terminated: {s:?}");
    }

    /// A read deadline on every test socket, so a wrong assumption about the protocol fails at
    /// the timeout instead of hanging the whole `cargo test` run.
    fn guard(s: &UnixStream) {
        s.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
    }

    /// End-to-end over a real socket pair: a create's body reaches upstream carrying our label
    /// with a corrected length, and upstream's 201 reaches the client.
    #[test]
    fn handle_labels_a_create_end_to_end() {
        let (client_a, client_b) = UnixStream::pair().unwrap();
        let (up_a, up_b) = UnixStream::pair().unwrap();
        for s in [&client_a, &client_b, &up_a, &up_b] {
            guard(s);
        }

        // The proxy under test drives client_b <-> up_a.
        let h = thread::spawn(move || {
            let _ = handle(client_b, up_a, "limes.owner", "limes-proj");
        });

        // Client: send a create with a small JSON body, then half-close so the proxy's
        // keep-alive loop sees end-of-requests and returns (without this it blocks reading the
        // next request and the read below never reaches EOF).
        let body = br#"{"Image":"postgres:17"}"#;
        let mut client = client_a;
        let req = format!(
            "POST /v1.45/containers/create HTTP/1.1\r\nHost: docker\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        client.write_all(req.as_bytes()).unwrap();
        client.write_all(body).unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();

        // Upstream: read the forwarded (rewritten) request, assert the label is in it.
        let mut up = up_b;
        let fwd_head = read_head(&mut up).unwrap().unwrap();
        let fwd = parse_head(&fwd_head);
        let len = fwd.content_length().unwrap();
        let mut fwd_body = vec![0u8; len];
        up.read_exact(&mut fwd_body).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&fwd_body).unwrap();
        assert_eq!(v["Labels"]["limes.owner"], "limes-proj");
        assert_eq!(v["Image"], "postgres:17");
        assert_eq!(len, fwd_body.len(), "forwarded length matches rewritten body");

        // Upstream: reply 201 with a length-framed body.
        let resp_body = br#"{"Id":"deadbeef","Warnings":[]}"#;
        let resp = format!("HTTP/1.1 201 Created\r\nContent-Length: {}\r\n\r\n", resp_body.len());
        up.write_all(resp.as_bytes()).unwrap();
        up.write_all(resp_body).unwrap();
        drop(up);

        // Client: the 201 comes back intact.
        let mut got = String::new();
        client.read_to_string(&mut got).unwrap();
        assert!(got.contains("201 Created"), "{got}");
        assert!(got.contains("deadbeef"), "{got}");

        h.join().unwrap();
    }

    /// The regression that motivated the keep-alive loop: the docker CLI sends `HEAD /_ping`
    /// and then the create on the *same* connection. The proxy has to survive the ping (a
    /// framed, bodyless response) and still label the create that follows — an earlier version
    /// spliced the connection away after the ping and never saw the create at all.
    #[test]
    fn create_after_ping_on_one_connection_is_labeled() {
        let (client_a, client_b) = UnixStream::pair().unwrap();
        let (up_a, up_b) = UnixStream::pair().unwrap();
        for s in [&client_a, &client_b, &up_a, &up_b] {
            guard(s);
        }

        let h = thread::spawn(move || {
            let _ = handle(client_b, up_a, "limes.owner", "limes-proj");
        });

        // Ping then create, pipelined on one connection, then half-close.
        let mut client = client_a;
        client.write_all(b"HEAD /_ping HTTP/1.1\r\nHost: docker\r\n\r\n").unwrap();
        let body = br#"{"Image":"busybox"}"#;
        client
            .write_all(
                format!(
                    "POST /v1.55/containers/create HTTP/1.1\r\nHost: docker\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            )
            .unwrap();
        client.write_all(body).unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();

        let mut up = up_b;
        // Upstream sees the ping first; a HEAD gets a bodyless 200 (Content-Length ignored).
        let ping = read_head(&mut up).unwrap().unwrap();
        assert!(ping.starts_with(b"HEAD /_ping"), "{:?}", String::from_utf8_lossy(&ping));
        up.write_all(b"HTTP/1.1 200 OK\r\nApi-Version: 1.55\r\nContent-Length: 0\r\n\r\n").unwrap();

        // Then the create — and it must carry the label despite sharing the ping's connection.
        let ch = read_head(&mut up).unwrap().unwrap();
        let cr = parse_head(&ch);
        assert!(cr.is_create(), "second request is the create: {:?}", String::from_utf8_lossy(&ch));
        let mut cb = vec![0u8; cr.content_length().unwrap()];
        up.read_exact(&mut cb).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&cb).unwrap();
        assert_eq!(v["Labels"]["limes.owner"], "limes-proj");

        let rb = br#"{"Id":"x"}"#;
        up.write_all(
            format!("HTTP/1.1 201 Created\r\nContent-Length: {}\r\n\r\n", rb.len()).as_bytes(),
        )
        .unwrap();
        up.write_all(rb).unwrap();
        drop(up);

        h.join().unwrap();
    }

    /// A hijacked stream must keep the return path open after the client half-closes stdin —
    /// the `printf … | docker run -i … cat` case, where the container echoes its input *after*
    /// seeing stdin EOF. An earlier splice shut the whole upstream down on stdin EOF and
    /// silently dropped that output.
    #[test]
    fn hijack_half_close_preserves_the_return_path() {
        let (client_a, client_b) = UnixStream::pair().unwrap();
        let (up_a, up_b) = UnixStream::pair().unwrap();
        for s in [&client_a, &client_b, &up_a, &up_b] {
            guard(s);
        }

        let h = thread::spawn(move || {
            let _ = handle(client_b, up_a, "limes.owner", "o");
        });

        // An attach (Upgrade header → splice path): send stdin, then half-close it.
        let mut client = client_a;
        client
            .write_all(
                b"POST /v1.55/containers/abc/attach?stdin=1&stdout=1&stream=1 HTTP/1.1\r\n\
                  Host: d\r\nUpgrade: tcp\r\nConnection: Upgrade\r\nContent-Length: 0\r\n\r\n",
            )
            .unwrap();
        client.write_all(b"hello-stdin").unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();

        let mut up = up_b;
        let head = read_head(&mut up).unwrap().unwrap();
        assert!(head.starts_with(b"POST /v1.55/containers/abc/attach"), "{head:?}");
        // The proxy forwards stdin and then, on the half-close, EOFs our read — not the socket.
        let mut got_stdin = Vec::new();
        up.read_to_end(&mut got_stdin).unwrap();
        assert_eq!(got_stdin, b"hello-stdin", "stdin forwarded through the splice");
        // Writing the container's output back must still reach the client.
        up.write_all(b"echoed-output").unwrap();
        drop(up);

        let mut out = Vec::new();
        client.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"echoed-output", "container output survived the stdin half-close");

        h.join().unwrap();
    }

    /// A non-create is forwarded byte-for-byte and its (framed) response relayed straight back.
    #[test]
    fn handle_passes_non_create_through_untouched() {
        let (client_a, client_b) = UnixStream::pair().unwrap();
        let (up_a, up_b) = UnixStream::pair().unwrap();
        for s in [&client_a, &client_b, &up_a, &up_b] {
            guard(s);
        }

        let h = thread::spawn(move || {
            let _ = handle(client_b, up_a, "limes.owner", "limes-proj");
        });

        let mut client = client_a;
        client.write_all(b"GET /v1.45/containers/json HTTP/1.1\r\nHost: docker\r\n\r\n").unwrap();
        // Half-close so the proxy's keep-alive loop reaches end-of-requests and returns.
        client.shutdown(std::net::Shutdown::Write).unwrap();

        let mut up = up_b;
        let head = read_head(&mut up).unwrap().unwrap();
        assert_eq!(
            head, b"GET /v1.45/containers/json HTTP/1.1\r\nHost: docker\r\n\r\n",
            "non-create head forwarded verbatim"
        );
        up.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n[]").unwrap();
        drop(up);

        let mut got = String::new();
        client.read_to_string(&mut got).unwrap();
        assert!(got.contains("200 OK") && got.ends_with("[]"), "{got}");

        h.join().unwrap();
    }
}
