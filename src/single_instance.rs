//! Single-instance enforcement via an abstract-namespace Unix socket. The primary instance
//! binds the socket; a second launch connects to it to ask the primary to raise its window.

use std::io::Write as _;
use std::os::unix::net::{SocketAddr, UnixListener, UnixStream};

use tokio::sync::mpsc::UnboundedSender;

use crate::error::{AppError, AppResult};

/// Abstract socket name. Leading NUL → Linux abstract namespace (no filesystem entry).
pub const SOCKET_NAME: &[u8] = b"\0wireguard-gui-rust-v1";

/// Holds the bound listener's lifetime for the primary instance.
///
/// Dropping this value closes the underlying listener, which releases the abstract-namespace
/// socket so a new primary can bind it.
pub struct InstanceGuard(UnixListener);

/// Outcome of attempting to become the primary instance.
pub enum InstanceResult {
    /// We are the primary; hold onto the guard and listen on the returned socket.
    Primary(InstanceGuard, UnixListener),
    /// Another instance is already primary; we signalled it and should exit.
    Secondary,
}

/// Build a `SocketAddr` for the abstract-namespace socket name.
///
/// Uses `std::os::linux::net::SocketAddrExt::from_abstract_name` on the slice starting
/// at index 1 (we pass the NUL-prefixed constant, strip the leading NUL for the kernel API
/// which adds it internally).
fn abstract_addr() -> std::io::Result<SocketAddr> {
    addr_for(SOCKET_NAME)
}

/// Build a `SocketAddr` for an arbitrary NUL-prefixed abstract socket name.
///
/// The leading NUL is stripped because `from_abstract_name` adds it internally. Factored out
/// so tests can use unique names (the kernel abstract namespace is a single global table, so
/// every test sharing one name would otherwise collide on `AddrInUse`).
fn addr_for(name: &[u8]) -> std::io::Result<SocketAddr> {
    use std::os::linux::net::SocketAddrExt as _;
    // `name` starts with a NUL byte; from_abstract_name must NOT include the NUL.
    SocketAddr::from_abstract_name(&name[1..])
}

/// Try to bind the abstract socket and become the primary instance.
///
/// - If the bind succeeds we are the primary: return `Primary(guard, listener)` where
///   `guard` keeps the socket alive as long as it is held, and `listener` is a clone for
///   use with [`accept_raises`].
/// - If the bind fails with `AddrInUse` another instance already owns the socket, so we
///   call [`send_raise`] to signal it and return `Secondary`.
/// - Any other I/O error is wrapped in `AppError::IpcFailed`.
pub fn try_become_primary() -> AppResult<InstanceResult> {
    try_become_primary_with(SOCKET_NAME)
}

/// Implementation of [`try_become_primary`] parameterized by the abstract socket name, so tests
/// can each use a distinct name and avoid colliding on the single global abstract namespace.
fn try_become_primary_with(name: &[u8]) -> AppResult<InstanceResult> {
    let addr = addr_for(name).map_err(|e| AppError::IpcFailed(e.to_string()))?;

    match UnixListener::bind_addr(&addr) {
        Ok(listener) => {
            // Clone so caller gets one listener for accept_raises, guard holds the other.
            let guard_listener = listener
                .try_clone()
                .map_err(|e| AppError::IpcFailed(e.to_string()))?;
            Ok(InstanceResult::Primary(InstanceGuard(guard_listener), listener))
        }
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            // Another instance is running — signal it then report Secondary.
            send_raise_to(name)?;
            Ok(InstanceResult::Secondary)
        }
        Err(e) => Err(AppError::IpcFailed(e.to_string())),
    }
}

/// Connect to the primary instance and send a single "raise" byte (`b"R"`).
pub fn send_raise() -> AppResult<()> {
    send_raise_to(SOCKET_NAME)
}

/// Implementation of [`send_raise`] parameterized by the abstract socket name.
fn send_raise_to(name: &[u8]) -> AppResult<()> {
    let addr = addr_for(name).map_err(|e| AppError::IpcFailed(e.to_string()))?;
    let mut stream =
        UnixStream::connect_addr(&addr).map_err(|e| AppError::IpcFailed(e.to_string()))?;
    stream
        .write_all(b"R")
        .map_err(|e| AppError::IpcFailed(e.to_string()))?;
    Ok(())
}

/// Accept incoming "raise" connections, forwarding a `()` on `tx` for each.
///
/// The function runs until the channel receiver is dropped or the listener errors fatally.
/// Each accepted connection (regardless of its payload) causes one `()` to be sent on `tx`.
///
/// This is driven by `tokio::task::spawn_blocking` so the synchronous `UnixListener::accept`
/// doesn't monopolize an async executor thread. The listener is put into non-blocking mode and
/// the loop polls with a short sleep so it can also notice the receiver being dropped — a plain
/// blocking `accept()` would otherwise wedge forever (and block runtime shutdown) waiting for a
/// connection that never comes after the app has quit.
pub async fn accept_raises(listener: UnixListener, tx: UnboundedSender<()>) {
    tokio::task::spawn_blocking(move || {
        // Non-blocking so the loop can periodically check whether the receiver is still alive.
        if listener.set_nonblocking(true).is_err() {
            return;
        }
        loop {
            // Bail out promptly once the consumer (the app) has gone away.
            if tx.is_closed() {
                break;
            }
            match listener.accept() {
                Ok(_) => {
                    // A new instance connected — tell the primary to raise its window.
                    if tx.send(()).is_err() {
                        // Receiver dropped; primary is shutting down.
                        break;
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // No pending connection yet — nap briefly, then re-check `tx`.
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(_) => {
                    // Listener closed or fatal error; exit the loop.
                    break;
                }
            }
        }
    })
    .await
    .ok();
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    /// Build a process-unique NUL-prefixed abstract socket name for a test.
    ///
    /// The Linux abstract namespace is one global table shared by every test in the binary, so
    /// each test must use a distinct name — otherwise tests collide on `AddrInUse` whether run
    /// in parallel OR serially (a socket only frees when its last fd is dropped, which is not
    /// guaranteed to have happened before the next test in the same process binds).
    fn unique_name(tag: &str) -> Vec<u8> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut v = vec![0u8]; // leading NUL → abstract namespace
        v.extend_from_slice(
            format!("wireguard-gui-rust-test-{tag}-{}-{n}", std::process::id()).as_bytes(),
        );
        v
    }

    /// Helper: bind a specific abstract socket name directly and return the listener.
    fn raw_bind(name: &[u8]) -> std::io::Result<UnixListener> {
        let addr = addr_for(name)?;
        UnixListener::bind_addr(&addr)
    }

    // -----------------------------------------------------------------------
    // Abstract-address construction
    // -----------------------------------------------------------------------

    #[test]
    fn socket_name_starts_with_nul() {
        assert_eq!(SOCKET_NAME[0], 0, "SOCKET_NAME must start with a NUL byte");
    }

    #[test]
    fn abstract_addr_roundtrips() {
        let addr = abstract_addr().expect("abstract_addr() should not fail");
        // The abstract name we built should equal the non-NUL slice of SOCKET_NAME.
        use std::os::linux::net::SocketAddrExt as _;
        let name = addr
            .as_abstract_name()
            .expect("must be an abstract address");
        assert_eq!(name, &SOCKET_NAME[1..]);
    }

    // -----------------------------------------------------------------------
    // try_become_primary: first bind succeeds, second returns Secondary
    // -----------------------------------------------------------------------

    /// First call becomes Primary. A second call while the guard is alive must return Secondary.
    /// Dropping the guard frees the socket so a third call can become Primary again.
    #[test]
    fn first_bind_primary_second_secondary_drop_primary_again() {
        let name = unique_name("lifecycle");

        // First: should be Primary.
        let result1 = try_become_primary_with(&name)
            .expect("first try_become_primary should not return an error");

        let (guard, listener) = match result1 {
            InstanceResult::Primary(g, l) => (g, l),
            InstanceResult::Secondary => panic!("first call should be Primary, not Secondary"),
        };

        // Second: socket is still bound — should be Secondary.
        let result2 = try_become_primary_with(&name)
            .expect("second try_become_primary should not return an error");
        assert!(
            matches!(result2, InstanceResult::Secondary),
            "second call must be Secondary while guard is alive"
        );

        // Clean up: drop everything that holds the socket open.
        drop(listener);
        drop(guard);

        // Third: socket released — should be Primary again.
        let result3 = try_become_primary_with(&name)
            .expect("third try_become_primary should not return an error");

        let (guard3, listener3) = match result3 {
            InstanceResult::Primary(g, l) => (g, l),
            InstanceResult::Secondary => {
                panic!("third call should be Primary after guard was dropped")
            }
        };

        // Clean up.
        drop(listener3);
        drop(guard3);
    }

    // -----------------------------------------------------------------------
    // send_raise: sends b"R" when primary is listening
    // -----------------------------------------------------------------------

    #[test]
    fn send_raise_writes_r_to_listener() {
        use std::io::Read as _;

        let name = unique_name("sendraise");

        // Become primary manually.
        let listener = raw_bind(&name).expect("raw_bind should succeed");

        // Send the raise byte from a thread (listener.accept is blocking).
        let send_name = name.clone();
        let join = std::thread::spawn(move || {
            // Small sleep so the main thread reaches accept first.
            std::thread::sleep(std::time::Duration::from_millis(10));
            send_raise_to(&send_name).expect("send_raise should succeed");
        });

        let (mut stream, _addr) = listener.accept().expect("accept should succeed");
        join.join().expect("thread should finish cleanly");

        let mut buf = [0u8; 1];
        stream.read_exact(&mut buf).expect("read_exact should succeed");
        assert_eq!(buf[0], b'R', "send_raise must write exactly 0x52 ('R')");

        drop(listener);
    }

    // -----------------------------------------------------------------------
    // send_raise: fails gracefully when no primary is listening
    // -----------------------------------------------------------------------

    #[test]
    fn send_raise_fails_when_no_listener() {
        // A name nobody ever binds → connecting must fail. Using a unique name guarantees no
        // other test holds this socket.
        let name = unique_name("nolistener");

        let result = send_raise_to(&name);
        assert!(
            result.is_err(),
            "send_raise should return Err when nobody is listening"
        );
        match result {
            Err(AppError::IpcFailed(_)) => {} // expected
            other => panic!("unexpected result: {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // accept_raises: each accepted connection produces a () on the channel
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn accept_raises_forwards_unit_per_connection() {
        use std::time::Duration;
        use tokio::time::timeout;

        let name = unique_name("acceptraises");
        let listener = raw_bind(&name).expect("raw_bind should succeed");
        // Set a non-blocking accept timeout via a clone so the background task can be
        // interrupted by dropping the sender.
        let (tx, mut rx) = mpsc::unbounded_channel::<()>();

        // Spawn accept_raises into the tokio runtime.
        tokio::spawn(accept_raises(listener, tx));

        // Connect once → expect one () on the channel. The channel item is `()`, so the
        // `.expect()` chain (no timeout + channel still open) IS the assertion.
        let addr = addr_for(&name).expect("addr_for");
        let _s1 = UnixStream::connect_addr(&addr).expect("connect 1");
        timeout(Duration::from_millis(200), rx.recv())
            .await
            .expect("timed out waiting for first raise")
            .expect("channel closed before first raise");

        // Connect again → expect another ().
        let _s2 = UnixStream::connect_addr(&addr).expect("connect 2");
        timeout(Duration::from_millis(200), rx.recv())
            .await
            .expect("timed out waiting for second raise")
            .expect("channel closed before second raise");
    }

    // -----------------------------------------------------------------------
    // InstanceGuard drop releases the socket
    // -----------------------------------------------------------------------

    #[test]
    fn guard_drop_releases_socket() {
        let name = unique_name("guarddrop");
        let r = try_become_primary_with(&name).expect("should succeed");
        let (guard, listener) = match r {
            InstanceResult::Primary(g, l) => (g, l),
            InstanceResult::Secondary => panic!("expected Primary"),
        };

        drop(listener);
        drop(guard);

        // If the socket was released, raw_bind must succeed now.
        let r2 = raw_bind(&name);
        assert!(r2.is_ok(), "raw_bind should succeed after guard is dropped");
        drop(r2.unwrap());
    }
}
