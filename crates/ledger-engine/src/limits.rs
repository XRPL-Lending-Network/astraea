//! Time limit for one request.
//!
//! Handlers run on blocking threads, and a blocking thread cannot be stopped
//! from outside: a request that runs away would hold its slot (one of
//! `MAX_INFLIGHT`) for as long as it likes. So a request stops itself. The
//! server sets a deadline for the thread before calling the handler, and the
//! loops whose length the client controls (owner directory pages, cold index
//! partitions, the transactions of a page or a ledger) call `check`. Past the
//! deadline the request ends with `tooBusy` and its slot goes to the next one.
//! Threads that read for a request (`cold::Cold::ledgers`) take its deadline
//! with them (`current`, `start_at`).

use std::cell::Cell;
use std::time::{Duration, Instant};

use crate::api::{RpcError, rpc_err};

thread_local! {
    static DEADLINE: Cell<Option<Instant>> = const { Cell::new(None) };
}

/// The error text that carries an exceeded limit through modules whose errors
/// are strings; `api::internal` turns it back into `tooBusy`.
pub const EXCEEDED: &str = "request time limit exceeded";

/// The deadline of the current thread's request; cleared when dropped, so a
/// pooled thread does not carry it into the next task.
#[derive(Debug)]
pub struct Deadline(());

impl Drop for Deadline {
    fn drop(&mut self) {
        DEADLINE.with(|d| d.set(None));
    }
}

/// Starts the limit for the request about to run on this thread.
pub fn start(limit: Duration) -> Deadline {
    DEADLINE.with(|d| d.set(Some(Instant::now() + limit)));
    Deadline(())
}

/// The deadline of the current thread's request, to hand to threads that
/// read for it.
pub fn current() -> Option<Instant> {
    DEADLINE.with(Cell::get)
}

/// Runs this thread under a deadline taken from another (`current`); `None`
/// sets none.
pub fn start_at(at: Option<Instant>) -> Deadline {
    DEADLINE.with(|d| d.set(at));
    Deadline(())
}

/// `Err(EXCEEDED)` once the current request is past its deadline. Without a
/// deadline (loading, tools, tests) there is no limit.
pub fn check() -> Result<(), String> {
    match DEADLINE.with(Cell::get) {
        Some(at) if Instant::now() >= at => Err(EXCEEDED.into()),
        _ => Ok(()),
    }
}

/// `check` for handlers.
pub(crate) fn check_rpc() -> Result<(), RpcError> {
    check().map_err(|_| exceeded())
}

pub(crate) fn exceeded() -> RpcError {
    rpc_err(
        "tooBusy",
        9,
        "The request took too long. Ask for less: a smaller limit or a narrower ledger range.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_deadline_stops_only_its_own_request() {
        assert!(check().is_ok());
        {
            let _d = start(Duration::ZERO);
            assert_eq!(check(), Err(EXCEEDED.to_string()));
            assert_eq!(check_rpc().unwrap_err().error, "tooBusy");
            assert_eq!(crate::api::internal(EXCEEDED.into()).error, "tooBusy");
        }
        assert!(check().is_ok());
        let _d = start(Duration::from_secs(60));
        assert!(check().is_ok());
    }

    #[test]
    fn a_deadline_carries_to_another_thread() {
        let _d = start(Duration::ZERO);
        let at = current();
        assert!(at.is_some());
        std::thread::spawn(move || {
            assert!(check().is_ok());
            {
                let _d = start_at(at);
                assert_eq!(check(), Err(EXCEEDED.to_string()));
            }
            assert!(check().is_ok());
        })
        .join()
        .unwrap();
    }
}
