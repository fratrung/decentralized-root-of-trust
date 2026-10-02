//! The measurement boundary shared by the relying-party targets.
//!
//! A receiver's cost is reported as three figures: `decode`, `verify`, and one
//! contiguous `decode + verify` interval (the sum of two medians is not the
//! median of the total). For those figures to be comparable across `raw_agg`,
//! `verifier` and `mldsa_raw_agg`, every target must start and stop its timers
//! at the same points and keep the same objects alive between them:
//!
//! - `total` starts immediately before decoding;
//! - `decode` ends when the decoder returns;
//! - `verify` starts right after and ends when the predicate returns;
//! - `total` ends there too, **before the decoded record is released**.
//!
//! The record is handed back alive, so releasing it is never inside a timed
//! interval and the caller samples RSS while it still exists. A verifier that
//! consumed the record instead (for example through `Result::is_ok_and`) would
//! run its destructor, one allocation per signature, before the verify and
//! total timers stop, and would read RSS after the memory has been freed.
//! `mldsa_raw_agg` lives in a separate crate and writes the same sequence out
//! inline.
//!
//! **Elapsed time and CPU time are both reported, and they are not the same
//! quantity.** `Instant` measures how long the caller waited. A prover that
//! spreads its work over sixteen cores waits less than it computes, a signer
//! blocked in `sync_data` waits more than it computes, and adding the
//! milliseconds of processes with different parallelism adds neither CPU,
//! energy nor money. `process_cpu_time` reads the kernel's account of the CPU
//! this process used, user plus system, over all of its threads. Each timed
//! phase is bracketed by both clocks, the CPU clock outside the elapsed one,
//! so reading it never enters an elapsed figure.

use std::time::{Duration, Instant};

/// CPU time this process has consumed since it started: user plus system,
/// summed over every thread, live or exited (`CLOCK_PROCESS_CPUTIME_ID`).
///
/// A difference of two readings is the CPU spent in between by the whole
/// process, whatever thread did the work. The clock has nanosecond units; the
/// kernel updates it at scheduler granularity, which on Linux is finer than a
/// microsecond for a running thread.
pub fn process_cpu_time() -> Duration {
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `now` is a valid, writable `timespec` for the duration of the
    // call, and `clock_gettime` writes nothing else.
    let status = unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut now) };
    // A failure here would be reported as zero CPU; refuse instead.
    assert_eq!(status, 0, "clock_gettime(CLOCK_PROCESS_CPUTIME_ID) failed");
    Duration::new(now.tv_sec as u64, now.tv_nsec as u32)
}

/// One timed decode-then-verify, with the decoded record still alive.
pub struct DecodeVerify<R, E> {
    /// What the decoder returned. Dropping it is the caller's, after it has
    /// read RSS; no destructor has run when this value is returned.
    pub decoded: Result<R, E>,
    /// Whether the predicate accepted the record; `false` if decoding failed.
    pub accepted: bool,
    pub decode: Duration,
    pub verify: Duration,
    /// Contiguous decode + verify, ending before the record is released.
    pub total: Duration,
    /// CPU the process spent over that same interval, all threads.
    pub cpu: Duration,
}

/// Time `decode`, then `verify` on a borrow of what it produced.
///
/// `verify` is not called when decoding fails; `verify` and `total` then cover
/// only the failed decode.
pub fn decode_then_verify<R, E>(
    decode: impl FnOnce() -> Result<R, E>,
    verify: impl FnOnce(&R) -> bool,
) -> DecodeVerify<R, E> {
    let cpu_start = process_cpu_time();
    let total_start = Instant::now();
    let decoded = decode();
    let decode_time = total_start.elapsed();
    let verify_start = Instant::now();
    let accepted = match &decoded {
        Ok(record) => verify(record),
        Err(_) => false,
    };
    let verify_time = verify_start.elapsed();
    let total = total_start.elapsed();
    let cpu = process_cpu_time().saturating_sub(cpu_start);
    DecodeVerify {
        decoded,
        accepted,
        decode: decode_time,
        verify: verify_time,
        total,
        cpu,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::rc::Rc;

    /// Counts its own destruction, standing in for a decoded record.
    struct Record(Rc<Cell<u32>>);
    impl Drop for Record {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    #[test]
    fn the_record_outlives_every_timer() {
        let drops = Rc::new(Cell::new(0));
        let seen_alive = Cell::new(false);
        let measured = decode_then_verify(
            || Ok::<_, ()>(Record(Rc::clone(&drops))),
            |record| {
                seen_alive.set(record.0.get() == 0);
                true
            },
        );
        assert!(measured.accepted);
        assert!(seen_alive.get(), "the predicate saw a released record");
        // The timers have stopped and nothing has been released: a destructor
        // inside the timed interval would already have counted here.
        assert_eq!(drops.get(), 0, "the record was released before returning");
        assert!(measured.total >= measured.decode + measured.verify);
        drop(measured);
        assert_eq!(
            drops.get(),
            1,
            "the caller releases the record exactly once"
        );
    }

    #[test]
    fn a_failed_decode_is_rejected_without_calling_the_predicate() {
        let called = Cell::new(false);
        let measured = decode_then_verify(
            || Err::<Record, _>("malformed"),
            |_| {
                called.set(true);
                true
            },
        );
        assert!(!measured.accepted);
        assert!(!called.get());
        assert_eq!(measured.decoded.err(), Some("malformed"));
    }
}
