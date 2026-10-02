//! `bench::timing::process_cpu_time` counts work, not waiting, and counts it on
//! every thread.
//!
//! This is its own test binary with a single `#[test]` on purpose: the clock
//! is the CPU of the whole process, so in the library's unit-test binary the
//! other tests running in parallel would be counted too, and "sleeping costs
//! almost no CPU" could not be asserted.

use std::time::{Duration, Instant};

use decentralized_root_of_trust::bench::timing::process_cpu_time;

fn burn(duration: Duration) {
    let start = Instant::now();
    let mut x = 0u64;
    while start.elapsed() < duration {
        x = std::hint::black_box(x.wrapping_mul(6364136223846793005).wrapping_add(1));
    }
}

#[test]
fn the_cpu_clock_counts_work_on_every_thread_and_not_waiting() {
    let window = Duration::from_millis(80);

    // Waiting: elapsed time passes, CPU time hardly moves.
    let before = process_cpu_time();
    std::thread::sleep(window);
    let slept = process_cpu_time() - before;
    assert!(
        slept < window / 4,
        "sleeping {window:?} cost {slept:?} of CPU"
    );

    // Working on this thread: CPU time advances with elapsed time.
    let before = process_cpu_time();
    burn(window);
    let busy = process_cpu_time() - before;
    assert!(busy > window / 2, "a busy {window:?} cost only {busy:?}");

    // Working on another thread while this one only waits for it: a per-thread
    // clock would see nothing.
    let before = process_cpu_time();
    std::thread::spawn(move || burn(window))
        .join()
        .expect("worker panicked");
    let elsewhere = process_cpu_time() - before;
    assert!(
        elsewhere > window / 2,
        "a busy worker thread for {window:?} cost only {elsewhere:?}"
    );
}
