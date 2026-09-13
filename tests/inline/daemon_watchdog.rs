//! Anti-wedge watchdog decision (`watchdog_check`).
//!
//! Pure tests of the abort decision: `on_stall` is injected as a flag so the
//! stall path is asserted without a real `std::process::abort()`. The production
//! wiring (heartbeat store each tick + a thread that calls `abort`) is a thin
//! loop around these predicates.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::{watchdog_check, watchdog_step, watchdog_unaccounted};

/// A tick that last completed longer ago than the deadline trips `on_stall`.
#[test]
fn watchdog_aborts_when_tick_stalls_past_deadline() {
    let mut stalled = false;
    // last tick at t=1000ms; now t=1000+61_000ms; deadline 60_000ms → 61s > 60s.
    watchdog_check(1_000, 1_000 + 61_000, 60_000, || stalled = true);
    assert!(
        stalled,
        "a tick stalled past the deadline must trip the abort path"
    );
}

/// A tick within the deadline does not trip.
#[test]
fn watchdog_does_not_abort_on_a_fresh_tick() {
    let mut stalled = false;
    watchdog_check(1_000, 1_000 + 30_000, 60_000, || stalled = true);
    assert!(!stalled, "a tick within the deadline must not abort");
}

/// Exactly at the deadline is not yet stalled (strict `>`), so it holds one more
/// poll — the boundary must not abort a daemon that just barely ticked.
#[test]
fn watchdog_boundary_is_not_stalled() {
    let mut stalled = false;
    watchdog_check(1_000, 1_000 + 60_000, 60_000, || stalled = true);
    assert!(!stalled, "exactly at the deadline is not past it");
}

/// A zero heartbeat means no tick has completed yet (boot in progress); the
/// watchdog must never abort during that window.
#[test]
fn watchdog_ignores_zero_heartbeat_during_boot() {
    let mut stalled = false;
    watchdog_check(0, 999_999_999, 60_000, || stalled = true);
    assert!(!stalled, "a zero heartbeat (no tick yet) must not abort");
}

/// A poll that took its nominal window charges no unaccounted time.
#[test]
fn watchdog_unaccounted_is_zero_for_a_normal_poll() {
    assert_eq!(watchdog_unaccounted(10_000, 10_000), 0);
    // Scheduling jitter: only the jitter is unaccounted, the window is charged.
    assert_eq!(watchdog_unaccounted(10_050, 10_000), 50);
}

/// A poll that overshot its window by more than the slack was interrupted by a
/// suspend or a clock jump: the loop froze with the clock, so the WHOLE poll
/// charges no running time.
#[test]
fn watchdog_unaccounted_absorbs_an_overshot_poll_whole() {
    // 10s window + 1h freeze.
    assert_eq!(watchdog_unaccounted(3_610_000, 10_000), 3_610_000);
}

/// The slack boundary: exactly poll + slack charges only the slack, one ms past
/// absorbs the whole poll.
#[test]
fn watchdog_unaccounted_boundary_is_at_the_slack() {
    assert_eq!(watchdog_unaccounted(11_000, 10_000), 1_000);
    assert_eq!(watchdog_unaccounted(11_001, 10_000), 11_001);
}

/// A poll shorter than its window charges nothing (a clock step backwards).
#[test]
fn watchdog_unaccounted_saturates_a_short_poll() {
    assert_eq!(watchdog_unaccounted(5_000, 10_000), 0);
}

/// A freeze landing mid-tick does not trip: the absorbed poll leaves the gap at
/// what the previous wake measured, and the tick's own budget (deadline - TICK)
/// still has time to complete after the resume.
#[test]
fn watchdog_step_does_not_trip_a_freeze_mid_slow_tick() {
    // heartbeat 1_000; poll began at 21s (gap 20s, no trip); 5s ran, then a
    // 10s freeze; wake at 36s sees elapsed 15s > 11s slack -> whole poll
    // absorbed, the gap stays at what the previous wake measured.
    let mut stalled = false;
    let uncharged = watchdog_step(1_000, 21_000, 36_000, 0, 10_000, 30_000, || stalled = true);
    assert!(!stalled, "a freeze mid-tick must not read as a wedge");
    assert_eq!(uncharged, 15_000);
    // The tick completes within its own budget right after the resume (a
    // 29s running budget, 20s of it already spent) and re-stamps; the next
    // normal poll reads the fresh heartbeat, not the absorbed gap.
    let mut stalled = false;
    let _ = watchdog_step(44_000, 36_000, 46_000, uncharged, 10_000, 30_000, || {
        stalled = true
    });
    assert!(
        !stalled,
        "a slow tick that completes after the resume must not trip"
    );
}

/// A loop wedged BEFORE the freeze still aborts: the first post-resume poll
/// absorbs the freeze and sits on the deadline boundary, the next normal poll
/// trips.
#[test]
fn watchdog_step_aborts_a_pre_freeze_wedge_after_resume() {
    // heartbeat 1_000; a poll began at 31s (the 30s boundary the previous
    // wake measured), 5s ran, then a 10s freeze; wake at 46s absorbs the
    // whole poll and reads gap 30s — the boundary, not past it.
    let mut stalled = false;
    let uncharged = watchdog_step(1_000, 31_000, 46_000, 0, 10_000, 30_000, || stalled = true);
    assert!(!stalled);
    assert_eq!(uncharged, 15_000);
    // The next poll takes its normal 10s: gap 40s of running time trips.
    let mut stalled = false;
    let uncharged = watchdog_step(1_000, 46_000, 56_000, uncharged, 10_000, 30_000, || {
        stalled = true
    });
    assert!(
        stalled,
        "a pre-freeze wedge must abort one poll after resume"
    );
    assert_eq!(uncharged, 15_000);
}

/// A long freeze with a healthy loop: the freeze poll absorbs, the loop
/// re-stamps right after the resume, and the next normal poll reads the fresh
/// heartbeat.
#[test]
fn watchdog_step_survives_a_long_freeze() {
    // heartbeat 1_000; poll began at 11s (gap 10s), a 1h freeze, wake at
    // 1h+11s: the whole poll absorbs and the gap stays 10s.
    let mut stalled = false;
    let uncharged = watchdog_step(1_000, 11_000, 3_611_000, 0, 10_000, 30_000, || {
        stalled = true
    });
    assert!(!stalled, "a freeze must not read as a wedge");
    assert_eq!(uncharged, 3_600_000);
    // The loop re-stamped right after the resume (its tick completed in
    // running time); the next poll 10s later reads a ~10s-old heartbeat.
    let mut stalled = false;
    let _ = watchdog_step(
        3_611_000,
        3_611_000,
        3_621_000,
        uncharged,
        10_000,
        30_000,
        || stalled = true,
    );
    assert!(
        !stalled,
        "a re-stamped heartbeat after a freeze must not trip"
    );
}

/// A normal poll still trips a stall past the deadline: the running-time frame
/// leaves ordinary stall detection untouched.
#[test]
fn watchdog_step_still_aborts_a_stall_on_a_normal_poll() {
    let mut stalled = false;
    let uncharged = watchdog_step(1_000, 20_000, 30_000, 0, 10_000, 30_000, || stalled = true);
    assert!(!stalled, "gap 29s is within the deadline");
    assert_eq!(uncharged, 0);
    let mut stalled = false;
    let _ = watchdog_step(1_000, 30_000, 40_000, uncharged, 10_000, 30_000, || {
        stalled = true
    });
    assert!(stalled, "gap 39s must trip");
}
