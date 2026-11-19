//! Recorder versions, in one place. A change that makes earlier observations or
//! proofs unsound bumps the block below, and nothing else.

// BEGIN recorder versions
/// Increment when a change to the tracer invalidates existing observations.
pub const TRACER_VERSION: u32 = 7;
/// Proof file format. Older files stay cold: they load, list and import, but no planner reads them.
// Integration tests include this file by path and do not read every constant.
#[allow(dead_code)]
pub const PROOF_VERSION: u32 = 4;
/// Recorder semantics older than this floor may produce unsound plan proofs.
/// Raise it together with `TRACER_VERSION` when recorder changes make earlier proofs unsound.
#[allow(dead_code)]
pub const MIN_PLANNABLE_RECORDER_VERSION: u32 = 7;
// END recorder versions
