//! Deliberately failing test for the debug-rerun proof.
//! Proves the debug-rerun workflow fires exactly once with debug logging
//! when a CI run fails. Deleted after the proof; never merged.

#[test]
fn debug_rerun_proof_fails_deliberately() {
    panic!("deliberate failure for the debug-rerun proof");
}
