//! Dry-run mode: the global "say what you would do, do nothing" switch.
//!
//! Every mutating operation in the codebase goes through the single guard
//! here (`DryRun::allow`) before any write, API call, or external action.
//! No component mutates state without consulting it.
//!
//! - In dry-run, the operation is skipped and the would-do plan is printed
//!   (to stderr, so stdout stays machine-readable) and recorded, so tests
//!   can assert on it.
//! - In live mode, the operation proceeds.
//!
//! The effective mode is resolved once at startup, in this precedence:
//! CLI flag (`--dry-run` / `--live`) > env var (`FRESHCRAB_DRY_RUN`) >
//! config file (`dry_run`). It is logged loudly at startup so it is
//! always obvious which mode is running.
//!
//! Reads are NOT gated: the watcher still polls the collectors in dry-run
//! (it has to, to say what it WOULD queue), and the queue still evaluates
//! the dedup rules (it has to, to print the decision). Only writes and
//! external actions are gated.

use std::cell::RefCell;

/// The global dry-run mode.
#[derive(Debug)]
pub struct DryRun {
    enabled: bool,
    plan: RefCell<Vec<String>>,
}

impl DryRun {
    /// A dry-run mode with the given setting. `true` = dry-run (do
    /// nothing, print the plan); `false` = live.
    pub fn new(enabled: bool) -> Self {
        DryRun {
            enabled,
            plan: RefCell::new(Vec::new()),
        }
    }

    /// True when dry-run is on (nothing is written or filed).
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// True when live (dry-run off).
    pub fn live(&self) -> bool {
        !self.enabled
    }

    /// The would-do plan recorded so far (in order). Tests assert on this;
    /// production prints each entry to stderr as it is recorded.
    pub fn plan(&self) -> Vec<String> {
        self.plan.borrow().clone()
    }

    /// Merge another dry-run's recorded plan into this one, verbatim.
    /// The lines are already formatted (`[dry-run] ...`) and already
    /// printed by their owner (geectl's `DryRun` prints as it
    /// records), so this records them without printing or
    /// re-prefixing: it only makes `plan()` consumers see the full
    /// plan. In live mode the other plan is empty, so merging is a
    /// no-op — and a live `DryRun` records nothing even if lines are
    /// passed in, keeping the "live plan is empty" invariant.
    pub fn merge_plan(&self, lines: &[String]) {
        if self.enabled {
            self.plan.borrow_mut().extend(lines.iter().cloned());
        }
    }

    /// The guard. Call before any mutating operation. Returns true when
    /// the operation may proceed (live mode). In dry-run, records and
    /// prints the would-do action and returns false.
    pub fn allow(&self, action: &str) -> bool {
        if self.enabled {
            self.note(&format!("would: {action}"));
            false
        } else {
            true
        }
    }

    /// Record (and print) a would-do decision, e.g. a would-skip with its
    /// reason. Does not gate anything; use `allow` for that.
    pub fn note(&self, message: &str) {
        if self.enabled {
            let line = format!("[dry-run] {message}");
            eprintln!("{line}");
            self.plan.borrow_mut().push(line);
        }
    }

    /// Log the effective mode loudly at startup (stderr, so stdout stays
    /// machine-readable JSON).
    pub fn log_mode(&self) {
        if self.enabled {
            eprintln!("=== freshcrab DRY-RUN mode: no changes will be made ===");
        } else {
            eprintln!("=== freshcrab LIVE mode: changes WILL be made ===");
        }
    }
}

/// Parse an env-var boolean. Accepts true/false/1/0/yes/no
/// (case-insensitive). None for anything else.
pub fn parse_env_bool(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Some(true),
        "false" | "0" | "no" => Some(false),
        _ => None,
    }
}

/// Resolve the effective dry-run mode. Precedence: CLI flag > env var >
/// config file. `cli` is Some(true) for `--dry-run`, Some(false) for
/// `--live`, None when neither flag is given. `env` is the
/// `FRESHCRAB_DRY_RUN` value, if set.
pub fn resolve(cli: Option<bool>, env: Option<String>, config: bool) -> Result<DryRun, String> {
    if let Some(flag) = cli {
        return Ok(DryRun::new(flag));
    }
    if let Some(value) = env {
        // An empty env var is unset: fall back to the config value
        // instead of hard-failing on an empty string.
        if !value.trim().is_empty() {
            match parse_env_bool(&value) {
                Some(parsed) => return Ok(DryRun::new(parsed)),
                None => {
                    return Err(format!(
                        "invalid FRESHCRAB_DRY_RUN value: {value:?} (expected true/false/1/0/yes/no)"
                    ));
                }
            }
        }
    }
    Ok(DryRun::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_live_proceeds() {
        let dry = DryRun::new(false);
        assert!(dry.allow("write the queue file"));
        assert!(dry.plan().is_empty());
    }

    #[test]
    fn allow_dry_run_blocks_and_records() {
        let dry = DryRun::new(true);
        assert!(!dry.allow("write the queue file"));
        assert_eq!(dry.plan(), vec!["[dry-run] would: write the queue file"]);
    }

    #[test]
    fn merge_plan_records_verbatim() {
        let dry = DryRun::new(true);
        dry.note("would do the local step");
        dry.merge_plan(&["[dry-run] would: file submit request for foo".to_string()]);
        assert_eq!(
            dry.plan(),
            vec![
                "[dry-run] would do the local step",
                "[dry-run] would: file submit request for foo",
            ]
        );

        // Live mode records nothing, even merged lines.
        let live = DryRun::new(false);
        live.merge_plan(&["[dry-run] would: file submit request for foo".to_string()]);
        assert!(live.plan().is_empty());
    }

    #[test]
    fn note_only_records_in_dry_run() {
        let dry = DryRun::new(true);
        dry.note("would-skip foo: task already in flight");
        assert_eq!(
            dry.plan(),
            vec!["[dry-run] would-skip foo: task already in flight"]
        );

        let live = DryRun::new(false);
        live.note("would-skip foo: task already in flight");
        assert!(live.plan().is_empty());
    }

    #[test]
    fn resolve_precedence_cli_over_env_over_config() {
        // CLI wins over env and config.
        assert!(resolve(Some(true), Some("false".to_string()), false)
            .unwrap()
            .enabled());
        assert!(!resolve(Some(false), Some("true".to_string()), true)
            .unwrap()
            .enabled());
        // Env wins over config.
        assert!(resolve(None, Some("true".to_string()), false)
            .unwrap()
            .enabled());
        assert!(!resolve(None, Some("false".to_string()), true)
            .unwrap()
            .enabled());
        // Config is the fallback.
        assert!(resolve(None, None, true).unwrap().enabled());
        assert!(!resolve(None, None, false).unwrap().enabled());
    }

    #[test]
    fn resolve_invalid_env_is_error() {
        assert!(resolve(None, Some("maybe".to_string()), true).is_err());
    }

    #[test]
    fn resolve_empty_env_falls_back_to_config() {
        // An empty env var is unset, not an error.
        assert!(resolve(None, Some("".to_string()), true).unwrap().enabled());
        assert!(!resolve(None, Some("   ".to_string()), false)
            .unwrap()
            .enabled());
    }

    #[test]
    fn parse_env_bool_values() {
        assert_eq!(parse_env_bool("true"), Some(true));
        assert_eq!(parse_env_bool("TRUE"), Some(true));
        assert_eq!(parse_env_bool("1"), Some(true));
        assert_eq!(parse_env_bool("yes"), Some(true));
        assert_eq!(parse_env_bool("false"), Some(false));
        assert_eq!(parse_env_bool("0"), Some(false));
        assert_eq!(parse_env_bool("no"), Some(false));
        assert_eq!(parse_env_bool("maybe"), None);
        assert_eq!(parse_env_bool(""), None);
    }
}
