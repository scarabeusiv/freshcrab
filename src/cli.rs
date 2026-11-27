//! Command-line interface definition for freshcrab.
//!
//! The single source of truth for the flags: the binary parses them
//! here, and the man-page / shell-completion generator drives the
//! same definition (see `cli_command`), so the two can never drift.

use clap::{CommandFactory, Parser};

/// Automatic updater and validator for openSUSE Tumbleweed/Factory.
#[derive(Debug, Parser)]
#[command(
    name = "freshcrab",
    version,
    about = "Automatic updater and validator for openSUSE Tumbleweed/Factory",
    long_about = "Report-only by default: prints the queue (packages behind on Factory) \
        and files nothing. Dry-run mode (default true) is global: the watcher polls the \
        collectors and prints what it WOULD queue, the queue evaluates the dedup rules \
        and prints the decision for each candidate, and the dispatcher logs the would-do \
        plan and the exact SR payload and files nothing. All plan output goes to stderr, \
        so stdout stays machine-readable JSON."
)]
pub struct Cli {
    /// path to config.yaml
    #[arg(long, value_name = "path", default_value = "config.yaml")]
    pub config: String,

    /// check only these packages (overrides the config list)
    #[arg(long, value_name = "pkg", num_args = 1..)]
    pub packages: Option<Vec<String>>,

    /// path to the queue state file
    #[arg(long, value_name = "path", default_value = "queue.json")]
    pub queue: String,

    /// force dry-run mode (default)
    #[arg(long, conflicts_with = "live")]
    pub dry_run: bool,

    /// force live mode (writes the queue; overrides config and env)
    #[arg(long, conflicts_with = "dry_run")]
    pub live: bool,
}

/// The shared clap `Command` definition, for the generator.
pub fn cli_command() -> clap::Command {
    Cli::command()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults() {
        let cli = Cli::try_parse_from(["freshcrab"]).unwrap();
        assert_eq!(cli.config, "config.yaml");
        assert_eq!(cli.packages, None);
        assert_eq!(cli.queue, "queue.json");
        assert!(!cli.dry_run);
        assert!(!cli.live);
    }

    #[test]
    fn each_flag_parsed() {
        let cli = Cli::try_parse_from([
            "freshcrab",
            "--config",
            "mine.yaml",
            "--packages",
            "foo",
            "bar",
            "--queue",
            "q.json",
            "--live",
        ])
        .unwrap();
        assert_eq!(cli.config, "mine.yaml");
        assert_eq!(
            cli.packages,
            Some(vec!["foo".to_string(), "bar".to_string()])
        );
        assert_eq!(cli.queue, "q.json");
        assert!(cli.live);
        assert!(!cli.dry_run);
    }

    #[test]
    fn dry_run_flag_parsed() {
        let cli = Cli::try_parse_from(["freshcrab", "--dry-run"]).unwrap();
        assert!(cli.dry_run);
        assert!(!cli.live);
    }

    #[test]
    fn dry_run_and_live_conflict() {
        let err = Cli::try_parse_from(["freshcrab", "--dry-run", "--live"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn unknown_argument_rejected() {
        let err = Cli::try_parse_from(["freshcrab", "--nope"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    #[test]
    fn config_without_a_value_rejected() {
        let err = Cli::try_parse_from(["freshcrab", "--config"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::InvalidValue, "{err}");
    }
}
