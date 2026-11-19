//! Command-line entry point for the freshcrab watcher.
//!
//! Report-only by default: prints the queue (packages behind on Factory)
//! and files nothing. The config file controls the package set, the
//! exclusions, and the kill switch.
//!
//! Dry-run mode (default true in this phase) is global: the watcher polls
//! the collectors and prints what it WOULD queue, the queue evaluates the
//! dedup rules and prints the decision for each candidate, and nothing is
//! written or filed. The effective mode is resolved as CLI flag
//! (`--dry-run` / `--live`) > env var (`FRESHCRAB_DRY_RUN`) > config
//! (`dry_run`) and is logged loudly at startup. All plan output goes to
//! stderr, so stdout stays machine-readable JSON.

use freshcrab::config::load_config;
use freshcrab::dry_run::resolve as resolve_dry_run;
use freshcrab::factory::FactoryClient;
use freshcrab::http::UreqClient;
use freshcrab::obs::ObsClient;
use freshcrab::queue::{DedupChecks, Queue, QueueEntry};
use freshcrab::watcher::Watcher;
use std::process::ExitCode;

fn print_usage() {
    eprintln!("Usage: freshcrab [--config <path>] [--packages <pkg>...] [--queue <path>] [--dry-run | --live]");
    eprintln!("  --config <path>     path to config.yaml (default: config.yaml)");
    eprintln!("  --packages <pkg>... check only these packages (overrides the config list)");
    eprintln!("  --queue <path>      path to the queue state file (default: queue.json)");
    eprintln!("  --dry-run           force dry-run mode (default in this phase)");
    eprintln!("  --live              force live mode (writes the queue; overrides config and env)");
    eprintln!(
        "The watcher runs in report-only mode: it prints the queue as JSON and files nothing."
    );
    eprintln!("Dry-run plan output goes to stderr; stdout is the JSON report.");
}

fn main() -> ExitCode {
    let mut config_path = "config.yaml".to_string();
    let mut packages: Option<Vec<String>> = None;
    let mut queue_path = "queue.json".to_string();
    let mut cli_dry_run: Option<bool> = None;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => match args.next() {
                Some(path) => config_path = path,
                None => {
                    eprintln!("--config needs a path");
                    print_usage();
                    return ExitCode::from(2);
                }
            },
            "--queue" => match args.next() {
                Some(path) => queue_path = path,
                None => {
                    eprintln!("--queue needs a path");
                    print_usage();
                    return ExitCode::from(2);
                }
            },
            "--dry-run" => {
                if cli_dry_run == Some(false) {
                    eprintln!("--dry-run and --live conflict; pass only one");
                    print_usage();
                    return ExitCode::from(2);
                }
                cli_dry_run = Some(true);
            }
            "--live" => {
                if cli_dry_run == Some(true) {
                    eprintln!("--dry-run and --live conflict; pass only one");
                    print_usage();
                    return ExitCode::from(2);
                }
                cli_dry_run = Some(false);
            }
            "--packages" => {
                let mut list = Vec::new();
                for pkg in args.by_ref() {
                    if pkg.starts_with("--") {
                        eprintln!("--packages must come last");
                        print_usage();
                        return ExitCode::from(2);
                    }
                    list.push(pkg);
                }
                packages = Some(list);
            }
            "--help" | "-h" => {
                print_usage();
                return ExitCode::from(0);
            }
            other => {
                eprintln!("unknown argument: {other}");
                print_usage();
                return ExitCode::from(2);
            }
        }
    }

    let config = match load_config(&config_path) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };

    // Targets: only Factory is implemented. A Leap target in the config
    // fails fast here rather than being silently skipped (see
    // docs/leap-and-cve.md). The per-target loop is the later Leap step.
    for target in &config.targets {
        if !target.is_implemented() {
            eprintln!("target {target} is not yet implemented (see docs/leap-and-cve.md)");
            return ExitCode::from(1);
        }
    }

    // Resolve the effective dry-run mode and log it loudly.
    let env_dry_run = std::env::var("FRESHCRAB_DRY_RUN").ok();
    let dry_run = match resolve_dry_run(cli_dry_run, env_dry_run, config.dry_run) {
        Ok(dry_run) => dry_run,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    dry_run.log_mode();

    if config.kill_switch {
        println!("kill switch is on: pipeline paused, nothing queued.");
        return ExitCode::from(0);
    }

    let http = UreqClient::new();
    let factory = FactoryClient::new(&http);
    let watcher = Watcher::new(&http, factory, None, &dry_run);

    let entries = match &packages {
        Some(list) => {
            let in_scope: Vec<&str> = list
                .iter()
                .map(|s| s.as_str())
                .filter(|p| config.watched(p))
                .collect();
            match watcher.check_packages(&in_scope) {
                Ok(entries) => entries,
                Err(e) => {
                    eprintln!("watcher error: {e}");
                    return ExitCode::from(1);
                }
            }
        }
        None => {
            if !config.packages.is_empty() {
                let in_scope: Vec<&str> = config
                    .packages
                    .iter()
                    .map(|s| s.as_str())
                    .filter(|p| config.watched(p))
                    .collect();
                match watcher.check_packages(&in_scope) {
                    Ok(entries) => entries,
                    Err(e) => {
                        eprintln!("watcher error: {e}");
                        return ExitCode::from(1);
                    }
                }
            } else {
                // Broad default: all of Factory except the exclusions.
                let all = match factory.list_packages() {
                    Ok(all) => all,
                    Err(e) => {
                        eprintln!("cannot list Factory packages: {e}");
                        return ExitCode::from(1);
                    }
                };
                let in_scope: Vec<&str> = all
                    .iter()
                    .map(|s| s.as_str())
                    .filter(|p| config.watched(p))
                    .collect();
                match watcher.check_packages(&in_scope) {
                    Ok(entries) => entries,
                    Err(e) => {
                        eprintln!("watcher error: {e}");
                        return ExitCode::from(1);
                    }
                }
            }
        }
    };

    // The exclusions apply even to the full-Factory list.
    let entries: Vec<_> = entries
        .into_iter()
        .filter(|e| config.watched(&e.package))
        .collect();

    // Feed the watcher entries into the queue. In dry-run the queue
    // evaluates the dedup rules and prints the decision for each candidate
    // (would-enqueue / would-skip + reason) and persists nothing; in live
    // mode it enqueues and the state file is written (via the dry-run
    // guard in `Queue::save`).
    let mut queue = match Queue::open(&queue_path) {
        Ok(queue) => queue,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    let obs = ObsClient::new(&http);
    for entry in &entries {
        let package = entry.package.as_str();
        // The OBS dedup checks are best-effort reads: on error, log loudly
        // and fail open (the worker re-checks before filing).
        let devel_version = |pkg: &str| match obs.devel_version(pkg) {
            Ok(version) => version,
            Err(e) => {
                eprintln!("warning: devel version check failed for {pkg}: {e}");
                None
            }
        };
        let has_open_sr = |pkg: &str| match obs.has_open_sr(pkg) {
            Ok(found) => found,
            Err(e) => {
                eprintln!("warning: open-SR check failed for {pkg}: {e}");
                false
            }
        };
        queue.add(
            QueueEntry::new(
                package,
                &entry.factory_version,
                &entry.upstream_version,
                &entry.source,
                &entry.target,
                entry.kind,
            ),
            DedupChecks {
                devel_version: Some(&devel_version),
                has_open_sr: Some(&has_open_sr),
            },
            &dry_run,
        );
    }
    if let Err(e) = queue.save(&dry_run) {
        eprintln!("{e}");
        return ExitCode::from(1);
    }

    if config.report_only {
        match serde_json::to_string_pretty(&entries) {
            Ok(json) => println!("{json}"),
            Err(e) => {
                eprintln!("cannot serialize queue: {e}");
                return ExitCode::from(1);
            }
        }
        return ExitCode::from(0);
    }

    // Filing submit requests is a later phase; report-only is the only
    // mode this scaffolding implements.
    eprintln!("SR filing is not implemented yet; running in report-only mode.");
    match serde_json::to_string_pretty(&entries) {
        Ok(json) => println!("{json}"),
        Err(e) => {
            eprintln!("cannot serialize queue: {e}");
            return ExitCode::from(1);
        }
    }
    ExitCode::from(0)
}
