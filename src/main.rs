//! Command-line entry point for the freshcrab watcher and dispatcher.
//!
//! Report-only by default: prints the queue (packages behind on Factory)
//! and files nothing. The config file controls the package set, the
//! exclusions, and the kill switch.
//!
//! When `report_only` is false, the dispatcher runs after the watcher:
//! it picks pending queue entries (security first, within the
//! concurrency limit and the daily SR cap), drives each through the
//! worker, and prints the dispatch report as JSON. Dry-run mode
//! (default true) is global: the watcher polls the collectors and
//! prints what it WOULD queue, the queue evaluates the dedup rules and
//! prints the decision for each candidate, and the dispatcher logs the
//! would-do plan and the exact SR payload and files nothing. The
//! effective mode is resolved as CLI flag (`--dry-run` / `--live`) >
//! env var (`FRESHCRAB_DRY_RUN`) > config (`dry_run`) and is logged
//! loudly at startup. All plan output goes to stderr, so stdout stays
//! machine-readable JSON.

use freshcrab::config::load_config;
use freshcrab::dispatcher::Dispatcher;
use freshcrab::dry_run::resolve as resolve_dry_run;
use freshcrab::factory::FactoryClient;
use freshcrab::http::{map_obs_credentials_error, UreqClient};
use freshcrab::queue::{DedupChecks, Queue, QueueEntry};
use freshcrab::review_queue::{classify_records, discover, own_sr_ids, refresh_signals};
use freshcrab::watcher::Watcher;
use freshcrab::worker::{DryRunExecutor, Worker};
use geectl::auth::Credentials;
use geectl::error::{ErrorKind, GeectlError};
use std::process::ExitCode;

fn print_usage() {
    eprintln!("Usage: freshcrab [--config <path>] [--packages <pkg>...] [--queue <path>] [--review-queue <path>] [--review-ruleset <path>] [--dry-run | --live]");
    eprintln!("  --config <path>     path to config.yaml (default: config.yaml)");
    eprintln!("  --packages <pkg>... check only these packages (overrides the config list)");
    eprintln!("  --queue <path>      path to the queue state file (default: queue.json)");
    eprintln!(
        "  --review-queue <path> path to the review queue state file (default: review_queue.json)"
    );
    eprintln!(
        "  --review-ruleset <path> path to the review ruleset file (default: review_ruleset.json)"
    );
    eprintln!("  --dry-run           force dry-run mode (default)");
    eprintln!("  --live              force live mode (writes the queue; overrides config and env)");
    eprintln!(
        "The watcher runs in report-only mode by default: it prints the queue as JSON and files nothing."
    );
    eprintln!("Report-only gates the dispatcher only: the watcher still enqueues, and in live");
    eprintln!("mode the queue state file is still written (dry-run prevents all writes).");
    eprintln!("With report_only: false in the config, the dispatcher runs after the watcher and");
    eprintln!("files submit requests to the devel projects (dry-run by default: it logs the plan");
    eprintln!("and the exact SR payload and files nothing).");
    eprintln!("Dry-run plan output goes to stderr; stdout is the JSON report.");
}

fn main() -> ExitCode {
    let mut config_path = "config.yaml".to_string();
    let mut packages: Option<Vec<String>> = None;
    let mut queue_path = "queue.json".to_string();
    let mut review_queue_path = "review_queue.json".to_string();
    let mut review_ruleset_path = "review_ruleset.json".to_string();
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
            "--review-queue" => match args.next() {
                Some(path) => review_queue_path = path,
                None => {
                    eprintln!("--review-queue needs a path");
                    print_usage();
                    return ExitCode::from(2);
                }
            },
            "--review-ruleset" => match args.next() {
                Some(path) => review_ruleset_path = path,
                None => {
                    eprintln!("--review-ruleset needs a path");
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
    // docs/leap-and-cve.md). Leap per-target processing is the remaining work.
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
        // The human message goes to stderr; stdout stays valid JSON
        // (an empty report) so `freshcrab | jq` keeps working when the
        // pipeline is paused.
        eprintln!("kill switch is on: pipeline paused, nothing queued.");
        println!("[]");
        return ExitCode::from(0);
    }

    // The OBS client carries the credentials for the authenticated
    // endpoints (the open-SR search the dedup checks use, and filing a
    // submit request). Credentials come from the environment only;
    // without them those calls fail closed. The OBS client
    // is geectl's, on its own HTTP client: the freshcrab client keeps
    // the freshcrab User-Agent the collectors need, and the OBS client
    // gets geectl's bounded timeouts. It is built before the watcher:
    // the Factory reads (spec, package list) are geectl public reads
    // through this same client, so they inherit the same transport:
    // bounded timeouts with retries, and a 10 MiB body cap (far above
    // any spec or listing).
    let geectl_http = match geectl::http::UreqClient::new(geectl::http::Timeout::default()) {
        Ok(client) => client,
        Err(e) => {
            eprintln!("cannot build the OBS HTTP client: {e}");
            return ExitCode::from(1);
        }
    };
    let credentials = match obs_credentials_from_env() {
        Ok(credentials) => credentials,
        Err(e) => {
            eprintln!("invalid OBS credentials (OSC_USERNAME/OSC_PASSWORD): {e}");
            return ExitCode::from(1);
        }
    };
    let obs = match &credentials {
        Some(creds) => {
            match geectl::obs::ObsClient::with_credentials(&geectl_http, creds.clone()) {
                Ok(obs) => obs,
                Err(e) => {
                    eprintln!("cannot build the OBS client: {e}");
                    return ExitCode::from(1);
                }
            }
        }
        None => geectl::obs::ObsClient::new(&geectl_http),
    };
    let http = UreqClient::new();
    let factory = FactoryClient::new(&obs);
    let watcher = Watcher::new(&http, factory, None, &dry_run);

    let entries = match &packages {
        Some(list) => {
            let in_scope: Vec<&str> = list
                .iter()
                .map(|s| s.as_str())
                .filter(|p| config.watched(p))
                .collect();
            watcher.check_packages(&in_scope)
        }
        None => {
            if !config.packages.is_empty() {
                let in_scope: Vec<&str> = config
                    .packages
                    .iter()
                    .map(|s| s.as_str())
                    .filter(|p| config.watched(p))
                    .collect();
                watcher.check_packages(&in_scope)
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
                watcher.check_packages(&in_scope)
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
    // guard in `Queue::save`) — unless the loop below fails loudly on
    // an auth rejection, which returns before `save`; the next run
    // re-derives the entries that were dropped.
    let mut queue = match Queue::open(&queue_path) {
        Ok(queue) => queue,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    for entry in &entries {
        let package = entry.package.as_str();
        // The devel-version check is a public-API read: on error, log
        // loudly and skip that check (fail-open for this check only —
        // a transient hiccup must not drop the package).
        let devel_version = |pkg: &str| match obs.devel_version(pkg) {
            Ok(version) => version,
            Err(e) => {
                eprintln!("warning: devel version check failed for {pkg}: {e}");
                None
            }
        };
        // The open-SR check is fail-closed for a non-auth failure:
        // `Queue::add` skips the package instead of queueing it on an
        // unchecked dedup. Without OBS credentials geectl refuses the
        // check before any request (a ConfigError, mapped at the seam
        // below to name the `OSC_*` variables freshcrab users set),
        // so without them an error here is the normal no-credentials
        // case, and skipping is the safe answer until credentials are
        // provided. An auth failure (rotated or expired credentials)
        // is different: it would strike every candidate, so
        // `Queue::add` returns it as an error and the run fails
        // loudly below instead of exiting 0 with an empty batch.
        // Map geectl's no-credentials ConfigError at the seam: geectl
        // names its own `GEECTL_OBS_*` variables, but freshcrab users
        // set `OSC_*`. Auth failures and every other error pass
        // through untouched.
        let has_open_sr = |pkg: &str| -> Result<bool, GeectlError> {
            obs.has_open_sr(pkg).map_err(|e| {
                if e.kind() == ErrorKind::ConfigError {
                    map_obs_credentials_error(&e)
                } else {
                    e
                }
            })
        };
        if let Err(e) = queue.add(
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
        ) {
            // `Queue::add` only propagates auth rejections (every other
            // check failure is a fail-closed skip inside `add`).
            eprintln!(
                "OBS authentication rejected ({e}); stopping — check OSC_USERNAME/OSC_PASSWORD"
            );
            return ExitCode::from(1);
        }
    }
    if let Err(e) = queue.save(&dry_run) {
        eprintln!("{e}");
        return ExitCode::from(1);
    }

    // The review queue discovers submissions across all configured
    // instances on every run (report-only: it reads and records,
    // posts nothing). It runs after the update queue is saved, so
    // the sr_ids it matches freshcrab's own filings against are
    // current. The review queue reads through geectl's pull-request
    // surface with geectl's own credentials (GEECTL_*), not the
    // update pipeline's OSC_* pair. A discovery failure is logged
    // loudly and the run continues: the review queue is sidecar
    // state, and a corrupt review queue or a malformed geectl
    // config must not break the update pipeline or its stdout JSON.
    let sr_ids = own_sr_ids(queue.entries());
    match discover(&config, &sr_ids, &geectl_http, &review_queue_path, &dry_run) {
        Ok(report) => {
            let scanned = report.instances.iter().filter(|i| !i.skipped).count();
            eprintln!(
                "review queue: {scanned} instance arm(s) scanned, {} discovered, {} new, {} updated, {} terminal, {} unresolved",
                report.discovered,
                report.new_records,
                report.updated_records,
                report.terminal_marked,
                report.unresolved
            );
            for (alias, reason) in &report.unscannable {
                eprintln!("review queue: instance {alias} unscannable: {reason}");
            }
            for instance in &report.instances {
                if let Some(error) = &instance.error {
                    if instance.skipped {
                        eprintln!(
                            "review queue: {} {} skipped: {error}",
                            instance.alias, instance.backend
                        );
                    } else {
                        eprintln!(
                            "review queue: {} {} search failed: {error}",
                            instance.alias, instance.backend
                        );
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("review queue discovery failed: {e}");
        }
    }

    // The review queue reads the signal snapshot for every
    // non-terminal record on every run (step 2, report-only: it
    // reads and records, posts nothing). It runs after discovery,
    // so the records it refreshes are current. A refresh failure
    // is logged loudly and the run continues, like discovery: the
    // review queue is sidecar state and must not break the update
    // pipeline or its stdout JSON.
    match refresh_signals(&config, &sr_ids, &geectl_http, &review_queue_path, &dry_run) {
        Ok(report) => {
            eprintln!(
                "review queue: signals refreshed for {} records, {} with failed reads",
                report.refreshed, report.failed
            );
            for instance in &report.instances {
                if let Some(error) = &instance.error {
                    if instance.skipped {
                        eprintln!(
                            "review queue: {} {} skipped: {error}",
                            instance.alias, instance.backend
                        );
                    } else {
                        eprintln!(
                            "review queue: {} {} refresh failed: {error}",
                            instance.alias, instance.backend
                        );
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("review queue signal refresh failed: {e}");
        }
    }

    // The review queue classifies every snapshot against the
    // ruleset (step 3, report-only: it records the tier and the
    // decided action; it posts nothing). It runs after the signal
    // refresh, so the snapshots it classifies are current. A
    // ruleset that fails to load refuses the run: the failure is
    // logged loudly and the run classifies nothing (the
    // classification is skipped, not defaulted). Like discovery
    // and refresh, a classification failure is sidecar state and
    // must not break the update pipeline or its stdout JSON.
    match classify_records(&review_ruleset_path, &review_queue_path, &dry_run) {
        Ok(report) => {
            eprintln!(
                "review queue: classified {} records ({} auto, {} mid, {} human; {} skipped: {} terminal, {} escalated, {} without snapshot, {} no longer open)",
                report.classified,
                report.auto,
                report.mid,
                report.human,
                report.skipped_terminal
                    + report.skipped_escalated
                    + report.skipped_no_snapshot
                    + report.skipped_not_open,
                report.skipped_terminal,
                report.skipped_escalated,
                report.skipped_no_snapshot,
                report.skipped_not_open
            );
        }
        Err(e) => {
            eprintln!("review queue classification failed: {e}");
        }
    }

    // Report-only gates the dispatcher only: the watcher above has
    // already enqueued, and in live mode the queue state file was
    // already written (the queue is the watcher's staging state, not a
    // filing). `dry_run` is the flag that prevents all writes.
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

    // The dispatcher drives the queued entries through the worker and
    // files submit requests to the devel projects. Dry-run (default
    // true) still applies: the worker logs the plan and the exact SR
    // payload and files nothing. The live executor is the agent/CI
    // step and is the remaining work, so in live mode the DryRunExecutor
    // refuses and the entries escalate instead of filing.
    let executor = DryRunExecutor;
    let worker = Worker::new(
        &obs,
        &executor,
        credentials.as_ref(),
        &config.home_project,
        &dry_run,
    );
    let dispatcher = Dispatcher::new(&worker, &config, &dry_run);
    let report = match dispatcher.dispatch(&mut queue) {
        Ok(report) => report,
        Err(e) => {
            eprintln!("error: dispatch failed: {e}");
            return ExitCode::from(1);
        }
    };
    eprintln!(
        "dispatched {} package(s), filed {} SR(s), {} planned, {} skipped, {} escalated",
        report.dispatched, report.filed, report.planned, report.skipped, report.escalated
    );
    match serde_json::to_string_pretty(&report) {
        Ok(json) => println!("{json}"),
        Err(e) => {
            eprintln!("cannot serialize dispatch report: {e}");
            return ExitCode::from(1);
        }
    }
    ExitCode::from(0)
}

/// Read OBS credentials from the environment (`OSC_USERNAME` /
/// `OSC_PASSWORD`), as geectl Basic credentials. None when either
/// variable is unset or empty. The pair is validated with geectl's
/// `validate_basic` (no `:` in the username, non-empty password), so
/// a malformed pair fails fast here instead of 401ing at the first
/// request. geectl's own resolver reads the `GEECTL_OBS_*` variables,
/// which are the wrong names for freshcrab users, so freshcrab resolves
/// credentials itself.
fn obs_credentials_from_env() -> Result<Option<Credentials>, GeectlError> {
    let username = std::env::var("OSC_USERNAME")
        .ok()
        .filter(|v| !v.trim().is_empty());
    let password = std::env::var("OSC_PASSWORD")
        .ok()
        .filter(|v| !v.trim().is_empty());
    match (username, password) {
        (Some(username), Some(password)) => {
            let (username, password) = geectl::auth::validate_basic(&username, &password)?;
            Ok(Some(Credentials::Basic { username, password }))
        }
        _ => Ok(None),
    }
}
