//! Integration tests for config loading and validation.

use freshcrab::config::{load_config, load_config_text};

#[test]
fn repo_config_loads_with_broad_defaults() {
    let cfg = load_config("config.yaml").unwrap();
    // Broad defaults: no package list, gcc/qemu/kernel excluded.
    assert!(cfg.packages.is_empty());
    assert!(cfg.exclusions.contains(&"gcc".to_string()));
    assert!(cfg.exclusions.contains(&"qemu".to_string()));
    assert!(cfg.exclusions.contains(&"kernel".to_string()));
    assert!(cfg.report_only);
    assert!(!cfg.kill_switch);
    // Dry-run is the default in this phase.
    assert!(cfg.dry_run);
}

#[test]
fn dry_run_flag_parses() {
    let cfg = load_config_text("dry_run: false\n").unwrap();
    assert!(!cfg.dry_run);
    let cfg = load_config_text("dry_run: true\n").unwrap();
    assert!(cfg.dry_run);
    assert!(load_config_text("dry_run: yes\n").is_err());
}

#[test]
fn invalid_config_is_rejected() {
    assert!(load_config_text("bogus_key: 1\n").is_err());
    assert!(load_config_text("concurrency: 0\n").is_err());
    assert!(load_config_text("packages: [foo]\n").is_err());
}

#[test]
fn exclusions_win_over_package_list() {
    let cfg = load_config_text("packages:\n  - gcc\nexclusions:\n  - gcc\n").unwrap();
    assert!(!cfg.watched("gcc"));
}
