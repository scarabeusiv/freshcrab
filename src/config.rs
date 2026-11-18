//! Load and validate freshcrab configuration.
//!
//! The config file is YAML, but only the documented subset is supported
//! (see `docs/runbook.md`): top-level `key: value` scalars (string,
//! integer, boolean) and top-level `key:` followed by `  - item` string
//! lists. The parser is hand-written and strict: anything outside the
//! subset is rejected, so a bad config fails fast instead of being
//! silently mis-read. No YAML library is pulled in (standard library
//! only); the rest of the crate uses serde_json for JSON APIs.

use std::collections::HashMap;
use std::fmt;
use std::fs;

/// Error raised when the configuration is invalid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(pub String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "config error: {}", self.0)
    }
}

impl std::error::Error for ConfigError {}

/// A parsed YAML scalar or string list (the only shapes the subset allows).
#[derive(Debug, Clone, PartialEq)]
enum Value {
    Str(String),
    Int(i64),
    Bool(bool),
    List(Vec<String>),
}

const KNOWN_KEYS: &[&str] = &[
    "packages",
    "exclusions",
    "concurrency",
    "daily_sr_cap",
    "kill_switch",
    "report_only",
    "dry_run",
];

/// Validated configuration.
#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    pub packages: Vec<String>,
    pub exclusions: Vec<String>,
    pub concurrency: u32,
    pub daily_sr_cap: u32,
    pub kill_switch: bool,
    pub report_only: bool,
    /// Dry-run mode: when true, nothing is written or filed; components
    /// print what they WOULD do. Default true in this phase (the watcher
    /// is report-only anyway). Overridable by `--dry-run` / `--live` and
    /// by the `FRESHCRAB_DRY_RUN` env var.
    pub dry_run: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            packages: Vec::new(),
            exclusions: Vec::new(),
            concurrency: 3,
            daily_sr_cap: 10,
            kill_switch: false,
            report_only: true,
            dry_run: true,
        }
    }
}

impl Config {
    /// True if the package is in scope: watched and not excluded.
    pub fn watched(&self, package: &str) -> bool {
        if self.exclusions.iter().any(|e| e == package) {
            return false;
        }
        if !self.packages.is_empty() {
            return self.packages.iter().any(|p| p == package);
        }
        true
    }
}

/// Strip a trailing comment (`# ...`) that is preceded by whitespace and
/// not inside quotes. Returns the line without the comment.
fn strip_comment(line: &str) -> &str {
    let mut in_single = false;
    let mut in_double = false;
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let ch = bytes[i] as char;
        match ch {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            '#' if !in_single
                && !in_double
                && (i == 0 || bytes[i - 1] == b' ' || bytes[i - 1] == b'\t') =>
            {
                // A `#` at the start or after whitespace starts a comment.
                return line[..i].trim_end();
            }
            _ => {}
        }
        i += 1;
    }
    line
}

/// Parse a scalar value: boolean, integer, or (possibly quoted) string.
fn parse_scalar(raw: &str) -> Result<Value, ConfigError> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(ConfigError("empty value".to_string()));
    }
    if raw == "true" {
        return Ok(Value::Bool(true));
    }
    if raw == "false" {
        return Ok(Value::Bool(false));
    }
    if let Ok(n) = raw.parse::<i64>() {
        return Ok(Value::Int(n));
    }
    // Quoted string.
    if raw.len() >= 2
        && ((raw.starts_with('"') && raw.ends_with('"'))
            || (raw.starts_with('\'') && raw.ends_with('\'')))
    {
        return Ok(Value::Str(raw[1..raw.len() - 1].to_string()));
    }
    // Unquoted string: reject flow syntax and anything that looks like a
    // nested structure.
    if raw.contains('[') || raw.contains(']') || raw.contains('{') || raw.contains('}') {
        return Err(ConfigError(format!("unsupported value syntax: {raw}")));
    }
    Ok(Value::Str(raw.to_string()))
}

/// Parse the documented YAML subset into a key/value map.
fn parse_subset(text: &str) -> Result<HashMap<String, Value>, ConfigError> {
    let mut map: HashMap<String, Value> = HashMap::new();
    let mut current_list_key: Option<String> = None;

    for (lineno, raw_line) in text.lines().enumerate() {
        let lineno = lineno + 1;
        if raw_line.contains('\t') {
            return Err(ConfigError(format!(
                "line {lineno}: tabs are not allowed for indentation"
            )));
        }
        let line = strip_comment(raw_line);
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // A list item belongs to the most recent `key:` with no value.
        if let Some(stripped) = trimmed.strip_prefix("- ") {
            let key = current_list_key.clone().ok_or_else(|| {
                ConfigError(format!("line {lineno}: list item without a preceding key"))
            })?;
            let item = parse_scalar(stripped)
                .map_err(|e| ConfigError(format!("line {lineno}: {}", e.0)))?;
            match item {
                Value::Str(s) => {
                    if let Some(Value::List(list)) = map.get_mut(&key) {
                        list.push(s);
                    } else {
                        return Err(ConfigError(format!(
                            "line {lineno}: list item for non-list key {key}"
                        )));
                    }
                }
                _ => {
                    return Err(ConfigError(format!(
                        "line {lineno}: list entries must be strings"
                    )))
                }
            }
            continue;
        }
        if trimmed == "-" {
            return Err(ConfigError(format!("line {lineno}: empty list item")));
        }

        // A top-level key must not be indented.
        if line.starts_with(' ') {
            return Err(ConfigError(format!(
                "line {lineno}: unexpected indentation (only list items may be indented)"
            )));
        }

        let (key, value) = match line.split_once(':') {
            Some((k, v)) => (k.trim().to_string(), v.trim().to_string()),
            None => {
                return Err(ConfigError(format!(
                    "line {lineno}: expected 'key: value', got {trimmed:?}"
                )))
            }
        };
        if key.is_empty() {
            return Err(ConfigError(format!("line {lineno}: empty key")));
        }
        if key.contains(' ') {
            return Err(ConfigError(format!("line {lineno}: invalid key {key:?}")));
        }
        if map.contains_key(&key) {
            return Err(ConfigError(format!("line {lineno}: duplicate key {key}")));
        }
        current_list_key = None;

        if value.is_empty() {
            // `key:` with no value starts a list.
            map.insert(key.clone(), Value::List(Vec::new()));
            current_list_key = Some(key);
        } else {
            let parsed =
                parse_scalar(&value).map_err(|e| ConfigError(format!("line {lineno}: {}", e.0)))?;
            map.insert(key, parsed);
        }
    }

    Ok(map)
}

fn require_list(map: &HashMap<String, Value>, name: &str) -> Result<Vec<String>, ConfigError> {
    match map.get(name) {
        None => Ok(Vec::new()),
        Some(Value::List(items)) => {
            for item in items {
                if item.is_empty() {
                    return Err(ConfigError(format!(
                        "{name}: entries must be non-empty strings"
                    )));
                }
            }
            Ok(items.clone())
        }
        Some(_) => Err(ConfigError(format!("{name}: expected a list"))),
    }
}

fn require_int(map: &HashMap<String, Value>, name: &str, minimum: i64) -> Result<i64, ConfigError> {
    match map.get(name) {
        None => Ok(match name {
            "concurrency" => 3,
            "daily_sr_cap" => 10,
            _ => 0,
        }),
        Some(Value::Int(n)) => {
            if *n < minimum {
                return Err(ConfigError(format!(
                    "{name}: must be >= {minimum}, got {n}"
                )));
            }
            Ok(*n)
        }
        Some(_) => Err(ConfigError(format!("{name}: expected an integer"))),
    }
}

fn require_bool(
    map: &HashMap<String, Value>,
    name: &str,
    default: bool,
) -> Result<bool, ConfigError> {
    match map.get(name) {
        None => Ok(default),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err(ConfigError(format!("{name}: expected a boolean"))),
    }
}

/// Validate a parsed map into a Config.
fn validate(map: HashMap<String, Value>) -> Result<Config, ConfigError> {
    let unknown: Vec<&str> = map
        .keys()
        .filter(|k| !KNOWN_KEYS.contains(&k.as_str()))
        .map(|k| k.as_str())
        .collect();
    if !unknown.is_empty() {
        return Err(ConfigError(format!(
            "unknown config keys: {}",
            unknown.join(", ")
        )));
    }

    Ok(Config {
        packages: require_list(&map, "packages")?,
        exclusions: require_list(&map, "exclusions")?,
        concurrency: require_int(&map, "concurrency", 1)? as u32,
        daily_sr_cap: require_int(&map, "daily_sr_cap", 0)? as u32,
        kill_switch: require_bool(&map, "kill_switch", false)?,
        report_only: require_bool(&map, "report_only", true)?,
        dry_run: require_bool(&map, "dry_run", true)?,
    })
}

/// Load and validate the config file at `path`.
pub fn load_config(path: &str) -> Result<Config, ConfigError> {
    let text = fs::read_to_string(path)
        .map_err(|e| ConfigError(format!("cannot read config file {path}: {e}")))?;
    load_config_text(&text)
}

/// Load and validate config from a YAML string (used by the tests).
pub fn load_config_text(text: &str) -> Result<Config, ConfigError> {
    let map = parse_subset(text)?;
    validate(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_config_uses_defaults() {
        let cfg = load_config_text("").unwrap();
        assert_eq!(cfg, Config::default());
    }

    #[test]
    fn full_config() {
        let cfg = load_config_text("packages: [foo]\n");
        // Inline flow lists are NOT in the subset.
        assert!(cfg.is_err());
        let cfg = load_config_text(
            "packages:\n  - foo\n  - bar\nexclusions:\n  - gcc\n  - qemu\nconcurrency: 5\ndaily_sr_cap: 20\nkill_switch: true\nreport_only: false\n",
        )
        .unwrap();
        assert_eq!(cfg.packages, vec!["foo", "bar"]);
        assert_eq!(cfg.exclusions, vec!["gcc", "qemu"]);
        assert_eq!(cfg.concurrency, 5);
        assert_eq!(cfg.daily_sr_cap, 20);
        assert!(cfg.kill_switch);
        assert!(!cfg.report_only);
    }

    #[test]
    fn unknown_key_rejected() {
        assert!(load_config_text("bogus_key: 1\n").is_err());
    }

    #[test]
    fn packages_must_be_a_list() {
        assert!(load_config_text("packages: foo\n").is_err());
    }

    #[test]
    fn concurrency_must_be_positive_int() {
        assert!(load_config_text("concurrency: 0\n").is_err());
        assert!(load_config_text("concurrency: -1\n").is_err());
        assert!(load_config_text("concurrency: three\n").is_err());
        assert!(load_config_text("concurrency: true\n").is_err());
    }

    #[test]
    fn daily_sr_cap_must_be_non_negative_int() {
        assert!(load_config_text("daily_sr_cap: -1\n").is_err());
        let cfg = load_config_text("daily_sr_cap: 0\n").unwrap();
        assert_eq!(cfg.daily_sr_cap, 0);
    }

    #[test]
    fn kill_switch_must_be_bool() {
        assert!(load_config_text("kill_switch: yes\n").is_err());
    }

    #[test]
    fn comments_and_blank_lines_ignored() {
        let cfg =
            load_config_text("# a comment\n\npackages:\n  - foo # trailing comment\n").unwrap();
        assert_eq!(cfg.packages, vec!["foo"]);
    }

    #[test]
    fn tabs_rejected() {
        assert!(load_config_text("packages:\n\t- foo\n").is_err());
    }

    #[test]
    fn duplicate_key_rejected() {
        assert!(load_config_text("concurrency: 3\nconcurrency: 4\n").is_err());
    }

    #[test]
    fn watched() {
        let cfg = load_config_text("exclusions:\n  - gcc\n").unwrap();
        assert!(cfg.watched("foo"));
        assert!(!cfg.watched("gcc"));

        let cfg = load_config_text("packages:\n  - foo\n  - bar\nexclusions:\n  - bar\n").unwrap();
        assert!(cfg.watched("foo"));
        assert!(!cfg.watched("bar"));
        assert!(!cfg.watched("baz"));

        // Exclusion beats the package list.
        let cfg = load_config_text("packages:\n  - gcc\nexclusions:\n  - gcc\n").unwrap();
        assert!(!cfg.watched("gcc"));
    }

    #[test]
    fn repo_config_loads() {
        // The repo config.yaml lives next to the crate root; the test
        // runs with the crate root as the working directory.
        let cfg = load_config("config.yaml").unwrap();
        assert!(cfg.packages.is_empty());
        assert!(cfg.exclusions.contains(&"gcc".to_string()));
        assert!(cfg.exclusions.contains(&"qemu".to_string()));
        assert!(cfg.exclusions.contains(&"kernel".to_string()));
        assert!(cfg.report_only);
        assert!(!cfg.kill_switch);
    }
}
