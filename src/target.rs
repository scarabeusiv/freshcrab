//! Distribution targets: Factory and Leap.
//!
//! freshcrab watches Factory. Leap is the not-yet-implemented second target
//! (see `docs/leap-and-cve.md`): stable distros backport security patches
//! instead of bumping versions, so the "is this fixed?" question is
//! different there — a CVE is fixed when the backported patch is present,
//! not when the version number rises. This module is the extension point
//! for that: the target identity, the per-target update-policy hook, and
//! the implemented / not-yet-implemented gate.
//!
//! Only Factory is implemented. A Leap target parses (so the config
//! shape is real) but the pipeline refuses to run it — see
//! `Target::is_implemented`.

use crate::version::is_newer;
use serde::{Deserialize, Serialize};
use std::fmt;

/// A distribution the pipeline can target.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub enum Target {
    /// openSUSE:Factory (Tumbleweed rolling).
    #[default]
    Factory,
    /// An openSUSE Leap release, e.g. `Leap { version: "16.0" }`.
    Leap { version: String },
}

impl Target {
    /// Parse a target name: `"factory"`, `"leap-16.0"`, `"leap-15.6"`.
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "factory" => Ok(Target::Factory),
            _ => match s.strip_prefix("leap-") {
                Some(version) if is_leap_version(version) => Ok(Target::Leap {
                    version: version.to_string(),
                }),
                _ => Err(format!("unknown distribution target: {s:?}")),
            },
        }
    }

    /// The OBS project for this target.
    pub fn obs_project(&self) -> String {
        match self {
            Target::Factory => "openSUSE:Factory".to_string(),
            Target::Leap { version } => format!("openSUSE:Leap:{version}"),
        }
    }

    /// True when the pipeline implements this target. Only Factory;
    /// Leap is scaffolded but not implemented (see `docs/leap-and-cve.md`).
    pub fn is_implemented(&self) -> bool {
        matches!(self, Target::Factory)
    }

    /// True for Leap targets.
    pub fn is_leap(&self) -> bool {
        matches!(self, Target::Leap { .. })
    }
}

/// A Leap release number: `major.minor`, e.g. `"16.0"`, `"15.6"`.
/// A bare major (`"16"`) is a typo, not a release, so it is rejected.
fn is_leap_version(version: &str) -> bool {
    let parts: Vec<&str> = version.split('.').collect();
    parts.len() == 2
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Target::Factory => write!(f, "factory"),
            Target::Leap { version } => write!(f, "leap-{version}"),
        }
    }
}

// Serialize a target as its name ("factory", "leap-16.0") so queue state
// stays human-readable.
impl Serialize for Target {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Target {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Target::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// Decides whether a target needs an update, given the version the target
/// currently ships and the candidate upstream version.
///
/// Factory's policy is a plain RPM version comparison. Leap's policy
/// (not implemented yet) is backport-aware: a CVE is fixed when the backported
/// patch is present in the Leap package, even if the version did not
/// rise — so it consults the CVE validator (`crate::cve`) instead of
/// comparing versions alone. The watcher holds a policy behind this
/// trait (`Watcher::with_policy`) so the Leap policy can replace the
/// Factory one without changing the watcher.
pub trait UpdatePolicy {
    /// True when the target needs an update.
    fn needs_update(&self, current: &str, candidate: &str) -> bool;
}

/// The Factory policy: an update is needed exactly when the candidate
/// version is newer (proper RPM version comparison).
pub struct FactoryPolicy;

impl UpdatePolicy for FactoryPolicy {
    fn needs_update(&self, current: &str, candidate: &str) -> bool {
        is_newer(candidate, current)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_factory() {
        assert_eq!(Target::parse("factory").unwrap(), Target::Factory);
    }

    #[test]
    fn parse_leap() {
        assert_eq!(
            Target::parse("leap-16.0").unwrap(),
            Target::Leap {
                version: "16.0".to_string()
            }
        );
        assert_eq!(
            Target::parse("leap-15.6").unwrap(),
            Target::Leap {
                version: "15.6".to_string()
            }
        );
    }

    #[test]
    fn parse_unknown_rejected() {
        assert!(Target::parse("sles").is_err());
        assert!(Target::parse("leap").is_err());
        assert!(Target::parse("leap-").is_err());
        assert!(Target::parse("leap-16").is_err());
        assert!(Target::parse("leap-16.x").is_err());
        assert!(Target::parse("leap-16.").is_err());
        assert!(Target::parse("leap-16.0.1").is_err());
        assert!(Target::parse("").is_err());
    }

    #[test]
    fn obs_project() {
        assert_eq!(Target::Factory.obs_project(), "openSUSE:Factory");
        assert_eq!(
            Target::Leap {
                version: "16.0".to_string()
            }
            .obs_project(),
            "openSUSE:Leap:16.0"
        );
    }

    #[test]
    fn implemented_gate() {
        assert!(Target::Factory.is_implemented());
        assert!(!Target::Leap {
            version: "16.0".to_string()
        }
        .is_implemented());
        assert!(Target::Leap {
            version: "16.0".to_string()
        }
        .is_leap());
        assert!(!Target::Factory.is_leap());
    }

    #[test]
    fn display_roundtrip() {
        assert_eq!(Target::Factory.to_string(), "factory");
        assert_eq!(
            Target::Leap {
                version: "16.0".to_string()
            }
            .to_string(),
            "leap-16.0"
        );
        assert_eq!(
            Target::parse(&Target::Factory.to_string()).unwrap(),
            Target::Factory
        );
    }

    #[test]
    fn serde_roundtrip() {
        let json = serde_json::to_string(&Target::Factory).unwrap();
        assert_eq!(json, "\"factory\"");
        assert_eq!(
            serde_json::from_str::<Target>(&json).unwrap(),
            Target::Factory
        );
        let leap = Target::Leap {
            version: "16.0".to_string(),
        };
        let json = serde_json::to_string(&leap).unwrap();
        assert_eq!(json, "\"leap-16.0\"");
        assert_eq!(serde_json::from_str::<Target>(&json).unwrap(), leap);
        assert!(serde_json::from_str::<Target>("\"sles\"").is_err());
    }

    #[test]
    fn factory_policy_matches_is_newer() {
        let policy = FactoryPolicy;
        assert!(policy.needs_update("1.9", "2.0"));
        assert!(policy.needs_update("1.9", "1.10"));
        assert!(!policy.needs_update("2.0", "2.0"));
        assert!(!policy.needs_update("1.0", "1.0~rc1"));
    }
}
