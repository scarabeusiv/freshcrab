//! freshcrab: automatic updater and validator for openSUSE
//! Tumbleweed/Factory.
//!
//! The watcher queries version collectors in priority order (Repology,
//! Anitya, PyPI for Python packages, Distrowatch), confirms the candidate
//! version, compares it against the Factory version with proper RPM
//! version comparison, and queues updates for packages that are behind.
//! The queue deduplicates (devel already new, open submit request,
//! in-flight task). Report-only by default: nothing is filed.

pub mod collectors;
pub mod config;
pub mod cve;
pub mod dry_run;
pub mod factory;
pub mod http;
pub mod obs;
pub mod queue;
pub mod target;
pub mod version;
pub mod watcher;
