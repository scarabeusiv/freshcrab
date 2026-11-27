//! freshcrab: automatic updater and validator for openSUSE
//! Tumbleweed/Factory.
//!
//! The watcher queries version collectors in priority order (Repology,
//! Anitya, PyPI for Python packages, Distrowatch), confirms the candidate
//! version, compares it against the Factory version with proper RPM
//! version comparison, and queues updates for packages that are behind.
//! The queue deduplicates (devel already new, open submit request,
//! in-flight task). Report-only by default: nothing is filed. The
//! dispatcher picks queued entries (security first, within the
//! concurrency limit and the daily SR cap) and drives each through the
//! worker, which builds the update plan and files the submit request
//! to the devel project (dry-run by default: the plan and the exact SR
//! payload are logged, nothing is filed).

pub mod collectors;
pub mod config;
pub mod cve;
pub mod dispatcher;
pub mod dry_run;
pub mod factory;
pub mod http;
pub mod queue;
pub mod review_queue;
pub mod target;
pub mod version;
pub mod watcher;
pub mod worker;
