//! RPM version comparison, implemented in pure Rust.
//!
//! This is the rpm `rpmvercmp` algorithm: versions are compared segment by
//! segment, where a segment is a run of digits or a run of letters. Numeric
//! segments compare numerically (so 1.10 > 1.9); alpha segments compare
//! lexically. `~` sorts before everything, including the end of the string
//! (pre-release: 1.0~rc1 < 1.0). `^` sorts after the end of the string but
//! before any other character (post-release snapshot: 1.0 < 1.0^git1 <
//! 1.0.1). Separators (anything that is not alphanumeric, `~`, or `^`) are
//! skipped.
//!
//! `rpmvercmp(a, b)` returns `Ordering::Less` if a < b, `Equal` if a == b,
//! `Greater` if a > b. `compare_evr` compares (epoch:)version-release
//! strings the way RPM does.

use std::cmp::Ordering;

fn is_digit(ch: char) -> bool {
    ch.is_ascii_digit()
}

fn is_alpha(ch: char) -> bool {
    ch.is_ascii_alphabetic()
}

fn is_alnum(ch: char) -> bool {
    ch.is_ascii_alphanumeric()
}

/// Compare two version (or release) strings the way RPM does.
pub fn rpmvercmp(a: &str, b: &str) -> Ordering {
    if a == b {
        return Ordering::Equal;
    }

    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut i = 0usize;
    let mut j = 0usize;

    while i < a.len() || j < b.len() {
        // Skip separators (not alnum, not ~, not ^).
        while i < a.len() && !is_alnum(a[i]) && a[i] != '~' && a[i] != '^' {
            i += 1;
        }
        while j < b.len() && !is_alnum(b[j]) && b[j] != '~' && b[j] != '^' {
            j += 1;
        }

        // Tilde sorts before everything, including the end of the string.
        let a_tilde = i < a.len() && a[i] == '~';
        let b_tilde = j < b.len() && b[j] == '~';
        if a_tilde || b_tilde {
            if !a_tilde {
                return Ordering::Greater;
            }
            if !b_tilde {
                return Ordering::Less;
            }
            i += 1;
            j += 1;
            continue;
        }

        // Caret sorts after the end of the string but before any character.
        let a_caret = i < a.len() && a[i] == '^';
        let b_caret = j < b.len() && b[j] == '^';
        if a_caret || b_caret {
            if i >= a.len() {
                return Ordering::Less;
            }
            if j >= b.len() {
                return Ordering::Greater;
            }
            if !a_caret {
                return Ordering::Greater;
            }
            if !b_caret {
                return Ordering::Less;
            }
            i += 1;
            j += 1;
            continue;
        }

        // One string ended: the other (longer) one is newer.
        if i >= a.len() {
            return Ordering::Less;
        }
        if j >= b.len() {
            return Ordering::Greater;
        }

        // Both have a segment: take the run of digits or the run of letters.
        let (seg_a, is_num_a) = take_segment(&a, &mut i);
        let (seg_b, is_num_b) = take_segment(&b, &mut j);

        // A numeric segment is newer than an alpha segment.
        if is_num_a && !is_num_b {
            return Ordering::Greater;
        }
        if !is_num_a && is_num_b {
            return Ordering::Less;
        }

        if is_num_a {
            // Numeric: strip leading zeros, longer run wins, then lexical.
            let stripped_a = seg_a.trim_start_matches('0');
            let stripped_b = seg_b.trim_start_matches('0');
            let stripped_a = if stripped_a.is_empty() {
                "0"
            } else {
                stripped_a
            };
            let stripped_b = if stripped_b.is_empty() {
                "0"
            } else {
                stripped_b
            };
            if stripped_a.len() != stripped_b.len() {
                return if stripped_a.len() > stripped_b.len() {
                    Ordering::Greater
                } else {
                    Ordering::Less
                };
            }
            if stripped_a != stripped_b {
                return stripped_a.cmp(stripped_b);
            }
        } else if seg_a != seg_b {
            return seg_a.cmp(&seg_b);
        }
    }

    Ordering::Equal
}

/// Take the next segment (a run of digits or a run of letters) starting at
/// `pos`, advancing `pos` past it. Returns (segment, is_numeric).
fn take_segment(chars: &[char], pos: &mut usize) -> (String, bool) {
    let start = *pos;
    if is_digit(chars[*pos]) {
        while *pos < chars.len() && is_digit(chars[*pos]) {
            *pos += 1;
        }
        (chars[start..*pos].iter().collect(), true)
    } else {
        while *pos < chars.len() && is_alpha(chars[*pos]) {
            *pos += 1;
        }
        (chars[start..*pos].iter().collect(), false)
    }
}

fn parse_epoch(version: &str) -> (u64, &str) {
    if let Some((epoch, rest)) = version.split_once(':') {
        if !epoch.is_empty() && epoch.chars().all(|c| c.is_ascii_digit()) {
            if let Ok(n) = epoch.parse::<u64>() {
                return (n, rest);
            }
        }
    }
    (0, version)
}

/// Compare two (epoch:)version-release strings the way RPM does.
///
/// Accepts "1.0-1", "2:1.0-1", or a bare version. The epoch defaults to 0;
/// the release defaults to "".
pub fn compare_evr(a: &str, b: &str) -> Ordering {
    let (epoch_a, rest_a) = parse_epoch(a);
    let (epoch_b, rest_b) = parse_epoch(b);
    if epoch_a != epoch_b {
        return epoch_a.cmp(&epoch_b);
    }

    let (version_a, release_a) = match rest_a.split_once('-') {
        Some((v, r)) => (v, r),
        None => (rest_a, ""),
    };
    let (version_b, release_b) = match rest_b.split_once('-') {
        Some((v, r)) => (v, r),
        None => (rest_b, ""),
    };

    let rc = rpmvercmp(version_a, version_b);
    if rc != Ordering::Equal {
        return rc;
    }
    rpmvercmp(release_a, release_b)
}

/// True if `candidate` is a newer version than `current`.
pub fn is_newer(candidate: &str, current: &str) -> bool {
    compare_evr(candidate, current) == Ordering::Greater
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal() {
        assert_eq!(rpmvercmp("1.0", "1.0"), Ordering::Equal);
        assert_eq!(rpmvercmp("2.3.4", "2.3.4"), Ordering::Equal);
    }

    #[test]
    fn numeric_segments() {
        // Numeric comparison, not lexicographic: 1.10 > 1.9.
        assert_eq!(rpmvercmp("1.10", "1.9"), Ordering::Greater);
        assert_eq!(rpmvercmp("1.9", "1.10"), Ordering::Less);
        assert_eq!(rpmvercmp("2.0", "10.0"), Ordering::Less);
        assert_eq!(rpmvercmp("1.0", "2.0"), Ordering::Less);
    }

    #[test]
    fn leading_zeros_ignored() {
        assert_eq!(rpmvercmp("1.01", "1.1"), Ordering::Equal);
        assert_eq!(rpmvercmp("1.001", "1.1"), Ordering::Equal);
    }

    #[test]
    fn alpha_segments() {
        assert_eq!(rpmvercmp("1.0a", "1.0b"), Ordering::Less);
        assert_eq!(rpmvercmp("1.0b", "1.0a"), Ordering::Greater);
    }

    #[test]
    fn numeric_beats_alpha() {
        assert_eq!(rpmvercmp("1.01", "1.0a"), Ordering::Greater);
        assert_eq!(rpmvercmp("1.0a", "1.01"), Ordering::Less);
    }

    #[test]
    fn longer_is_newer() {
        assert_eq!(rpmvercmp("1.0", "1.0.1"), Ordering::Less);
        assert_eq!(rpmvercmp("1.0.1", "1.0"), Ordering::Greater);
        assert_eq!(rpmvercmp("1.0", "1.0a"), Ordering::Less);
    }

    #[test]
    fn tilde_sorts_before_everything() {
        // Pre-release: 1.0~rc1 < 1.0.
        assert_eq!(rpmvercmp("1.0~rc1", "1.0"), Ordering::Less);
        assert_eq!(rpmvercmp("1.0", "1.0~rc1"), Ordering::Greater);
        assert_eq!(rpmvercmp("1.0~rc1", "1.0~rc2"), Ordering::Less);
        assert_eq!(rpmvercmp("1.0~rc1~git2", "1.0~rc1"), Ordering::Less);
    }

    #[test]
    fn caret_sorts_after_end_before_char() {
        // Post-release snapshot: 1.0 < 1.0^git1 < 1.0.1.
        assert_eq!(rpmvercmp("1.0^git1", "1.0"), Ordering::Greater);
        assert_eq!(rpmvercmp("1.0", "1.0^git1"), Ordering::Less);
        assert_eq!(rpmvercmp("1.0^git1", "1.0.1"), Ordering::Less);
        assert_eq!(rpmvercmp("1.0.1", "1.0^git1"), Ordering::Greater);
    }

    #[test]
    fn separators_skipped() {
        assert_eq!(rpmvercmp("1.0", "1-0"), Ordering::Equal);
        assert_eq!(rpmvercmp("1_0", "1.0"), Ordering::Equal);
    }

    #[test]
    fn epoch_wins() {
        assert_eq!(compare_evr("2:1.0", "1:9.9"), Ordering::Greater);
        assert_eq!(compare_evr("1:1.0", "1.0"), Ordering::Greater);
        assert_eq!(compare_evr("1.0", "1:1.0"), Ordering::Less);
    }

    #[test]
    fn version_then_release() {
        assert_eq!(compare_evr("1.0-1", "1.0-2"), Ordering::Less);
        assert_eq!(compare_evr("1.0-2", "1.0-1"), Ordering::Greater);
        assert_eq!(compare_evr("1.0-1", "1.1-1"), Ordering::Less);
        assert_eq!(compare_evr("1.0-1", "1.0-1"), Ordering::Equal);
    }

    #[test]
    fn is_newer_cases() {
        assert!(is_newer("2.0", "1.9"));
        assert!(is_newer("1.10", "1.9"));
        assert!(!is_newer("1.0~rc1", "1.0"));
        assert!(!is_newer("1.0", "1.0"));
    }
}
