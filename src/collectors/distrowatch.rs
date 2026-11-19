//! Distrowatch collector (secondary signal only).
//!
//! Distrowatch lists package versions per distribution in an HTML table.
//! It is a secondary signal: a Distrowatch-only candidate never confirms
//! on its own (see `crate::collectors`). The parser is scoped to table
//! rows: within a `<tr>`, the first two `<td>` cells are (package,
//! version), with any nested tags stripped. Pairing inside a row (not
//! across the whole document) means a stray cell in an ad or header row
//! cannot misalign the package rows, and stripping tags means a nested
//! `<a>` cannot pollute the version string. No regex crate is used; the
//! scan is a plain string search.

use crate::collectors::{Candidate, Collector};
use crate::http::{HttpClient, HttpError};

pub const DISTROWATCH_URL: &str = "https://distrowatch.com/table.php?distribution=opensuse";

/// Strip HTML tags from a string (e.g. a nested `<a>` inside a cell),
/// leaving the text. A `<` without a matching `>` drops the rest.
fn strip_tags(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_tag = false;
    for ch in text.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(ch),
            _ => {}
        }
    }
    out.trim().to_string()
}

/// Extract the text of every `<td>...</td>` cell in `html`, in document
/// order, with nested tags stripped.
fn table_cells(html: &str) -> Vec<String> {
    let mut cells = Vec::new();
    let mut rest = html;
    while let Some(td) = rest.find("<td") {
        let after_tag = match rest[td..].find('>') {
            Some(pos) => td + pos + 1,
            None => break,
        };
        let end = match rest[after_tag..].find("</td>") {
            Some(pos) => after_tag + pos,
            None => break,
        };
        cells.push(strip_tags(&rest[after_tag..end]));
        rest = &rest[end + "</td>".len()..];
    }
    cells
}

/// Parse a Distrowatch package table. Returns the version of `package`,
/// or None when it is not listed. Cells are paired (name, version)
/// inside each `<tr>` row, never across rows.
pub fn parse_distrowatch_page(html: &str, package: &str) -> Option<Candidate> {
    let mut rest = html;
    while let Some(tr) = rest.find("<tr") {
        let row_start = match rest[tr..].find('>') {
            Some(pos) => tr + pos + 1,
            None => break,
        };
        let row_end = match rest[row_start..].find("</tr>") {
            Some(pos) => row_start + pos,
            None => break,
        };
        let cells = table_cells(&rest[row_start..row_end]);
        if cells.len() >= 2 && cells[0] == package {
            let version = cells[1].trim().to_string();
            if version.is_empty() {
                return None;
            }
            return Some(Candidate {
                collector: "distrowatch",
                version,
                multi_source: false,
            });
        }
        rest = &rest[row_end + "</tr>".len()..];
    }
    None
}

pub struct DistrowatchCollector<'a> {
    http: &'a dyn HttpClient,
}

impl<'a> DistrowatchCollector<'a> {
    pub fn new(http: &'a dyn HttpClient) -> Self {
        DistrowatchCollector { http }
    }
}

impl<'a> Collector for DistrowatchCollector<'a> {
    fn name(&self) -> &'static str {
        "distrowatch"
    }

    fn latest_version(&self, package: &str) -> Result<Option<Candidate>, HttpError> {
        let body = self.http.get(DISTROWATCH_URL)?;
        Ok(parse_distrowatch_page(&body, package))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = r#"<html><body><table>
<tr><th>Package</th><th>Version</th></tr>
<tr><td class="pkg">foo</td><td>2.0</td></tr>
<tr><td class="pkg">bar</td><td>1.0</td></tr>
<tr><td class="pkg">baz</td><td>3.0~rc1</td></tr>
</table></body></html>"#;

    #[test]
    fn package_found() {
        let candidate = parse_distrowatch_page(FIXTURE, "foo").unwrap();
        assert_eq!(candidate.version, "2.0");
        assert_eq!(candidate.collector, "distrowatch");
        let candidate = parse_distrowatch_page(FIXTURE, "baz").unwrap();
        assert_eq!(candidate.version, "3.0~rc1");
    }

    #[test]
    fn package_missing() {
        assert!(parse_distrowatch_page(FIXTURE, "qux").is_none());
    }

    #[test]
    fn empty_table_is_none() {
        assert!(parse_distrowatch_page("<html></html>", "foo").is_none());
    }

    #[test]
    fn nested_link_in_version_cell_is_stripped() {
        // A nested `<a>` inside the version cell must not pollute the
        // version string.
        let html = r#"<table>
<tr><td class="pkg">foo</td><td><a href="/package/foo">2.0</a></td></tr>
</table>"#;
        let candidate = parse_distrowatch_page(html, "foo").unwrap();
        assert_eq!(candidate.version, "2.0");
    }

    #[test]
    fn stray_cell_in_another_row_does_not_misalign() {
        // A single-cell row (ad / header) before the package row must
        // not shift the pairing: cells pair inside a row, never across
        // the whole document.
        let html = r#"<table>
<tr><td colspan="2">advertisement</td></tr>
<tr><td class="pkg">foo</td><td>2.0</td></tr>
</table>"#;
        let candidate = parse_distrowatch_page(html, "foo").unwrap();
        assert_eq!(candidate.version, "2.0");
    }
}
