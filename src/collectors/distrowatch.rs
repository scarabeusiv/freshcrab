//! Distrowatch collector (secondary signal only).
//!
//! Distrowatch lists package versions per distribution in an HTML table.
//! It is a secondary signal: a Distrowatch-only candidate never confirms
//! on its own (see `crate::collectors`). The parser extracts `<td>` cell
//! text in document order and pairs them (package name, version). No
//! regex crate is used; the scan is a plain string search.

use crate::collectors::{Candidate, Collector};
use crate::http::{HttpClient, HttpError};

pub const DISTROWATCH_URL: &str = "https://distrowatch.com/table.php?distribution=opensuse";

/// Extract the text of every `<td>...</td>` cell, in document order.
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
        let text = rest[after_tag..end].trim().to_string();
        cells.push(text);
        rest = &rest[end + "</td>".len()..];
    }
    cells
}

/// Parse a Distrowatch package table. Returns the version of `package`,
/// or None when it is not listed. Cells are paired (name, version).
pub fn parse_distrowatch_page(html: &str, package: &str) -> Option<Candidate> {
    let cells = table_cells(html);
    for pair in cells.as_chunks::<2>().0 {
        if pair[0] == package {
            let version = pair[1].trim().to_string();
            if version.is_empty() {
                return None;
            }
            return Some(Candidate {
                collector: "distrowatch",
                version,
                multi_source: false,
            });
        }
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
}
