//! Generator for man pages and shell completions.
//!
//! Built only with `--features gen`; it shares the clap `Command` definition
//! with the shipped binary (see [`freshcrab::cli::cli_command`]) so the two can
//! never drift. Output is written under `{man,completions}` at the repo root
//! and is checked in; CI fails if a clap change leaves the committed assets
//! stale (the assets-drift job).
//!
//! Layout: one man page (`freshcrab.1`) — the CLI is a single command with
//! no subcommands, so there is nothing to walk. When subcommands land,
//! this grows a leaf walk like geectl's. Completions cover bash, zsh,
//! and fish only. Regeneration prunes stale pages: a `.1` file under
//! `man/` with no corresponding page is removed, so a renamed command
//! leaves no orphan page behind.
//!
//! Two geectl patterns are deliberately mirrored here. There is no
//! hidden-arg filter: freshcrab has no hidden args (verified by grep over
//! the CLI definition), so there is nothing to strip. There is no appended
//! `EXIT STATUS` section: freshcrab has no frozen exit-code contract, so
//! there is no frozen table to document.
//!
//! Usage: `cargo run --features gen --bin freshcrab-gen -- <out-dir>`
//! (defaults to `.` when run from the repo root).

#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use clap_complete::Shell;
use freshcrab::cli::cli_command;

/// Render one man page. The file name is derived from the title here, so
/// the call site never re-derives it: the page is `freshcrab.1`.
fn render_man(man_dir: &Path, cmd: clap::Command, title: &str) -> Result<(), Box<dyn Error>> {
    let mut rendered = Vec::new();
    clap_mangen::Man::new(cmd)
        .title(title)
        .section("1")
        .render(&mut rendered)?;
    let page = String::from_utf8(rendered)?;
    fs::write(man_dir.join(format!("{title}.1")), page)?;
    Ok(())
}

/// Remove `.1` files under `man_dir` with no page in `expected`, so a
/// renamed command leaves no orphan page behind. Other files are left alone.
fn prune_stale_man_pages(man_dir: &Path, expected: &HashSet<String>) -> Result<(), Box<dyn Error>> {
    for entry in fs::read_dir(man_dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.ends_with(".1") && !expected.contains(&name) {
            fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

fn run(root: PathBuf) -> Result<(), Box<dyn Error>> {
    let cmd = cli_command();

    let man_dir = root.join("man");
    fs::create_dir_all(&man_dir)?;
    // The root command is cloned once here: the same tree feeds the
    // completions below, so it cannot be moved into the render. The
    // derive version flows into the `.TH` header and VERSION section.
    render_man(&man_dir, cmd.clone(), "freshcrab")?;
    let page_count = 1;
    let mut expected: HashSet<String> = HashSet::with_capacity(page_count);
    expected.insert("freshcrab.1".to_string());
    prune_stale_man_pages(&man_dir, &expected)?;

    let completions_dir = root.join("completions");
    fs::create_dir_all(&completions_dir)?;
    let mut comp_cmd = cmd;
    for (shell, ext) in [
        (Shell::Bash, "bash"),
        (Shell::Zsh, "zsh"),
        (Shell::Fish, "fish"),
    ] {
        let path = completions_dir.join(format!("freshcrab.{ext}"));
        let mut file = fs::File::create(&path)?;
        clap_complete::generate(shell, &mut comp_cmd, "freshcrab", &mut file);
    }

    println!(
        "wrote {page_count} man page and 3 completions under {}",
        root.display()
    );
    Ok(())
}

fn main() {
    let root = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    if let Err(err) = run(root) {
        eprintln!("freshcrab-gen: {err}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn write_file(dir: &Path, name: &str) {
        fs::write(dir.join(name), "page").unwrap();
    }

    #[test]
    fn prune_removes_stale_man_pages_and_keeps_the_rest() {
        let tmp = tempfile::tempdir().unwrap();
        let man_dir = tmp.path().join("man");
        fs::create_dir_all(&man_dir).unwrap();
        write_file(&man_dir, "freshcrab.1");
        write_file(&man_dir, "freshcrab-old.1");
        write_file(&man_dir, "notes.txt");
        let expected: HashSet<String> = ["freshcrab.1"].iter().map(|s| s.to_string()).collect();
        prune_stale_man_pages(&man_dir, &expected).unwrap();
        assert!(!man_dir.join("freshcrab-old.1").exists());
        assert!(man_dir.join("freshcrab.1").exists());
        assert!(man_dir.join("notes.txt").exists());
    }

    #[test]
    fn render_man_writes_a_page_named_after_the_title() {
        let tmp = tempfile::tempdir().unwrap();
        let man_dir = tmp.path().join("man");
        fs::create_dir_all(&man_dir).unwrap();
        render_man(&man_dir, cli_command(), "freshcrab").unwrap();
        let page = fs::read_to_string(man_dir.join("freshcrab.1")).unwrap();
        assert!(page.contains("freshcrab"));
    }

    #[test]
    fn run_writes_one_page_and_three_completions_and_prunes_orphans_on_a_second_run() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        run(root.clone()).unwrap();
        assert_eq!(fs::read_dir(root.join("man")).unwrap().count(), 1);
        assert_eq!(fs::read_dir(root.join("completions")).unwrap().count(), 3);
        write_file(&root.join("man"), "freshcrab-old.1");
        run(root.clone()).unwrap();
        assert!(!root.join("man").join("freshcrab-old.1").exists());
        assert_eq!(fs::read_dir(root.join("man")).unwrap().count(), 1);
        assert_eq!(fs::read_dir(root.join("completions")).unwrap().count(), 3);
    }
}
