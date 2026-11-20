#!/usr/bin/env bash
# Move every release-version surface to a new version in one step.
#
# Usage: scripts/bump-version.sh X.Y.Z
#
# Freshcrab is a single crate, so the version surfaces are exactly two:
# the [package] version in Cargo.toml and the freshcrab entry in
# Cargo.lock. A repo-wide grep for the current version confirms nothing
# else carries it (README.md and docs/ hold no version string), so there
# are no doc sentences or generated files to rewrite — unlike rpmcrab's
# script, there is no `make gen` and no version-consistency gate to run
# afterwards; the script ends with its own consistency check instead.
# Historical mentions are left alone.
set -euo pipefail

# No leading zeros: Cargo rejects them, and only after the tree is edited.
semver='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'

new="${1:-}"
if ! [[ "$new" =~ $semver ]]; then
  echo "usage: $0 X.Y.Z" >&2
  exit 2
fi

cd "$(git rev-parse --show-toplevel)"

# Never mix unrelated uncommitted edits into a bump: the workflow runs
# on a fresh checkout, so a dirty tree here means a human ran this by
# hand with work in progress.
if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "refusing to bump with uncommitted changes in the tree" >&2
  exit 1
fi

old=$(sed -n '/^\[package\]/,/^\[/s/^version = "\(.*\)"$/\1/p' Cargo.toml | head -1)
if ! [[ "$old" =~ $semver ]]; then
  echo "no X.Y.Z [package] version found in Cargo.toml (got '$old')" >&2
  exit 1
fi

# Numeric X.Y.Z comparison (10# keeps leading zeros decimal); portable,
# unlike sort -V.
IFS=. read -r o1 o2 o3 <<<"$old"
IFS=. read -r n1 n2 n3 <<<"$new"
if ((10#$n1 != 10#$o1)); then
  forward=$((10#$n1 > 10#$o1))
elif ((10#$n2 != 10#$o2)); then
  forward=$((10#$n2 > 10#$o2))
else
  forward=$((10#$n3 > 10#$o3))
fi
if [ "$forward" -ne 1 ]; then
  echo "refusing to move $old to $new: the version only moves forward" >&2
  echo "(a half-applied earlier run is undone with: git checkout -- .)" >&2
  exit 1
fi

# In-place edit without GNU sed -i; `cat >` keeps the file's mode.
subst() { # sed-script file
  local tmp
  tmp=$(mktemp)
  # Expands now deliberately: each subst() call traps its own temp
  # file, so a failure mid-call cleans it up.
  # shellcheck disable=SC2064
  trap "rm -f '$tmp'" EXIT
  sed "$1" "$2" >"$tmp"
  cat "$tmp" >"$2"
  rm -f "$tmp"
}

old_re=${old//./\\.}

subst "/^\[package\]/,/^\[/s/^version = \"$old_re\"$/version = \"$new\"/" Cargo.toml

# -p freshcrab updates only this crate's lock entry; dependencies stay
# put. Anything more (a newer cargo rewriting the lock format, say)
# does not belong in a version bump.
cargo update -p freshcrab --quiet
if [ "$(git diff --numstat -- Cargo.lock | cut -f1-2)" != "$(printf '1\t1')" ]; then
  echo "Cargo.lock changed beyond the single freshcrab version line:" >&2
  git diff -- Cargo.lock >&2
  exit 1
fi

# Consistency check (freshcrab has no separate gate script): the new
# version is the only version in Cargo.toml's [package] table, the lock
# carries it for the freshcrab package, and the old version is gone
# from the manifest.
manifest=$(sed -n '/^\[package\]/,/^\[/s/^version = "\(.*\)"$/\1/p' Cargo.toml | head -1)
if [ "$manifest" != "$new" ]; then
  echo "Cargo.toml [package] version is '$manifest', expected '$new'" >&2
  exit 1
fi
lock=$(sed -n '/^name = "freshcrab"/,/^version = /s/^version = "\(.*\)"$/\1/p' Cargo.lock | head -1)
if [ "$lock" != "$new" ]; then
  echo "Cargo.lock freshcrab version is '$lock', expected '$new'" >&2
  exit 1
fi
if sed -n '/^\[package\]/,/^\[/p' Cargo.toml | grep -q "version = \"$old_re\""; then
  echo "old version $old still present in Cargo.toml" >&2
  exit 1
fi
