# Dockerfile for freshcrab.
#
# Three stages:
#   1. builder: build the static Rust binary (cargo build --release).
#   2. skill: fetch the opensuse-packaging-skill docs at a tagged release.
#   3. runtime: a minimal openSUSE image with the binary plus the distro
#      worker tools (rpmcrab, spec-cleaner, osc, bugwarden) installed with
#      zypper from the openSUSE repos. Nothing is built from source in the
#      runtime stage.
#
# The opensuse-packaging-skill docs are not a distro package and are not
# vendored in this repo; they are fetched at build time from the tagged
# release of openSUSE/openSUSE-packaging-skill (see the skill stage) and
# copied into the image at /usr/share/doc/freshcrab/opensuse-packaging-skill/
# (see docs/runbook.md). The tag is bumped by the weekly skill-tag-bump
# workflow: Dependabot's docker ecosystem only tracks FROM image tags, not
# a git-clone branch, so it cannot bump this tag. The commit SHA is
# pinned alongside the tag and the build verifies the clone matches it,
# so a mutable tag that moves fails the build instead of silently
# changing what the image contains.
#
# No secrets are baked into the image. OBS credentials (oscrc) and the
# GitHub token are injected at run time via environment variables or a
# mounted file.

# --- Stage 1: build the static binary -------------------------------------
FROM registry.opensuse.org/opensuse/tumbleweed:latest AS builder

RUN zypper --non-interactive refresh && \
    zypper --non-interactive install --no-recommends cargo rust \
    && zypper clean --all

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

# --- Stage 2: fetch the packaging skill ------------------------------------
# Shallow-clone the tagged release; only the nested skill dir
# (skills/opensuse-packaging/ inside the collection repo) is kept. The
# clone and its .git are discarded in this stage, so the runtime image
# carries just the skill docs.
FROM registry.opensuse.org/opensuse/tumbleweed:latest AS skill

ARG PACKAGING_SKILL_TAG=v3.24.3
# The commit the tag points to, pinned alongside it and verified below.
ARG PACKAGING_SKILL_SHA=57f5e9ddd0eacecc9bf21eb6dc60ac99acf21d64

RUN zypper --non-interactive refresh && \
    zypper --non-interactive install --no-recommends git \
    && zypper clean --all && \
    git clone --depth 1 --branch "${PACKAGING_SKILL_TAG}" \
        https://github.com/openSUSE/openSUSE-packaging-skill /tmp/packaging-skill && \
    actual_sha=$(git -C /tmp/packaging-skill rev-parse HEAD); \
    if [ "${actual_sha}" != "${PACKAGING_SKILL_SHA}" ]; then \
        echo "skill tag ${PACKAGING_SKILL_TAG} resolved to ${actual_sha}, expected ${PACKAGING_SKILL_SHA} (tag moved? bump it via the skill-tag-bump workflow)" >&2; \
        exit 1; \
    fi; \
    cp -r /tmp/packaging-skill/skills/opensuse-packaging /skill && \
    rm -rf /tmp/packaging-skill

# --- Stage 3: runtime ------------------------------------------------------
FROM registry.opensuse.org/opensuse/tumbleweed:latest

LABEL org.opencontainers.image.title="freshcrab"
LABEL org.opencontainers.image.description="Automatic updater and validator for openSUSE Tumbleweed/Factory"

# Worker tooling: the distro versions, from the openSUSE repos.
RUN zypper --non-interactive refresh && \
    zypper --non-interactive install --no-recommends \
        rpmcrab spec-cleaner osc bugwarden \
    && zypper clean --all

# The binary.
COPY --from=builder /src/target/release/freshcrab /usr/local/bin/freshcrab

# The opensuse-packaging-skill docs (fetched at build time, see the skill stage).
COPY --from=skill /skill /usr/share/doc/freshcrab/opensuse-packaging-skill

WORKDIR /app
COPY config.yaml /app/config.yaml

ENTRYPOINT ["freshcrab"]
CMD ["--config", "/app/config.yaml"]
