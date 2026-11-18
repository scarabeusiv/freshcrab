# Dockerfile for freshcrab.
#
# Two stages:
#   1. builder: build the static Rust binary (cargo build --release).
#   2. runtime: a minimal openSUSE image with the binary plus the distro
#      worker tools (rpmcrab, spec-cleaner, osc, bugwarden) installed with
#      zypper from the openSUSE repos. Nothing is built from source in the
#      runtime stage.
#
# The opensuse-packaging-skill docs are not a distro package; they are
# copied into the image at /usr/share/doc/freshcrab/opensuse-packaging-skill/
# (see docs/runbook.md). The skill sources live in the repo at
# skills/opensuse-packaging-skill/ (the docs only; no code).
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

# --- Stage 2: runtime ------------------------------------------------------
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

# The opensuse-packaging-skill docs (unpackaged upstream docs).
COPY skills/opensuse-packaging-skill /usr/share/doc/freshcrab/opensuse-packaging-skill

WORKDIR /app
COPY config.yaml /app/config.yaml

ENTRYPOINT ["freshcrab"]
CMD ["--config", "/app/config.yaml"]
