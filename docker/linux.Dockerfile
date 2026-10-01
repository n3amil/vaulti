# Build environment for the Linux desktop app (.deb) and workspace checks.
# Debian bookworm (glibc 2.36) so the .deb runs on Debian 12+ / Ubuntu 22.10+.
FROM rust:1-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        libwebkit2gtk-4.1-dev \
        libxdo-dev \
        libssl-dev \
        librsvg2-dev \
        librsvg2-bin \
        pkg-config \
        file \
        nodejs \
        npm \
    && rm -rf /var/lib/apt/lists/*

RUN rustup component add clippy rustfmt \
    && npm install -g @tauri-apps/cli@2.12.1

ENV CARGO_TARGET_DIR=/target
WORKDIR /src
