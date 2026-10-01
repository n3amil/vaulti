# Build environment for the browser extension (Rust → WebAssembly).
FROM rust:1-bookworm

# clang + lld: ring (TLS, used by iroh) has C/asm parts that need clang for wasm32.
RUN apt-get update && apt-get install -y --no-install-recommends clang lld nodejs npm zip binaryen \
    && rm -rf /var/lib/apt/lists/*

RUN rustup target add wasm32-unknown-unknown

# Must match the wasm-bindgen version in Cargo.lock.
ARG WASM_BINDGEN=0.2.129
RUN cargo install --locked wasm-bindgen-cli --version "$WASM_BINDGEN"

ENV CARGO_TARGET_DIR=/target
WORKDIR /src
