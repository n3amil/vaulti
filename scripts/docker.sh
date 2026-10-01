#!/usr/bin/env bash
# Build/test inside Docker so nothing needs installing on the host.
#
#   scripts/docker.sh deb     build the Linux .deb into dist/
#   scripts/docker.sh check   fmt + clippy + tests for the whole workspace
#   scripts/docker.sh shell   interactive shell in the build container
#   scripts/docker.sh ui-test click through the UI in headless Chromium (fake backend)
#   scripts/docker.sh extension build the browser extension into extension/dist/
#   scripts/docker.sh extension-test  pair the CLI with the Chrome extension and fill a login (network)
set -euo pipefail
cd "$(dirname "$0")/.."

IMAGE=vaulti-build-linux

run() {
    docker build -q -t "$IMAGE" -f docker/linux.Dockerfile docker >/dev/null
    local tty=()
    [ -t 0 ] && tty=(-it)
    docker run --rm "${tty[@]}" \
        -v "$PWD":/src \
        -v vaulti-cargo-registry:/usr/local/cargo/registry \
        -v vaulti-target-linux:/target \
        -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
        "$IMAGE" bash -c "$1"
}

# Files the container creates in the bind mount belong to root; hand them back.
CHOWN='chown -R "$HOST_UID:$HOST_GID" /src/dist /src/app/src-tauri/gen /src/app/src-tauri/icons 2>/dev/null || true'

# App icons are generated from app/icon.png (1024px) once and committed.
ICONS='if [ ! -f /src/app/src-tauri/icons/icon.png ]; then
        (cd /src/app && tauri icon icon.png -o src-tauri/icons)
    fi'

case "${1:-}" in
    deb)
        mkdir -p dist
        run "set -e
            $ICONS
            cd /src/app
            tauri build --bundles deb
            cp /target/release/bundle/deb/*.deb /src/dist/
            $CHOWN
            ls -lh /src/dist/*.deb"
        ;;
    extension)
        docker build -q -t vaulti-build-wasm -f docker/wasm.Dockerfile docker >/dev/null
        docker run --rm -v "$PWD":/src -v vaulti-cargo-registry:/usr/local/cargo/registry \
            -v vaulti-target-wasm:/target -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" vaulti-build-wasm bash -c '
            set -e
            cargo build -p vaulti-wasm --target wasm32-unknown-unknown --release
            rm -rf extension/pkg
            wasm-bindgen --target web --no-typescript --out-dir extension/pkg \
                /target/wasm32-unknown-unknown/release/vaulti_wasm.wasm
            wasm-opt -Oz --enable-bulk-memory --enable-nontrapping-float-to-int --enable-sign-ext \
                extension/pkg/vaulti_wasm_bg.wasm -o extension/pkg/vaulti_wasm_bg.wasm
            node extension/build.mjs
            chown -R "$HOST_UID:$HOST_GID" extension/pkg extension/dist'
        ;;
    extension-test)
        "$0" extension
        run "cargo build --release -p vaulti-cli && mkdir -p /src/extension/dist/bin && cp /target/release/vaulti /src/extension/dist/bin/ && chown -R \"\$HOST_UID:\$HOST_GID\" /src/extension/dist"
        # Test-only: let the harness find the test page's tab (a real popup gets it via activeTab).
        exec docker run --rm -v "$PWD/extension/dist/chrome:/ext-src:ro" -v "$PWD/extension/dist/bin:/bin-vaulti:ro" \
            -v "$PWD/extension/test:/src:ro" mcr.microsoft.com/playwright:v1.55.0-noble sh -c \
            'cp -r /ext-src /ext && node -e "const f=\"/ext/manifest.json\",m=require(f);m.permissions.push(\"tabs\");m.host_permissions=[\"http://localhost:8097/*\"];require(\"fs\").writeFileSync(f,JSON.stringify(m))" &&
             cp -r /src /t && cd /t && npm i -s --no-save playwright@1.55.0 >/dev/null 2>&1 && timeout 300 node e2e.mjs'
        ;;
    ui-test)
        exec docker run --rm -v "$PWD/app/ui:/ui:ro" -v "$PWD/app/ui-test:/src:ro" \
            mcr.microsoft.com/playwright:v1.55.0-noble sh -c \
            'cp -r /src /t && cd /t && npm i -s --no-save playwright@1.55.0 >/dev/null 2>&1 && node smoke.mjs'
        ;;
    check)
        run "set -e
            $ICONS
            cargo fmt --all --check
            cargo clippy --workspace --all-targets -- -D warnings
            cargo test --workspace
            $CHOWN"
        ;;
    shell)
        run "bash"
        ;;
    *)
        sed -n '2,7p' "$0"
        exit 1
        ;;
esac
