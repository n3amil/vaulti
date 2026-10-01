#!/usr/bin/env bash
# Build/test inside Docker so nothing needs installing on the host.
#
#   scripts/docker.sh deb     build the Linux .deb into dist/
#   scripts/docker.sh check   fmt + clippy + tests for the whole workspace
#   scripts/docker.sh shell   interactive shell in the build container
set -euo pipefail
cd "$(dirname "$0")/.."

IMAGE=vaulti-build-linux
docker build -q -t "$IMAGE" -f docker/linux.Dockerfile docker >/dev/null

run() {
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

# App icons are generated from app/icon.svg once and committed.
ICONS='if [ ! -f /src/app/src-tauri/icons/icon.png ]; then
        rsvg-convert -w 1024 -h 1024 /src/app/icon.svg -o /tmp/icon.png
        (cd /src/app && tauri icon /tmp/icon.png -o src-tauri/icons)
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
