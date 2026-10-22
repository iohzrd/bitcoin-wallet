#!/usr/bin/env bash
# Builds the wallet for arm64 handhelds and boards, in a container of the Debian their images
# run (packaging/aarch64), to target/aarch64/aarch64-unknown-linux-gnu/release/wallet. Further
# arguments go to `cargo build`, such as `--features security-key`.

set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
image="wallet-build-aarch64"

docker build --quiet --tag "${image}" "${root}/packaging/aarch64" >/dev/null
# A target directory of its own, as the container's toolchain is not the host's, and a cargo
# home kept between builds for the registry.
mkdir -p "${root}/target/aarch64/cargo"
docker run --rm \
    --user "$(id -u):$(id -g)" \
    --env HOME=/tmp \
    --env CARGO_HOME=/src/target/aarch64/cargo \
    --env CARGO_TARGET_DIR=/src/target/aarch64 \
    --volume "${root}:/src" \
    --workdir /src \
    "${image}" \
    cargo build --release --locked --package wallet --target aarch64-unknown-linux-gnu "$@"

echo "${root}/target/aarch64/aarch64-unknown-linux-gnu/release/wallet"
