#!/usr/bin/env bash
# Builds vmdk_tree_compact in the ryzombuild_xplat_tools Docker image (Git Bash or Linux).
# Usage: ./build.sh [test]
#   test  also runs `cargo test` (host linux-gnu target) before the release builds.
set -euo pipefail
cd "$(dirname "$0")"
# Docker Desktop on Windows wants a Windows path for the bind mount; stop MSYS from rewriting container paths.
if repo=$(pwd -W 2>/dev/null); then :; else repo=$(pwd); fi
export MSYS_NO_PATHCONV=1

run() {
	echo "==> $*"
	docker run --rm -v ryzombuild_xplat_tools_cargo:/usr/local/cargo/registry -v ryzombuild_xplat_tools_xwin:/root/.cache/cargo-xwin -e CARGO_TARGET_DIR=/mnt/src/target --mount "type=bind,source=$repo,target=/mnt/src" --workdir /mnt/src ryzombuild_xplat_tools "$@"
}

case "${1:-}" in
	test) run cargo test ;;
	"") ;;
	*) echo "Unknown argument: $1 (expected: test)"; exit 2 ;;
esac
run cargo xwin build --release --target x86_64-pc-windows-msvc
run cargo build --release --target x86_64-unknown-linux-musl
echo OK
