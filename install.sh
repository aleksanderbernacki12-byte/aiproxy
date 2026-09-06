#!/usr/bin/env bash
# Installer for aiproxy.
#
# Downloads the prebuilt binary for your OS/architecture from the latest
# GitHub Release and installs it onto your PATH. If that download fails
# (or curl is unavailable) and this script happens to be running from
# inside a cloned copy of the repo with a Go toolchain on PATH, it falls
# back to building aiproxy from source instead.
set -euo pipefail

REPO="aleksanderbernacki12-byte/aiproxy"
BINARY_NAME="aiproxy"
INSTALL_DIR="${AIPROXY_INSTALL_DIR:-/usr/local/bin}"

log() { printf '%s\n' "$*"; }
die() {
	printf 'error: %s\n' "$*" >&2
	exit 1
}

detect_os() {
	case "$(uname -s)" in
	Darwin) echo "darwin" ;;
	Linux) echo "linux" ;;
	*) die "unsupported OS: $(uname -s) (only Darwin and Linux are supported)" ;;
	esac
}

detect_arch() {
	case "$(uname -m)" in
	arm64 | aarch64) echo "arm64" ;;
	x86_64 | amd64) echo "amd64" ;;
	*) die "unsupported architecture: $(uname -m) (only amd64 and arm64 are supported)" ;;
	esac
}

OS="$(detect_os)"
ARCH="$(detect_arch)"
ASSET_NAME="${BINARY_NAME}-${OS}-${ARCH}"
RELEASE_URL="https://github.com/${REPO}/releases/latest/download/${ASSET_NAME}"

log "aiproxy installer"
log "  OS:            ${OS}"
log "  architecture:  ${ARCH}"
log "  release asset: ${ASSET_NAME}"
log ""

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "${WORK_DIR}"' EXIT

# Tries to download the prebuilt release binary. Returns non-zero (never
# exits the script) on any failure, so the caller can fall back.
download_release_binary() {
	command -v curl >/dev/null 2>&1 || return 1
	log "downloading ${ASSET_NAME} from the latest GitHub release..."
	curl -fsSL --retry 3 -o "${WORK_DIR}/${BINARY_NAME}" "${RELEASE_URL}"
}

# Tries to build from source, only possible when this script is sitting
# inside a checked-out copy of the repo (as opposed to running via
# `curl | sh`, where there is no source to build). Returns non-zero on
# any failure, never exits the script.
build_from_source() {
	local self="${BASH_SOURCE[0]:-}"
	[ -n "${self}" ] || return 1
	local script_dir
	script_dir="$(cd "$(dirname "${self}")" && pwd)"
	[ -f "${script_dir}/go.mod" ] || return 1
	command -v go >/dev/null 2>&1 || return 1

	log "building ${BINARY_NAME} from source for ${OS}/${ARCH} instead..."
	(cd "${script_dir}" && GOOS="${OS}" GOARCH="${ARCH}" go build -o "${WORK_DIR}/${BINARY_NAME}" "./cmd/${BINARY_NAME}")
}

if ! download_release_binary; then
	log "release download unavailable, falling back to a local build"
	build_from_source ||
		die "could not download a release binary for ${ASSET_NAME}, and no local source + Go toolchain was found to build from instead"
fi

mkdir -p "${INSTALL_DIR}" 2>/dev/null || true
if [ -w "${INSTALL_DIR}" ]; then
	SUDO=""
else
	SUDO="sudo"
	log "elevated permissions needed to write to ${INSTALL_DIR}"
fi

${SUDO} mkdir -p "${INSTALL_DIR}"
${SUDO} install -m 0755 "${WORK_DIR}/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"

log "installed ${BINARY_NAME} to ${INSTALL_DIR}/${BINARY_NAME}"

case ":${PATH}:" in
*":${INSTALL_DIR}:"*) ;;
*) log "warning: ${INSTALL_DIR} is not on your PATH — add it to use '${BINARY_NAME}' directly" ;;
esac

log ""
log "run '${BINARY_NAME} help' to get started."
