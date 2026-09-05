#!/usr/bin/env bash
# Installer for aiproxy.
#
# Today there are no published GitHub Releases yet, so this script builds
# aiproxy from source (requires a local Go toolchain) and installs the
# resulting binary into a directory on your PATH. It already detects OS
# and CPU architecture and derives the release asset name/URL that a
# future `curl | sh` install (see README.md) will fetch directly instead
# of building locally.
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
log "  (future download URL: ${RELEASE_URL})"
log ""

command -v go >/dev/null 2>&1 ||
	die "go is required to build aiproxy locally (no release binaries are published yet)"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -f "${SCRIPT_DIR}/go.mod" ] || die "go.mod not found next to install.sh (${SCRIPT_DIR}) — run this script from the aiproxy repo"

BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "${BUILD_DIR}"' EXIT

log "building ${BINARY_NAME} from source for ${OS}/${ARCH}..."
(cd "${SCRIPT_DIR}" && GOOS="${OS}" GOARCH="${ARCH}" go build -o "${BUILD_DIR}/${BINARY_NAME}" "./cmd/${BINARY_NAME}")

mkdir -p "${INSTALL_DIR}" 2>/dev/null || true
if [ -w "${INSTALL_DIR}" ]; then
	SUDO=""
else
	SUDO="sudo"
	log "elevated permissions needed to write to ${INSTALL_DIR}"
fi

${SUDO} mkdir -p "${INSTALL_DIR}"
${SUDO} install -m 0755 "${BUILD_DIR}/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"

log "installed ${BINARY_NAME} to ${INSTALL_DIR}/${BINARY_NAME}"

case ":${PATH}:" in
*":${INSTALL_DIR}:"*) ;;
*) log "warning: ${INSTALL_DIR} is not on your PATH — add it to use '${BINARY_NAME}' directly" ;;
esac

log ""
log "run '${BINARY_NAME} help' to get started."
