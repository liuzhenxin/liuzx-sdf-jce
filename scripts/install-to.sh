#!/usr/bin/env bash
#
# Install the built liuzx-sdf-jce artifact into a remote Maven local repository over
# SSH, so a downstream build (KMC/CA) on that host can resolve it offline.
#
# Usage:
#   scripts/install-to.sh <user@host> [remote-m2-root]
#
# Examples:
#   scripts/install-to.sh root@ccsec-ca-km-prd-05
#   scripts/install-to.sh build@ca-builder /opt/maven-repo
#
# Environment:
#   INSTALL_TO_SKIP_BUILD=1   do not run 'mvn install' first
#   INSTALL_TO_MAVEN_OPTS     extra maven flags (default: -o -q)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 0
fi

TARGET="${1:-}"
REMOTE_M2="${2:-}"
if [[ -z "${TARGET}" ]]; then
    echo "usage: $0 <user@host> [remote-m2-root]" >&2
    exit 2
fi

VERSION="$(sed -n 's/.*<version>\(.*\)<\/version>.*/\1/p' pom.xml | head -n1)"
if [[ -z "${VERSION}" ]]; then
    echo "[install-to] ERROR: cannot read project version from pom.xml" >&2
    exit 2
fi

LOCAL_M2="${HOME}/.m2/repository/org/liuzx/liuzx-sdf-jce/${VERSION}"
JAR_NAME="liuzx-sdf-jce-${VERSION}.jar"

if [[ "${INSTALL_TO_SKIP_BUILD:-0}" != "1" || ! -f "${LOCAL_M2}/${JAR_NAME}" ]]; then
    echo "[install-to] building and installing ${VERSION} into the local repository"
    # shellcheck disable=SC2086
    mvn ${INSTALL_TO_MAVEN_OPTS:--o -q} install -DskipTests
fi
if [[ ! -f "${LOCAL_M2}/${JAR_NAME}" ]]; then
    echo "[install-to] ERROR: ${LOCAL_M2}/${JAR_NAME} not found; run 'mvn install -DskipTests'" >&2
    exit 2
fi

REMOTE_HOME="$(ssh "${TARGET}" 'printf %s "$HOME"')"
REMOTE_BASE="${REMOTE_M2:-${REMOTE_HOME}/.m2/repository}"
REMOTE_DIR="${REMOTE_BASE}/org/liuzx/liuzx-sdf-jce/${VERSION}"

echo "[install-to] version=${VERSION}"
echo "[install-to] local =${LOCAL_M2}"
echo "[install-to] remote=${TARGET}:${REMOTE_DIR}"

ssh "${TARGET}" "mkdir -p \"${REMOTE_DIR}\""
scp -q -r "${LOCAL_M2}/." "${TARGET}:${REMOTE_DIR}/"

echo "[install-to] verifying remote artifact"
ssh "${TARGET}" "ls -l \"${REMOTE_DIR}/${JAR_NAME}\" \"${REMOTE_DIR}/liuzx-sdf-jce-${VERSION}.pom\""

echo "[install-to] done: ${TARGET} can now build against org.liuzx:liuzx-sdf-jce:${VERSION}"
