#!/usr/bin/env bash
#
# SDF JCE smoke test launcher.
#
# Runs the non-interactive SdfSmokeTest against a real SDF device, picking the
# vendor library/config from the environment or the HSM material directory, then
# prints the effective device-open strategy and the pass/fail summary.
#
# Usage:
#   scripts/sdf-smoke.sh [--] [extra SdfSmokeTest args]
#
# Environment:
#   SMOKE_VENDOR            Dysx | Shudun | SanSec            (default: Shudun)
#   SMOKE_LIBRARY_PATH      explicit native library path      (default: vendor/profile)
#   SMOKE_CONFIG_PATH       vendor config file or directory   (default: vendor material)
#   SMOKE_EXPECT_STRATEGY   assert SDF_OpenDeviceEx | SDF_OpenDeviceWithPath | SDF_OpenDevice
#   SMOKE_SM2_SIGN_INDEX    optional internal SM2 sign key index
#   SMOKE_RSA_SIGN_INDEX    optional internal RSA sign key index
#   SMOKE_SM4_KEY_INDEX     optional internal SM4 key index
#   SMOKE_PIN               PIN for internal keys
#   SMOKE_SKIP_BUILD=1      do not run 'mvn package'
#   SMOKE_MAVEN_OPTS        extra maven flags (default: -o -q)
#
# Exit code: 0 when every required check passed, non-zero otherwise.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    sed -n '2,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 0
fi

SMOKE_VENDOR="${SMOKE_VENDOR:-Shudun}"
SMOKE_LIBRARY_PATH="${SMOKE_LIBRARY_PATH:-}"
SMOKE_CONFIG_PATH="${SMOKE_CONFIG_PATH:-}"
SMOKE_EXPECT_STRATEGY="${SMOKE_EXPECT_STRATEGY:-}"

detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64) echo "x86_64" ;;
        aarch64|arm64) echo "aarch64" ;;
        *) echo "unknown" ;;
    esac
}

ARCH="$(detect_arch)"
OS_NAME="$(uname -s)"

# Vendor material defaults (only used when the caller did not provide a path).
# The bundled HSM material under HSM/ is Linux-only, so do not select it elsewhere;
# on other platforms the JAR profile (or SMOKE_LIBRARY_PATH) decides.
vendor_material() {
    if [[ "${OS_NAME}" != "Linux" ]]; then
        echo "|"
        return
    fi
    case "$(echo "${SMOKE_VENDOR}" | tr '[:upper:]' '[:lower:]')" in
        dysx)
            echo "${ROOT_DIR}/HSM/DYSX/2.0/${ARCH}/linux/libsdf.so|${ROOT_DIR}/HSM/DYSX/2.0/conf/cacipher.ini"
            ;;
        sansec)
            echo "${ROOT_DIR}/HSM/SanSec/1.3.87/${ARCH}/linux/libswsds.so|${ROOT_DIR}/HSM/SanSec/1.3.87/conf"
            ;;
        shudun)
            if [[ "${ARCH}" == "aarch64" && -f "${ROOT_DIR}/HSM/SHUDUN/SDF--aarch64-glibc2.31/libsdhsmcrypto.so" ]]; then
                echo "${ROOT_DIR}/HSM/SHUDUN/SDF--aarch64-glibc2.31/libsdhsmcrypto.so|${ROOT_DIR}/HSM/SHUDUN/SDF--aarch64-glibc2.31"
            elif [[ -f "${ROOT_DIR}/HSM/SHUDUN/1.4.2/${ARCH}/linux/libsdhsmcrypto.so" ]]; then
                echo "${ROOT_DIR}/HSM/SHUDUN/1.4.2/${ARCH}/linux/libsdhsmcrypto.so|${ROOT_DIR}/HSM/SHUDUN/1.4.2/conf"
            else
                # Fall back to the library bundled in the JAR for this platform.
                echo "|"
            fi
            ;;
        *)
            echo "|"
            ;;
    esac
}

IFS='|' read -r MATERIAL_LIB MATERIAL_CONF <<< "$(vendor_material)"
if [[ -z "${SMOKE_LIBRARY_PATH}" && -n "${MATERIAL_LIB}" && -f "${MATERIAL_LIB}" ]]; then
    SMOKE_LIBRARY_PATH="${MATERIAL_LIB}"
fi
if [[ -z "${SMOKE_CONFIG_PATH}" && -n "${MATERIAL_CONF}" && -e "${MATERIAL_CONF}" ]]; then
    SMOKE_CONFIG_PATH="${MATERIAL_CONF}"
fi

# Locate (or build) the runnable JAR. Newest first, so a stale artifact with an
# older version never shadows the freshly built one.
find_jar() {
    ls -1t target/liuzx-sdf-jce-*.jar 2>/dev/null \
        | grep -vE -- '-(sources|javadoc)\.jar$' \
        | head -n1 || true
}

JAR="$(find_jar)"
if [[ -z "${JAR}" && "${SMOKE_SKIP_BUILD:-0}" != "1" ]]; then
    echo "[smoke] building project (mvn ${SMOKE_MAVEN_OPTS:--o -q} package -DskipTests)"
    # shellcheck disable=SC2086
    mvn ${SMOKE_MAVEN_OPTS:--o -q} package -DskipTests
    JAR="$(find_jar)"
fi
if [[ -z "${JAR}" ]]; then
    echo "[smoke] ERROR: no liuzx-sdf-jce jar found under target/" >&2
    exit 2
fi
if [[ ! -d target/lib ]]; then
    echo "[smoke] ERROR: target/lib is missing; run 'mvn package -DskipTests'" >&2
    exit 2
fi

JAVA_OPTS=(-Dfile.encoding=UTF-8 "-Dliuzx.sdf.vendor=${SMOKE_VENDOR}")
[[ -n "${SMOKE_LIBRARY_PATH}" ]] && JAVA_OPTS+=("-Dliuzx.sdf.library.path=${SMOKE_LIBRARY_PATH}")
[[ -n "${SMOKE_CONFIG_PATH}" ]] && JAVA_OPTS+=("-Dliuzx.sdf.vendor-config.path=${SMOKE_CONFIG_PATH}")
[[ -n "${SMOKE_SM2_SIGN_INDEX:-}" ]] && JAVA_OPTS+=("-Dliuzx.sdf.smoke.sm2SignIndex=${SMOKE_SM2_SIGN_INDEX}")
[[ -n "${SMOKE_RSA_SIGN_INDEX:-}" ]] && JAVA_OPTS+=("-Dliuzx.sdf.smoke.rsaSignIndex=${SMOKE_RSA_SIGN_INDEX}")
[[ -n "${SMOKE_SM4_KEY_INDEX:-}" ]] && JAVA_OPTS+=("-Dliuzx.sdf.smoke.sm4KeyIndex=${SMOKE_SM4_KEY_INDEX}")
[[ -n "${SMOKE_PIN:-}" ]] && JAVA_OPTS+=("-Dliuzx.sdf.smoke.pin=${SMOKE_PIN}")

echo "[smoke] arch=${ARCH} os=${OS_NAME} vendor=${SMOKE_VENDOR}"
echo "[smoke] library=${SMOKE_LIBRARY_PATH:-<bundled/profile>}"
echo "[smoke] config=${SMOKE_CONFIG_PATH:-<none>}"
echo "[smoke] jar=${JAR}"
echo

OUTPUT_FILE="$(mktemp -t sdf-smoke.XXXXXX)"
trap 'rm -f "${OUTPUT_FILE}"' EXIT

set +e
java "${JAVA_OPTS[@]}" -cp "${JAR}:target/lib/*" org.liuzx.jce.demo.SdfSmokeTest "$@" 2>&1 | tee "${OUTPUT_FILE}"
STATUS=${PIPESTATUS[0]}
set -e

if [[ -n "${SMOKE_EXPECT_STRATEGY}" ]]; then
    if grep -q "strategy=${SMOKE_EXPECT_STRATEGY}" "${OUTPUT_FILE}"; then
        echo "[smoke] strategy assertion OK (${SMOKE_EXPECT_STRATEGY})"
    else
        echo "[smoke] strategy assertion FAILED: expected ${SMOKE_EXPECT_STRATEGY}" >&2
        STATUS=1
    fi
fi

if [[ "${STATUS}" -eq 0 ]]; then
    echo "[smoke] RESULT: PASS"
else
    echo "[smoke] RESULT: FAIL (exit ${STATUS})" >&2
fi
exit "${STATUS}"
