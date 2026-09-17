#!/usr/bin/env bash
#
# Build a portable SDF JCE smoke-test bundle for a target OS/architecture.
#
# The bundle is self-contained: it carries the provider jar, its Maven runtime
# dependencies, the vendor native library, the editable device config and a generated
# run-smoke.sh. Copy the tarball to the machine that can reach the HSM, edit the
# device IP/port in conf/, then run ./run-smoke.sh.
#
# Usage:
#   scripts/pack-smoke.sh
#
# Environment:
#   PACK_VENDOR        Shudun | SanSec | Dysx     (default: Shudun)
#   PACK_ARCH          aarch64 | x86_64           (default: aarch64)
#   PACK_LIBRARY_PATH  explicit native library    (required for Dysx aarch64)
#   PACK_CONFIG_PATH   explicit config file/dir   (default: HSM material)
#   PACK_OUT_DIR       output directory           (default: repo target/)
#   PACK_SKIP_BUILD=1  do not run 'mvn package'
#   PACK_MAVEN_OPTS    extra maven flags          (default: -o -q)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

PACK_VENDOR="${PACK_VENDOR:-Shudun}"
PACK_ARCH="${PACK_ARCH:-aarch64}"
PACK_LIBRARY_PATH="${PACK_LIBRARY_PATH:-}"
PACK_CONFIG_PATH="${PACK_CONFIG_PATH:-}"
PACK_OUT_DIR="${PACK_OUT_DIR:-${ROOT_DIR}/target}"

case "${PACK_ARCH}" in
    aarch64|x86_64) ;;
    *) echo "[pack] ERROR: unsupported PACK_ARCH '${PACK_ARCH}' (aarch64|x86_64)" >&2; exit 2 ;;
esac

VENDOR_KEY="$(echo "${PACK_VENDOR}" | tr '[:upper:]' '[:lower:]')"
case "${VENDOR_KEY}" in
    shudun|sansec|dysx) ;;
    *) echo "[pack] ERROR: unsupported PACK_VENDOR '${PACK_VENDOR}' (Shudun|SanSec|Dysx)" >&2; exit 2 ;;
esac

find_jar() {
    ls -1t target/liuzx-sdf-jce-*.jar 2>/dev/null \
        | grep -vE -- '-(sources|javadoc)\.jar$' \
        | head -n1 || true
}

JAR="$(find_jar)"
if [[ -z "${JAR}" && "${PACK_SKIP_BUILD:-0}" != "1" ]]; then
    # shellcheck disable=SC2086
    mvn ${PACK_MAVEN_OPTS:--o -q} package -DskipTests
    JAR="$(find_jar)"
fi
if [[ -z "${JAR}" || ! -d target/lib ]]; then
    echo "[pack] ERROR: missing ${JAR:-jar} or target/lib; run 'mvn package -DskipTests'" >&2
    exit 2
fi

# Resolve vendor material. The native library is always copied into lib/ and passed
# explicitly, so the bundle does not depend on extracting the copy inside the jar.
LIB_SOURCE=""
CONF_SOURCE=""
# Directory for SDF_OpenDeviceWithPath (Shudun/SanSec) or file for SDF_OpenDeviceEx (Dysx).
CONF_KIND="dir"
# RSA struct ABI of the vendor (standard fixed-size or packed variable-size).
RSA_LAYOUT="standard"

case "${VENDOR_KEY}" in
    shudun)
        if [[ "${PACK_ARCH}" == "aarch64" ]]; then
            LIB_SOURCE="HSM/SHUDUN/SDF--aarch64-glibc2.31/libsdhsmcrypto.so"
            CONF_SOURCE="HSM/SHUDUN/SDF--aarch64-glibc2.31/sdhsm.ini"
        fi
        if [[ ! -f "${LIB_SOURCE:-/nonexistent}" && -f "HSM/SHUDUN/1.4.2/${PACK_ARCH}/linux/libsdhsmcrypto.so" ]]; then
            LIB_SOURCE="HSM/SHUDUN/1.4.2/${PACK_ARCH}/linux/libsdhsmcrypto.so"
            CONF_SOURCE="HSM/SHUDUN/1.4.2/conf/sdhsm.ini"
        fi
        RSA_LAYOUT="packed"
        CONF_KIND="dir"
        ;;
    sansec)
        LIB_SOURCE="HSM/SanSec/1.3.87/${PACK_ARCH}/linux/libswsds.so"
        CONF_SOURCE="HSM/SanSec/1.3.87/conf/swsds.ini"
        RSA_LAYOUT="standard"
        CONF_KIND="dir"
        ;;
    dysx)
        LIB_SOURCE="HSM/DYSX/2.0/${PACK_ARCH}/linux/libsdf.so"
        CONF_SOURCE="HSM/DYSX/2.0/conf/cacipher.ini"
        RSA_LAYOUT="standard"
        CONF_KIND="file"
        ;;
esac

if [[ -n "${PACK_LIBRARY_PATH}" ]]; then
    LIB_SOURCE="${PACK_LIBRARY_PATH}"
fi
if [[ -n "${PACK_CONFIG_PATH}" ]]; then
    CONF_SOURCE="${PACK_CONFIG_PATH}"
fi
if [[ -d "${CONF_SOURCE}" ]]; then
    CONF_KIND="dir"
fi

if [[ -z "${LIB_SOURCE}" || ! -f "${LIB_SOURCE}" ]]; then
    echo "[pack] ERROR: native library not found: '${LIB_SOURCE:-<none>}'" >&2
    echo "[pack] Hint: Dysx ${PACK_ARCH} is not in HSM/; set PACK_LIBRARY_PATH=/path/to/libsdf.so" >&2
    exit 2
fi
if [[ -z "${CONF_SOURCE}" || ! -e "${CONF_SOURCE}" ]]; then
    echo "[pack] ERROR: device config not found: '${CONF_SOURCE:-<none>}'" >&2
    echo "[pack] Hint: set PACK_CONFIG_PATH=/path/to/vendor.ini" >&2
    exit 2
fi

BUNDLE_NAME="liuzx-sdf-jce-smoke-${VENDOR_KEY}-${PACK_ARCH}"
STAGE="$(mktemp -d -t "${BUNDLE_NAME}.XXXXXX")"
trap 'rm -rf "${STAGE}"' EXIT

mkdir -p "${STAGE}/${BUNDLE_NAME}/lib" "${STAGE}/${BUNDLE_NAME}/conf"

cp "${JAR}" "${STAGE}/${BUNDLE_NAME}/"
cp target/lib/*.jar "${STAGE}/${BUNDLE_NAME}/lib/"

LIB_BASENAME="$(basename "${LIB_SOURCE}")"
cp "${LIB_SOURCE}" "${STAGE}/${BUNDLE_NAME}/lib/${LIB_BASENAME}"

# Device config: copy the file, or the directory contents, into conf/.
if [[ -d "${CONF_SOURCE}" ]]; then
    cp -R "${CONF_SOURCE}/." "${STAGE}/${BUNDLE_NAME}/conf/"
    CONF_HINT="conf/ (contains $(basename "${CONF_SOURCE}"))"
else
    cp "${CONF_SOURCE}" "${STAGE}/${BUNDLE_NAME}/conf/"
    CONF_HINT="conf/$(basename "${CONF_SOURCE}")"
fi

if [[ "${CONF_KIND}" == "dir" ]]; then
    CONF_PROPERTY="\${ROOT_DIR}/conf"
else
    CONF_PROPERTY="\${ROOT_DIR}/conf/$(basename "${CONF_SOURCE}")"
fi

# --- generated runner ---------------------------------------------------------
cat > "${STAGE}/${BUNDLE_NAME}/run-smoke.sh" <<EOF
#!/usr/bin/env bash
#
# Generated by scripts/pack-smoke.sh for ${PACK_VENDOR} / ${PACK_ARCH}.
# Edit the device IP/port in ${CONF_HINT}, then run this script on the HSM host.
set -euo pipefail

ROOT_DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
JAR="\$(ls -1t "\${ROOT_DIR}"/liuzx-sdf-jce-*.jar 2>/dev/null | grep -vE -- '-(sources|javadoc)\.jar\$' | head -n1 || true)"
if [[ -z "\${JAR}" || ! -d "\${ROOT_DIR}/lib" ]]; then
    echo "ERROR: bundle incomplete (jar or lib missing)" >&2
    exit 2
fi

JAVA_MAJOR="\$(java -version 2>&1 | head -n1 | sed -E 's/.*version "([0-9]+)(\.[0-9]+)?.*/\1/')"
if [[ "\${JAVA_MAJOR}" == "1" ]]; then JAVA_MAJOR=8; fi
if [[ ! "\${JAVA_MAJOR}" =~ ^[0-9]+\$ || "\${JAVA_MAJOR}" -lt 8 ]]; then
    echo "ERROR: JDK 8 or newer is required (found: \$(java -version 2>&1 | head -n1))" >&2
    exit 2
fi

JAVA_OPTS=(-Dfile.encoding=UTF-8 "-Dliuzx.sdf.vendor=${PACK_VENDOR}")
JAVA_OPTS+=("-Dliuzx.sdf.library.path=\${ROOT_DIR}/lib/${LIB_BASENAME}")
JAVA_OPTS+=("-Dliuzx.sdf.rsa-key-layout=${RSA_LAYOUT}")
JAVA_OPTS+=("-Dliuzx.sdf.vendor-config.path=${CONF_PROPERTY}")
[[ -n "\${SMOKE_SM2_SIGN_INDEX:-}" ]] && JAVA_OPTS+=("-Dliuzx.sdf.smoke.sm2SignIndex=\${SMOKE_SM2_SIGN_INDEX}")
[[ -n "\${SMOKE_RSA_SIGN_INDEX:-}" ]] && JAVA_OPTS+=("-Dliuzx.sdf.smoke.rsaSignIndex=\${SMOKE_RSA_SIGN_INDEX}")
[[ -n "\${SMOKE_SM4_KEY_INDEX:-}" ]] && JAVA_OPTS+=("-Dliuzx.sdf.smoke.sm4KeyIndex=\${SMOKE_SM4_KEY_INDEX}")
[[ -n "\${SMOKE_PIN:-}" ]] && JAVA_OPTS+=("-Dliuzx.sdf.smoke.pin=\${SMOKE_PIN}")

echo "[smoke] bundle vendor=${PACK_VENDOR} arch=${PACK_ARCH}"
echo "[smoke] library=lib/${LIB_BASENAME}  (rsaKeyLayout=${RSA_LAYOUT})"
echo "[smoke] config=${CONF_HINT} (edit device IP/port here)"
echo "[smoke] java: \$(java -version 2>&1 | head -n1)"
echo

# Run from conf/ so the vendor's standard SDF_OpenDevice can read ./<vendor>.ini.
cd "\${ROOT_DIR}/conf"
exec java "\${JAVA_OPTS[@]}" -cp "\${JAR}:\${ROOT_DIR}/lib/*" org.liuzx.jce.demo.SdfSmokeTest "\$@"
EOF
chmod +x "${STAGE}/${BUNDLE_NAME}/run-smoke.sh"

cat > "${STAGE}/${BUNDLE_NAME}/README.txt" <<EOF
SDF JCE smoke bundle
====================
vendor : ${PACK_VENDOR}
arch   : ${PACK_ARCH}
library: lib/${LIB_BASENAME} (rsaKeyLayout=${RSA_LAYOUT})
config : ${CONF_HINT}

1. Edit the device IP/port (and credentials, if any) in ${CONF_HINT}.
2. Ensure this host is Linux ${PACK_ARCH}, has JDK 8+, and can reach the HSM.
3. Run:
     ./run-smoke.sh
   Optional internal-key checks:
     SMOKE_PIN=<pin> SMOKE_SM2_SIGN_INDEX=<n> SMOKE_RSA_SIGN_INDEX=<n> \\
     SMOKE_SM4_KEY_INDEX=<n> ./run-smoke.sh

Expected on a healthy device: all required checks [PASS], exit code 0, and
strategy=SDF_OpenDevice (standard entry point). strategy=SDF_OpenDeviceWithPath or
SDF_OpenDeviceEx means the standard call failed and a path extension was used.

Note: a trailing "[FORCE] ... should close the device before exit" line is a one-time
compliance reminder that the vendor library writes from its SDF_OpenDevice path and
flushes late; it does not mean the device was left open. The runner closes the device
explicitly before exit and logs "SDF_CloseDevice failed" only if closing fails.

SECURITY: conf/ may contain device credentials/certificates. Do not share this
bundle or commit it. The PIN passed via SMOKE_PIN is visible in the java argv.
EOF

OUT="${PACK_OUT_DIR}/${BUNDLE_NAME}.tar.gz"
tar -C "${STAGE}" -czf "${OUT}" "${BUNDLE_NAME}"
if command -v shasum >/dev/null 2>&1; then
    SHA="$(shasum -a 256 "${OUT}" | awk '{print $1}')"
else
    SHA="$(sha256sum "${OUT}" | awk '{print $1}')"
fi

echo "[pack] created ${OUT}"
echo "[pack] sha256 ${SHA}"
echo "[pack] next: scp ${OUT} <user>@<hsm-host>:/tmp/ && tar -xzf /tmp/${BUNDLE_NAME}.tar.gz -C /opt && cd /opt/${BUNDLE_NAME}"
