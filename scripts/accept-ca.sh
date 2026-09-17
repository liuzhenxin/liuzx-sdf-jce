#!/usr/bin/env bash
#
# CA SDF signer acceptance probe.
#
# Exercises the exact SDF signer path CA uses (SdfSignerFactory -> SDFSessionManager
# -> hardware key) through the CA signer-test endpoint, optionally issues a certificate
# and generates a CRL, and greps the CA logs for SDF/device errors.
#
# Usage:
#   CA_TOKEN=<token> CA_SIGNER_KEY_INDEX=11 CA_SIGNER_PIN=<pin> scripts/accept-ca.sh
#
# Environment:
#   CA_BASE_URL            default http://127.0.0.1:4443
#   CA_CONTEXT_PATH        default /api
#   CA_TOKEN               bearer token (required for API checks; without it only logs run)
#   CA_SIGNER_ALGO         default RSA_SHA256
#   CA_SIGNER_KEY_INDEX    default 11
#   CA_SIGNER_PIN          PIN for the SDF internal key
#   CA_ISSUE=1             also call /v1/certs/issue
#   CA_ROOT_ID             root CA id (needed for issue/CRL)
#   CA_PROFILE_ID          certificate profile id (needed for issue)
#   CA_SUBJECT             default C=CN,O=LiuZX,CN=ca-acceptance
#   CA_NOT_BEFORE / CA_NOT_AFTER   optional yyyyMMddHHmmss
#   CA_ROOT_CERT_FILE      root cert PEM, used by 'openssl verify' when available
#   CA_CRL=1               also call /v1/crls/gen
#   CA_CONTAINER           optional docker container for log assertions
#   CA_LOG_FILE            optional CA log file for log assertions
#
# Exit code: 0 = all executed checks passed, 1 = a check failed, 2 = usage error.
#
set -euo pipefail

CA_BASE_URL="${CA_BASE_URL:-http://127.0.0.1:4443}"
CA_CONTEXT_PATH="${CA_CONTEXT_PATH:-/api}"
CA_TOKEN="${CA_TOKEN:-}"
CA_SIGNER_ALGO="${CA_SIGNER_ALGO:-RSA_SHA256}"
CA_SIGNER_KEY_INDEX="${CA_SIGNER_KEY_INDEX:-11}"
CA_SIGNER_PIN="${CA_SIGNER_PIN:-}"
CA_ISSUE="${CA_ISSUE:-0}"
CA_ROOT_ID="${CA_ROOT_ID:-}"
CA_PROFILE_ID="${CA_PROFILE_ID:-}"
CA_SUBJECT="${CA_SUBJECT:-C=CN,O=LiuZX,CN=ca-acceptance}"
CA_NOT_BEFORE="${CA_NOT_BEFORE:-}"
CA_NOT_AFTER="${CA_NOT_AFTER:-}"
CA_ROOT_CERT_FILE="${CA_ROOT_CERT_FILE:-}"
CA_CRL="${CA_CRL:-0}"
CA_CONTAINER="${CA_CONTAINER:-}"
CA_LOG_FILE="${CA_LOG_FILE:-}"

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    sed -n '2,32p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 0
fi

BASE="${CA_BASE_URL%/}${CA_CONTEXT_PATH}"
FAILED=0
TMP_DIR="$(mktemp -d -t ca-accept.XXXXXX)"
trap 'rm -rf "${TMP_DIR}"' EXIT

pass() { echo "[PASS] $*"; }
fail() { echo "[FAIL] $*"; FAILED=1; }
skip() { echo "[SKIP] $*"; }

json_escape() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

post_json() {
    # $1 = path, $2 = json body
    curl -sS --max-time 60 -X POST \
        -H "Authorization: Bearer ${CA_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "$2" "${BASE}$1" 2>/dev/null || true
}

echo "[accept-ca] base=${BASE}"

# ---- 1) SDF signer test (CA's real code path) --------------------------------
if [[ -z "${CA_TOKEN}" ]]; then
    skip "signer test (set CA_TOKEN to enable; ${BASE}/v1/signers/test)"
else
    CONF_JSON="{\"keyIndex\":${CA_SIGNER_KEY_INDEX},\"algo\":\"${CA_SIGNER_ALGO}\"}"
    BODY="{\"co\":{\"type\":\"SDF\",\"conf\":\"$(json_escape "${CONF_JSON}")\",\"password\":\"$(json_escape "${CA_SIGNER_PIN}")\"}}"
    SIGNER_BODY="$(post_json "/v1/signers/test" "${BODY}")"
    echo "[accept-ca] signer-test: ${SIGNER_BODY}"
    if [[ "${SIGNER_BODY}" != *'"code":"OK"'* ]]; then
        fail "signer test request failed"
    elif [[ "${SIGNER_BODY}" == *'"passed":false'* || "${SIGNER_BODY}" != *'"passed":true'* ]]; then
        fail "SDF signer test not passed (keyIndex=${CA_SIGNER_KEY_INDEX}, algo=${CA_SIGNER_ALGO})"
    else
        pass "SDF signer test passed (keyIndex=${CA_SIGNER_KEY_INDEX}, algo=${CA_SIGNER_ALGO})"
    fi
fi

# ---- 2) Issue a certificate and verify (optional) ----------------------------
if [[ "${CA_ISSUE}" == "1" ]]; then
    if [[ -z "${CA_TOKEN}" || -z "${CA_ROOT_ID}" || -z "${CA_PROFILE_ID}" ]]; then
        skip "issue (CA_ISSUE=1 requires CA_TOKEN, CA_ROOT_ID, CA_PROFILE_ID)"
    else
        BODY="{\"co\":{\"rootId\":${CA_ROOT_ID},\"profileId\":${CA_PROFILE_ID},\"subject\":\"$(json_escape "${CA_SUBJECT}")\""
        [[ -n "${CA_NOT_BEFORE}" ]] && BODY+=",\"notBefore\":\"${CA_NOT_BEFORE}\""
        [[ -n "${CA_NOT_AFTER}" ]] && BODY+=",\"notAfter\":\"${CA_NOT_AFTER}\""
        BODY+="}}"
        ISSUE_BODY="$(post_json "/v1/certs/issue" "${BODY}")"
        echo "[accept-ca] issue: ${ISSUE_BODY}"
        if [[ "${ISSUE_BODY}" != *'"code":"OK"'* ]]; then
            fail "certificate issue failed (rootId=${CA_ROOT_ID}, profileId=${CA_PROFILE_ID})"
        else
            pass "certificate issued"
            if command -v jq >/dev/null 2>&1 && command -v openssl >/dev/null 2>&1 \
                    && [[ -n "${CA_ROOT_CERT_FILE}" && -f "${CA_ROOT_CERT_FILE}" ]]; then
                printf '%s' "${ISSUE_BODY}" | jq -r '.data.cert // empty' > "${TMP_DIR}/issued.pem"
                if [[ -s "${TMP_DIR}/issued.pem" ]] && openssl verify -CAfile "${CA_ROOT_CERT_FILE}" "${TMP_DIR}/issued.pem" >/dev/null 2>&1; then
                    pass "issued certificate verifies against ${CA_ROOT_CERT_FILE}"
                else
                    fail "issued certificate did not verify (jq/openssl/root cert)"
                fi
            else
                skip "issue signature verify (needs jq + openssl + CA_ROOT_CERT_FILE)"
            fi
        fi
    fi
else
    skip "issue (set CA_ISSUE=1 to enable)"
fi

# ---- 3) Generate a CRL (optional) -------------------------------------------
if [[ "${CA_CRL}" == "1" ]]; then
    if [[ -z "${CA_TOKEN}" || -z "${CA_ROOT_ID}" ]]; then
        skip "CRL gen (CA_CRL=1 requires CA_TOKEN, CA_ROOT_ID)"
    else
        CRL_BODY="$(post_json "/v1/crls/gen" "{\"co\":{\"rootId\":${CA_ROOT_ID},\"deltaCrl\":false}}")"
        echo "[accept-ca] crl: ${CRL_BODY}"
        if [[ "${CRL_BODY}" == *'"code":"OK"'* ]]; then
            pass "CRL generated (rootId=${CA_ROOT_ID})"
        else
            fail "CRL generation failed"
        fi
    fi
else
    skip "CRL gen (set CA_CRL=1 to enable)"
fi

# ---- 4) Log assertions -------------------------------------------------------
LOG_SOURCE=""
if [[ -n "${CA_CONTAINER}" ]]; then
    if command -v docker >/dev/null 2>&1; then
        LOG_SOURCE="$(docker logs "${CA_CONTAINER}" 2>&1 || true)"
    else
        skip "container log check (docker not found)"
    fi
elif [[ -n "${CA_LOG_FILE}" && -f "${CA_LOG_FILE}" ]]; then
    LOG_SOURCE="$(cat "${CA_LOG_FILE}")"
fi

if [[ -n "${LOG_SOURCE}" ]]; then
    check_log_forbidden() {
        if [[ "${LOG_SOURCE}" == *"$1"* ]]; then
            fail "log contains forbidden pattern: $1"
        else
            pass "log clean: no '$1'"
        fi
    }
    check_log_forbidden "SDF device probe failed"
    check_log_forbidden "key protection is not ready"
    check_log_forbidden "Error looking up function 'SDF_OpenDeviceEx'"
    check_log_forbidden "No such provider: liuzx"
    check_log_forbidden "[FORCE] 应用应仅打开一次设备句柄"
else
    skip "log check (set CA_CONTAINER or CA_LOG_FILE)"
fi

if [[ "${FAILED}" -eq 0 ]]; then
    echo "[accept-ca] RESULT: PASS"
    exit 0
fi
echo "[accept-ca] RESULT: FAIL" >&2
exit 1
