#!/usr/bin/env bash
#
# KMC SDF hardware acceptance probe.
#
# Polls the KMC readiness/liveness endpoints until the hsm health group is UP, then
# optionally checks the crypto-device status endpoint and greps the KMC logs for
# SDF device-probe failures.
#
# Usage:
#   scripts/accept-kmc.sh
#
# Environment:
#   KMC_BASE_URL         default http://127.0.0.1:3443
#   KMC_CONTEXT_PATH     default /api
#   KMC_TIMEOUT_SECONDS  readiness wait budget, default 120
#   KMC_POLL_INTERVAL    poll interval seconds, default 3
#   KMC_TOKEN            optional bearer token for /v1/crypto-devices/status
#   KMC_CONTAINER        optional docker container name for log assertions
#   KMC_LOG_FILE         optional KMC log file for log assertions
#
# Exit code: 0 = all executed checks passed, 1 = a check failed, 2 = usage/transport error.
#
set -euo pipefail

KMC_BASE_URL="${KMC_BASE_URL:-http://127.0.0.1:3443}"
KMC_CONTEXT_PATH="${KMC_CONTEXT_PATH:-/api}"
KMC_TIMEOUT_SECONDS="${KMC_TIMEOUT_SECONDS:-120}"
KMC_POLL_INTERVAL="${KMC_POLL_INTERVAL:-3}"
KMC_TOKEN="${KMC_TOKEN:-}"
KMC_CONTAINER="${KMC_CONTAINER:-}"
KMC_LOG_FILE="${KMC_LOG_FILE:-}"

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    sed -n '2,22p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 0
fi

BASE="${KMC_BASE_URL%/}${KMC_CONTEXT_PATH}"
FAILED=0

pass() { echo "[PASS] $*"; }
fail() { echo "[FAIL] $*"; FAILED=1; }
skip() { echo "[SKIP] $*"; }

http_get() {
    # $1 = url, $2 = optional bearer token
    if [[ -n "${2:-}" ]]; then
        curl -sS --max-time 10 -H "Authorization: Bearer ${2}" "$1" 2>/dev/null || true
    else
        curl -sS --max-time 10 "$1" 2>/dev/null || true
    fi
}

echo "[accept-kmc] base=${BASE}"

# 1) Readiness: the readiness group includes the 'hsm' indicator, so status=UP means
#    the SDF device probe succeeded.
READINESS_URL="${BASE}/actuator/health/readiness"
deadline=$(( $(date +%s) + KMC_TIMEOUT_SECONDS ))
ready_body=""
while :; do
    ready_body="$(http_get "${READINESS_URL}")"
    if [[ "${ready_body}" == *'"status":"UP"'* ]]; then
        break
    fi
    if [[ $(date +%s) -ge ${deadline} ]]; then
        fail "readiness not UP within ${KMC_TIMEOUT_SECONDS}s: ${ready_body:-<no response>}"
        break
    fi
    sleep "${KMC_POLL_INTERVAL}"
done
if [[ "${ready_body}" == *'"status":"UP"'* ]]; then
    pass "readiness UP (${READINESS_URL})"
    if [[ "${ready_body}" == *'"hsm"'* && "${ready_body}" == *'"hsm":{"status":"DOWN"'* ]]; then
        fail "readiness body reports hsm DOWN: ${ready_body}"
    fi
else
    if [[ -z "${ready_body}" ]]; then
        fail "readiness endpoint unreachable: ${READINESS_URL}"
    fi
fi

# 2) Liveness.
LIVENESS_URL="${BASE}/actuator/health/liveness"
liveness_body="$(http_get "${LIVENESS_URL}")"
if [[ "${liveness_body}" == *'"status":"UP"'* ]]; then
    pass "liveness UP (${LIVENESS_URL})"
else
    fail "liveness not UP: ${liveness_body:-<no response>}"
fi

# 3) Crypto device status (needs auth).
STATUS_URL="${BASE}/v1/crypto-devices/status?refresh=true"
if [[ -n "${KMC_TOKEN}" ]]; then
    status_body="$(http_get "${STATUS_URL}" "${KMC_TOKEN}")"
    if [[ "${status_body}" == *'"status":"UP"'* ]]; then
        pass "crypto-device status UP (${STATUS_URL})"
    else
        fail "crypto-device status not UP: ${status_body:-<no response>}"
    fi
else
    skip "crypto-device status (set KMC_TOKEN to enable; ${STATUS_URL})"
fi

# 4) Log assertions.
LOG_SOURCE=""
if [[ -n "${KMC_CONTAINER}" ]]; then
    if command -v docker >/dev/null 2>&1; then
        LOG_SOURCE="$(docker logs "${KMC_CONTAINER}" 2>&1 || true)"
    else
        skip "container log check (docker not found)"
    fi
elif [[ -n "${KMC_LOG_FILE}" && -f "${KMC_LOG_FILE}" ]]; then
    LOG_SOURCE="$(cat "${KMC_LOG_FILE}")"
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
    check_log_forbidden "[FORCE] 应用应仅打开一次设备句柄"
else
    skip "log check (set KMC_CONTAINER or KMC_LOG_FILE; the trailing \
'[FORCE] ...关闭设备' open-time reminder is benign)"
fi

if [[ "${FAILED}" -eq 0 ]]; then
    echo "[accept-kmc] RESULT: PASS"
    exit 0
fi
echo "[accept-kmc] RESULT: FAIL" >&2
exit 1
