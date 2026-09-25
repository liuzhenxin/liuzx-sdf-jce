#!/usr/bin/env bash
#
# verify-no-secret-in-argv.sh — SEC-03 regression guard.
#
# Asserts that the smoke test never passes its PIN on the java command line:
#   1. static: scripts/sdf-smoke.sh must not contain -Dliuzx.sdf.smoke.pin
#   2. static: the demo Main must not read a positional password (args[4])
#   3. runtime (best effort): launch SdfSmokeTest with LIUZX_SMOKE_PIN set and
#      assert `ps -o command= -p <pid>` does not contain the sentinel PIN.
#
# Exit code 0 means no leakage detected. Safe to run without an SDF device.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

SENTINEL="GSD_SENTINEL_PIN_DO_NOT_LEAK"
FAILED=0

fail() { echo "[FAIL] $*" >&2; FAILED=1; }
pass() { echo "[PASS] $*"; }

# --- 1. static: script must not pass the PIN via -D -------------------------
if grep -q -- '-Dliuzx.sdf.smoke.pin' scripts/sdf-smoke.sh; then
    fail "scripts/sdf-smoke.sh still passes the PIN via -Dliuzx.sdf.smoke.pin"
else
    pass "scripts/sdf-smoke.sh does not use -Dliuzx.sdf.smoke.pin"
fi
if grep -q 'export LIUZX_SMOKE_PIN' scripts/sdf-smoke.sh; then
    pass "scripts/sdf-smoke.sh exports LIUZX_SMOKE_PIN"
else
    fail "scripts/sdf-smoke.sh does not export LIUZX_SMOKE_PIN"
fi

# --- 2. static: demo must not accept a positional password -----------------
if grep -q 'args\[4\]' src/main/java/org/liuzx/jce/demo/Main.java; then
    fail "Main.java still reads a positional password (args[4])"
else
    pass "Main.java has no positional password argument"
fi

# --- 3. runtime: the java argv must not contain the PIN --------------------
JAR="$(ls -1t target/liuzx-sdf-jce-*.jar 2>/dev/null | grep -vE -- '-(sources|javadoc)\.jar$' | head -n1 || true)"
if [[ -z "${JAR}" || ! -d target/lib ]]; then
    echo "[SKIP] runtime argv check (no packaged JAR/target/lib; run 'mvn package' first)"
else
    export LIUZX_SMOKE_PIN="${SENTINEL}"
    java -Dfile.encoding=UTF-8 -cp "${JAR}:target/lib/*" org.liuzx.jce.demo.SdfSmokeTest \
        >/dev/null 2>&1 &
    PID=$!
    OBSERVED=""
    for _ in 1 2 3 4 5 6; do
        if ! kill -0 "${PID}" 2>/dev/null; then
            break
        fi
        OBSERVED="$(ps -o command= -p "${PID}" 2>/dev/null || true)"
        if [[ -n "${OBSERVED}" ]]; then
            break
        fi
        sleep 0.5
    done
    kill "${PID}" 2>/dev/null || true
    wait "${PID}" 2>/dev/null || true

    if [[ -z "${OBSERVED}" ]]; then
        echo "[SKIP] runtime argv check (process exited before it could be observed)"
    elif [[ "${OBSERVED}" == *"${SENTINEL}"* ]]; then
        fail "PIN leaked into the java command line: ${OBSERVED}"
    else
        pass "PIN is absent from the java command line"
    fi
fi

if [[ "${FAILED}" -eq 0 ]]; then
    echo "[verify-no-secret-in-argv] RESULT: PASS"
else
    echo "[verify-no-secret-in-argv] RESULT: FAIL" >&2
fi
exit "${FAILED}"
