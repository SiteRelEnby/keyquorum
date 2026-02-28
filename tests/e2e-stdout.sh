#!/usr/bin/env bash
# End-to-end tests for keyquorum using stdout action (no root required).
set -euo pipefail

BIN_DIR="${1:-$(cd "$(dirname "$0")/../target/release" && pwd)}"
KQ="$BIN_DIR/keyquorum"
KQ_SPLIT="$BIN_DIR/keyquorum-split"

WORK=$(mktemp -d)
PIDS=()
TESTS_PASSED=0
TESTS_FAILED=0

cleanup() {
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    rm -rf "$WORK"
}
trap cleanup EXIT

pass() {
    echo "  PASS: $1"
    TESTS_PASSED=$((TESTS_PASSED + 1))
}

fail() {
    echo "  FAIL: $1"
    TESTS_FAILED=$((TESTS_FAILED + 1))
}

wait_for_socket() {
    local sock="$1"
    local tries=0
    while [ ! -S "$sock" ]; do
        sleep 0.1
        tries=$((tries + 1))
        if [ "$tries" -ge 50 ]; then
            echo "ERROR: daemon socket $sock did not appear after 5s"
            return 1
        fi
    done
}

# Write a daemon config file.
# Usage: write_config <socket_path> <threshold> <total_shares> [extra_session_lines]
write_config() {
    local config_file="$1" socket="$2" threshold="$3" total="$4"
    local extra="${5:-}"
    cat > "$config_file" <<EOF
[daemon]
socket_path = "$socket"
[session]
threshold = $threshold
total_shares = $total
$extra
[action]
type = "stdout"
[logging]
level = "warn"
EOF
}

# Start a daemon, record its PID.
# Usage: start_daemon <config_file> <stdout_file> [extra_args...]
start_daemon() {
    local config="$1" stdout_file="$2"
    shift 2
    "$KQ" daemon -c "$config" --no-strict-hardening "$@" > "$stdout_file" 2>"$stdout_file.err" &
    local pid=$!
    PIDS+=("$pid")
    echo "$pid"
}

echo "=== keyquorum E2E tests (stdout mode) ==="
echo "Binaries: $BIN_DIR"
echo ""

# --------------------------------------------------------------------------
echo "--- Test: basic_quorum ---"
SECRET="basic-quorum-test-secret"
SOCK="$WORK/basic.sock"
write_config "$WORK/basic.toml" "$SOCK" 2 3

echo -n "$SECRET" | "$KQ_SPLIT" -n 3 -k 2 --no-strict-hardening -o files -d "$WORK/basic-shares/"

DAEMON_PID=$(start_daemon "$WORK/basic.toml" "$WORK/basic.stdout")
wait_for_socket "$SOCK"

"$KQ" submit -s "$(cat "$WORK/basic-shares/share-1.txt")" --socket "$SOCK" 2>"$WORK/basic-sub1.err"
SUBMIT2=$("$KQ" submit -s "$(cat "$WORK/basic-shares/share-2.txt")" --socket "$SOCK" 2>&1 || true)

# Give daemon a moment to write stdout
sleep 0.2

if grep -q "$SECRET" "$WORK/basic.stdout"; then
    pass "daemon stdout contains secret"
else
    fail "daemon stdout missing secret"
fi

if echo "$SUBMIT2" | grep -q "Quorum reached"; then
    pass "submitter got quorum notification"
else
    fail "submitter missing quorum notification: $SUBMIT2"
fi

kill "$DAEMON_PID" 2>/dev/null || true
wait "$DAEMON_PID" 2>/dev/null || true

# --------------------------------------------------------------------------
echo "--- Test: status_query ---"
SOCK="$WORK/status.sock"
write_config "$WORK/status.toml" "$SOCK" 2 3

echo -n "status-test" | "$KQ_SPLIT" -n 3 -k 2 --no-strict-hardening -o files -d "$WORK/status-shares/"

DAEMON_PID=$(start_daemon "$WORK/status.toml" "$WORK/status.stdout")
wait_for_socket "$SOCK"

"$KQ" submit -s "$(cat "$WORK/status-shares/share-1.txt")" --socket "$SOCK" 2>/dev/null

STATUS=$("$KQ" status --socket "$SOCK" 2>&1 || true)

if echo "$STATUS" | grep -qi "collecting\|shares_received.*1"; then
    pass "status shows collecting state"
else
    fail "status unexpected: $STATUS"
fi

kill "$DAEMON_PID" 2>/dev/null || true
wait "$DAEMON_PID" 2>/dev/null || true

# --------------------------------------------------------------------------
echo "--- Test: bare_base32_format ---"
SECRET="bare-base32-test"
SOCK="$WORK/base32.sock"
write_config "$WORK/base32.toml" "$SOCK" 2 3

echo -n "$SECRET" | "$KQ_SPLIT" -n 3 -k 2 --no-strict-hardening --bare --encoding base32 -o files -d "$WORK/base32-shares/"

DAEMON_PID=$(start_daemon "$WORK/base32.toml" "$WORK/base32.stdout")
wait_for_socket "$SOCK"

"$KQ" submit -s "$(cat "$WORK/base32-shares/share-1.txt")" --socket "$SOCK" 2>/dev/null
"$KQ" submit -s "$(cat "$WORK/base32-shares/share-2.txt")" --socket "$SOCK" 2>/dev/null

sleep 0.2

if grep -q "$SECRET" "$WORK/base32.stdout"; then
    pass "bare base32 shares reconstructed"
else
    fail "bare base32 reconstruction failed"
fi

kill "$DAEMON_PID" 2>/dev/null || true
wait "$DAEMON_PID" 2>/dev/null || true

# --------------------------------------------------------------------------
echo "--- Test: retry_with_corrupted_share ---"
SECRET="retry-corrupt-test"
SOCK="$WORK/retry.sock"
write_config "$WORK/retry.toml" "$SOCK" 2 3 \
    'on_failure = "retry"
verification = "embedded-blake3"
max_retries = 3'

echo -n "$SECRET" | "$KQ_SPLIT" -n 3 -k 2 --no-strict-hardening -o files -d "$WORK/retry-shares/"

# Corrupt the first share: flip some characters in the base64 payload
# (the last line of the PEM envelope or the bare share)
CORRUPT_FILE="$WORK/retry-shares/share-1.txt"
# Get the payload line (last non-empty line) and corrupt it
LAST_LINE=$(tail -1 "$CORRUPT_FILE")
CORRUPTED=$(echo "$LAST_LINE" | sed 's/A/Z/g; s/B/X/g; s/C/W/g')
sed -i "s|${LAST_LINE}|${CORRUPTED}|" "$CORRUPT_FILE"

DAEMON_PID=$(start_daemon "$WORK/retry.toml" "$WORK/retry.stdout")
wait_for_socket "$SOCK"

# Submit corrupted share first, then two valid ones
"$KQ" submit -s "$(cat "$WORK/retry-shares/share-1.txt")" --socket "$SOCK" 2>/dev/null || true
"$KQ" submit -s "$(cat "$WORK/retry-shares/share-2.txt")" --socket "$SOCK" 2>/dev/null || true
SUBMIT3=$("$KQ" submit -s "$(cat "$WORK/retry-shares/share-3.txt")" --socket "$SOCK" 2>&1 || true)

sleep 0.2

if grep -q "$SECRET" "$WORK/retry.stdout"; then
    pass "retry mode recovered from corrupted share"
else
    fail "retry mode did not recover"
fi

kill "$DAEMON_PID" 2>/dev/null || true
wait "$DAEMON_PID" 2>/dev/null || true

# --------------------------------------------------------------------------
echo "--- Test: require_metadata_rejects ---"
SOCK="$WORK/meta.sock"
write_config "$WORK/meta.toml" "$SOCK" 2 3 'require_metadata = true'

echo -n "meta-test" | "$KQ_SPLIT" -n 3 -k 2 --no-strict-hardening --no-metadata -o files -d "$WORK/meta-shares/"

DAEMON_PID=$(start_daemon "$WORK/meta.toml" "$WORK/meta.stdout")
wait_for_socket "$SOCK"

SUBMIT=$("$KQ" submit -s "$(cat "$WORK/meta-shares/share-1.txt")" --socket "$SOCK" 2>&1 || true)

if echo "$SUBMIT" | grep -qi "rejected\|metadata"; then
    pass "require_metadata rejected share without metadata"
else
    fail "require_metadata did not reject: $SUBMIT"
fi

kill "$DAEMON_PID" 2>/dev/null || true
wait "$DAEMON_PID" 2>/dev/null || true

# --------------------------------------------------------------------------
echo "--- Test: pipe_stdin ---"
SECRET="pipe-stdin-test"
SOCK="$WORK/stdin.sock"
write_config "$WORK/stdin.toml" "$SOCK" 2 3

echo -n "$SECRET" | "$KQ_SPLIT" -n 3 -k 2 --no-strict-hardening -o files -d "$WORK/stdin-shares/"

DAEMON_PID=$(start_daemon "$WORK/stdin.toml" "$WORK/stdin.stdout")
wait_for_socket "$SOCK"

"$KQ" submit --socket "$SOCK" < "$WORK/stdin-shares/share-1.txt" 2>/dev/null
"$KQ" submit --socket "$SOCK" < "$WORK/stdin-shares/share-2.txt" 2>/dev/null

sleep 0.2

if grep -q "$SECRET" "$WORK/stdin.stdout"; then
    pass "stdin pipe submission worked"
else
    fail "stdin pipe submission failed"
fi

kill "$DAEMON_PID" 2>/dev/null || true
wait "$DAEMON_PID" 2>/dev/null || true

# --------------------------------------------------------------------------
echo "--- Test: strict_hardening_enforced ---"
# Only meaningful when not running as root (root ignores RLIMIT_MEMLOCK)
if [ "$(id -u)" -ne 0 ]; then
    SOCK="$WORK/strict.sock"
    write_config "$WORK/strict.toml" "$SOCK" 2 3

    echo -n "strict-test" | "$KQ_SPLIT" -n 3 -k 2 --no-strict-hardening -o files -d "$WORK/strict-shares/"

    # Start daemon with mlock disabled at OS level, strict_hardening ON (default)
    prlimit --memlock=0:0 -- "$KQ" daemon -c "$WORK/strict.toml" > "$WORK/strict.stdout" 2>"$WORK/strict.stderr" &
    STRICT_PID=$!
    PIDS+=("$STRICT_PID")
    wait_for_socket "$SOCK"

    SUBMIT=$("$KQ" submit -s "$(cat "$WORK/strict-shares/share-1.txt")" --socket "$SOCK" 2>&1 || true)

    if echo "$SUBMIT" | grep -qi "strict_hardening\|rejected"; then
        pass "strict_hardening rejected share when mlock fails"
    else
        fail "strict_hardening did not reject: $SUBMIT"
    fi

    kill "$STRICT_PID" 2>/dev/null || true
    wait "$STRICT_PID" 2>/dev/null || true
else
    echo "  SKIP: strict_hardening_enforced (running as root, RLIMIT_MEMLOCK ignored)"
fi

# --------------------------------------------------------------------------
echo "--- Test: strict_hardening_disabled ---"
if [ "$(id -u)" -ne 0 ]; then
    SECRET="strict-disabled-test"
    SOCK="$WORK/nostrict.sock"
    write_config "$WORK/nostrict.toml" "$SOCK" 2 3

    echo -n "$SECRET" | "$KQ_SPLIT" -n 3 -k 2 --no-strict-hardening -o files -d "$WORK/nostrict-shares/"

    # Start daemon with mlock disabled at OS level, strict_hardening OFF
    prlimit --memlock=0:0 -- "$KQ" daemon -c "$WORK/nostrict.toml" --no-strict-hardening > "$WORK/nostrict.stdout" 2>"$WORK/nostrict.stderr" &
    NOSTRICT_PID=$!
    PIDS+=("$NOSTRICT_PID")
    wait_for_socket "$SOCK"

    SUBMIT=$("$KQ" submit -s "$(cat "$WORK/nostrict-shares/share-1.txt")" --socket "$SOCK" 2>&1 || true)
    "$KQ" submit -s "$(cat "$WORK/nostrict-shares/share-2.txt")" --socket "$SOCK" 2>/dev/null || true

    sleep 0.2

    if echo "$SUBMIT" | grep -qi "accepted"; then
        pass "strict_hardening disabled accepted share despite mlock failure"
    else
        fail "strict_hardening disabled did not accept: $SUBMIT"
    fi

    if grep -q "$SECRET" "$WORK/nostrict.stdout"; then
        pass "reconstruction succeeded with strict_hardening disabled"
    else
        fail "reconstruction failed with strict_hardening disabled"
    fi

    kill "$NOSTRICT_PID" 2>/dev/null || true
    wait "$NOSTRICT_PID" 2>/dev/null || true
else
    echo "  SKIP: strict_hardening_disabled (running as root, RLIMIT_MEMLOCK ignored)"
fi

# --------------------------------------------------------------------------
echo ""
echo "=== Results: $TESTS_PASSED passed, $TESTS_FAILED failed ==="

if [ "$TESTS_FAILED" -gt 0 ]; then
    exit 1
fi
