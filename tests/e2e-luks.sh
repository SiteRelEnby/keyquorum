#!/usr/bin/env bash
# End-to-end test for keyquorum LUKS unlock action.
# Must run as root. Pass binary directory as $1.
set -euo pipefail

BIN_DIR="${1:?Usage: $0 <binary-dir>}"
KQ="$BIN_DIR/keyquorum"
KQ_SPLIT="$BIN_DIR/keyquorum-split"

# Precondition checks
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: must run as root"
    exit 1
fi

for cmd in cryptsetup losetup dd; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "ERROR: $cmd not found"
        exit 1
    fi
done

WORK=$(mktemp -d)
LOOP=""
MAPPER_NAME="kq-e2e-test"
DAEMON_PID=""

cleanup() {
    set +e
    if [ -n "$DAEMON_PID" ]; then
        kill "$DAEMON_PID" 2>/dev/null
        wait "$DAEMON_PID" 2>/dev/null
    fi
    if [ -b "/dev/mapper/$MAPPER_NAME" ]; then
        cryptsetup luksClose "$MAPPER_NAME" 2>/dev/null
    fi
    if [ -n "$LOOP" ]; then
        losetup -d "$LOOP" 2>/dev/null
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT

SECRET="e2e-luks-test-secret-$$"

echo "=== keyquorum E2E test (LUKS) ==="
echo "Binaries: $BIN_DIR"
echo "Work dir: $WORK"
echo ""

# Create a 64MB disk image
echo "--- Creating LUKS volume ---"
dd if=/dev/zero of="$WORK/luks.img" bs=1M count=64 status=none
LOOP=$(losetup -f --show "$WORK/luks.img")
echo "Loop device: $LOOP"

# Format with LUKS using our test secret as the key
echo -n "$SECRET" | cryptsetup luksFormat --batch-mode --key-file=- "$LOOP"
echo "LUKS formatted"

# Verify we can open it manually first
echo -n "$SECRET" | cryptsetup luksOpen --key-file=- "$LOOP" "${MAPPER_NAME}-verify"
cryptsetup luksClose "${MAPPER_NAME}-verify"
echo "Manual unlock verified"

# Generate shares
echo "--- Generating shares ---"
echo -n "$SECRET" | "$KQ_SPLIT" -n 3 -k 2 --no-strict-hardening -o files -d "$WORK/shares/"
echo "3 shares generated (threshold 2)"

# Write daemon config
cat > "$WORK/config.toml" <<EOF
[daemon]
socket_path = "$WORK/kq.sock"
[session]
threshold = 2
total_shares = 3
[action]
type = "luks"
device = "$LOOP"
name = "$MAPPER_NAME"
[logging]
log_participation = true
level = "info"
EOF

# Start daemon
echo "--- Starting daemon ---"
"$KQ" daemon -c "$WORK/config.toml" --no-strict-hardening > "$WORK/daemon.stdout" 2>"$WORK/daemon.stderr" &
DAEMON_PID=$!

# Wait for socket
TRIES=0
while [ ! -S "$WORK/kq.sock" ]; do
    sleep 0.1
    TRIES=$((TRIES + 1))
    if [ "$TRIES" -ge 50 ]; then
        echo "ERROR: daemon socket did not appear after 5s"
        echo "Daemon stderr:"
        cat "$WORK/daemon.stderr"
        exit 1
    fi
done
echo "Daemon ready"

# Submit shares
echo "--- Submitting shares ---"
SUBMIT1=$("$KQ" submit -s "$(cat "$WORK/shares/share-1.txt")" -u alice --socket "$WORK/kq.sock" 2>&1)
echo "Share 1: $SUBMIT1"

SUBMIT2=$("$KQ" submit -s "$(cat "$WORK/shares/share-2.txt")" -u bob --socket "$WORK/kq.sock" 2>&1)
echo "Share 2: $SUBMIT2"

# Give cryptsetup a moment to finish
sleep 0.5

# Verify LUKS device was opened
echo "--- Verifying ---"
if [ -b "/dev/mapper/$MAPPER_NAME" ]; then
    echo "  PASS: /dev/mapper/$MAPPER_NAME exists"
else
    echo "  FAIL: /dev/mapper/$MAPPER_NAME does not exist"
    echo "Daemon stderr:"
    cat "$WORK/daemon.stderr"
    exit 1
fi

if echo "$SUBMIT2" | grep -qi "quorum reached"; then
    echo "  PASS: submitter got quorum notification"
else
    echo "  FAIL: missing quorum notification: $SUBMIT2"
    exit 1
fi

echo ""
echo "=== LUKS E2E test passed ==="
