# keyquorum

[![CI](https://github.com/SiteRelEnby/keyquorum/actions/workflows/ci.yml/badge.svg)](https://github.com/SiteRelEnby/keyquorum/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/keyquorum.svg)](https://crates.io/crates/keyquorum)
[![License: Apache-2.0](https://img.shields.io/crates/l/keyquorum.svg)](https://github.com/SiteRelEnby/keyquorum/blob/main/LICENSE)
![transrights](https://pride-badges.pony.workers.dev/static/v1?label=trans%20rights&stripeWidth=6&stripeColors=5BCEFA,F5A9B8,FFFFFF,F5A9B8,5BCEFA)
![enbyware](https://pride-badges.pony.workers.dev/static/v1?label=enbyware&labelColor=%23555&stripeWidth=8&stripeColors=FCF434%2CFFFFFF%2C9C59D1%2C2C2C2C)
![pluralmade](https://pride-badges.pony.workers.dev/static/v1?label=plural+made&labelColor=%23555&stripeWidth=8&stripeColors=2e0525%2C553578%2C7675c3%2C89c7b0%2Cf4ecbd)

Shamir secret sharing daemon for distributed teams. Split a secret into shares, distribute them to team members, and reconstruct the secret only when a quorum submits their shares. Nobody ever handles someone else's share or sees the reconstructed key. Shares implemented with [blahaj](https://git.distrust.co/public/blahaj) (maintained fork of sharks with zeroize support).

Built for unlocking LUKS partitions, but works with anything that takes a key on stdin. Other things may be supported in the future.

## Install

```bash
cargo install keyquorum keyquorum-split
```

Or build from source:

```bash
cargo build --release
# binaries at target/release/keyquorum and target/release/keyquorum-split
```

**Platform support:** Linux is the primary and tested target. macOS builds are **highly experimental and untested** by the project maintainers — memory hardening features (DONTFORK, DONTDUMP, prctl) are Linux-only and are silently skipped on macOS. The maintainer does not have access to Apple hardware. macOS PRs are welcome but please do not open issues requesting Apple support.

## Quick start

### 1. Generate shares

```bash
# Split a secret into 5 shares, any 3 can reconstruct (3-of-5)
echo -n "my-secret-key" | keyquorum-split -n 5 -k 3

# Or write one file per share for easier distribution
echo -n "my-secret-key" | keyquorum-split -n 5 -k 3 -o files -d ./shares/
```

By default, `keyquorum-split` embeds a blake3 verification checksum in the secret before splitting. This allows the daemon to verify candidate secrets in microseconds during reconstruction, without executing the configured action on wrong keys. Use `--no-checksum` to disable this (not recommended — see [Verification](#verification)).

Distribute each share to its holder. The split operator should delete their copy.

### 2. Configure the daemon

```toml
# /etc/keyquorum/config.toml

[daemon]
socket_path = "/run/keyquorum/keyquorum.sock"
# tcp_port = 35000  # optional, binds 127.0.0.1 only

[session]
threshold = 3
total_shares = 5
timeout_secs = 1800  # 30 min window to reach quorum

[action]
type = "luks"
device = "/dev/sda2"
name = "cryptdata"

# OR: pipe secret to any command's stdin
# [action]
# type = "command"
# program = "/usr/local/bin/unseal-vault"
# args = ["--cluster", "prod"]
```

See `example-config.toml` for all options.

### 3. Start the daemon

```bash
keyquorum daemon -c /etc/keyquorum/config.toml
```

### 4. Team members submit shares

Each participant SSHes in and submits their share:

```bash
# Pipe a share file (PEM envelope, bare V1, or raw base64/base32)
keyquorum submit -c /etc/keyquorum/config.toml < share-1.txt

# Or type/paste interactively (press Enter twice or Ctrl+D to finish)
keyquorum submit -c /etc/keyquorum/config.toml

# Check progress
keyquorum status -c /etc/keyquorum/config.toml
```

Shares are always read from stdin — never as command-line arguments — to avoid exposure via the process table (`/proc`, `ps`) and shell history.

When the threshold is reached, the secret is reconstructed and the configured action runs automatically. All shares are wiped from memory immediately after.

## Verification

`keyquorum-split` appends a 32-byte blake3 hash to the secret before splitting (enabled by default). On reconstruction, the daemon verifies the hash before executing any action. This means:

- **Wrong share combinations are rejected instantly** without running cryptsetup or other commands with incorrect keys
- **Retry mode works safely** — corrupted shares are identified by hash mismatch, not by executing the action on every C(n,k) combination

The config field `verification` controls this (default: `"embedded-blake3"`). Set to `"none"` only if shares were generated with `--no-checksum`.

## Share format

keyquorum uses a versioned share format (V1) with layered options for integrity and metadata. keyquorum is designed for a wide range of threat models and desired failure modes, and not all options will be appropriate for your use case — read this section before protecting anything valuable.

### Format layers

Shares have up to three layers, each independently optional at generation time:

1. **PEM envelope** (default) — human-readable wrapper with a `KEYQUORUM-SHARE-V1` marker line
2. **Metadata headers** (default) — share number, threshold, total shares, scheme, integrity method. Included in the envelope above the payload
3. **CRC32 integrity** (default) — per-share checksum embedded in the V1 binary payload, covering the raw share data

Example of a full share (all defaults):
```
KEYQUORUM-SHARE-V1
Share: 1 of 5 (threshold 3)
Scheme: shamir-gf256
Integrity: crc32

S1EBATt3zvABLJC/il49S81WaRcD...
```

The encoded payload line contains the complete V1 binary (KQ magic + flags + CRC32 + share data). If someone strips the headers and submits only the payload line, it works as a bare V1 share — no information is lost from the cryptographic material.

### Confidentiality vs integrity tradeoffs

**Full envelope with metadata** (`keyquorum-split -n 5 -k 3`, the default): maximum usability. Share holders can see which share they have, what threshold is required, and the daemon can cross-validate metadata against its config. The CRC32 catches corruption before reconstruction is attempted. Metadata is plaintext, so anyone with a share knows the scheme parameters.

**Envelope without metadata** (`--no-metadata`): the envelope marker identifies it as a keyquorum share, but reveals nothing about the scheme. CRC32 still provides integrity checking within the V1 binary payload. The daemon cannot cross-validate parameters.

**Bare V1** (`--bare`): no envelope, just the encoded V1 binary payload. Still includes the KQ magic prefix and optional CRC32. Compact, suitable for automation or embedding in other formats.

**No CRC32** (`--no-integrity`): disables per-share integrity checking. Corruption is only detected at reconstruction time (via blake3 verification or action failure). Use this if your threat model includes intentionally corrupted shares as a canary — without per-share integrity, an adversary who obtains multiple shares cannot determine which are corrupted.

**Base32 encoding** (`--encoding base32`): trades density for hand-writability. Base32 shares are ~60% longer but use only uppercase letters and digits, making them easier to transcribe on paper or read aloud. Base64 is the default.

### Daemon-side enforcement

The daemon auto-detects all share formats (PEM envelope, bare V1, raw base64/base32) and accepts them interchangeably within the same session.

Set `require_metadata = true` in config to reject shares that lack a PEM envelope with metadata headers. When enabled, the daemon cross-validates each share's threshold and total_shares against its own config, rejecting mismatches. When disabled (the default), metadata headers are ignored entirely — the daemon uses only the binary payload. This is deliberately not enforced by lockdown mode, since headerless shares leak less information about the scheme.

### Metadata is not authenticated

The PEM envelope metadata headers are **not cryptographically signed**. They are a convenience layer for human operators and optional daemon-side validation, not a security boundary.

An attacker with access to a share could forge the metadata headers (e.g., changing the claimed threshold or total shares). With `require_metadata = true`, forged headers that don't match the daemon config cause rejection — this is a denial-of-service vector, but an attacker with the share could simply not submit it for the same effect. With `require_metadata = false`, forged headers are ignored entirely.

The actual cryptographic integrity comes from the CRC32 on raw share data (catches corruption) and the blake3 hash embedded in the secret (catches wrong combinations at reconstruction). Neither depends on metadata headers.

Signed metadata envelopes are a stretch goal for a future format version. The V1 binary format includes a version byte to support this without breaking existing shares.

### What the format protects against (and what it doesn't)

| Threat | Protection | Status |
|--------|-----------|--------|
| Accidental share corruption (bit flip, truncation, copy-paste error) | CRC32 rejects at submit time; blake3 catches at reconstruction | Protected |
| Single malicious participant submits garbage | Retry mode + blake3 verification excludes bad shares automatically | Protected |
| MITM tampers with share data in transit | Same as accidental corruption — CRC32 + blake3 | Protected |
| Forged metadata headers on a share | With `require_metadata`: rejected if headers don't match config. Without: headers ignored entirely | Advisory only |
| Attacker collects K or more shares | Secret is compromised. No share format can prevent this — it's the fundamental assumption of the scheme | Not protectable |
| Malicious split operator gives fake shares | Not detected. Verifiable Secret Sharing (VSS) schemes solve this but are not yet implemented | Not protected |

In retry mode with `log_participation = true`, the daemon logs which share indices were used in a successful reconstruction and which were excluded, allowing operators to identify problematic shares.

## Retry on failure

If a participant submits a corrupted share, the default behavior (`on_failure = "wipe"`) discards everything — all participants must resubmit. For high-friction scenarios, enable retry mode:

```toml
[session]
on_failure = "retry"
max_retries = 3
# verification = "embedded-blake3"  # required for retry (and is the default)
# max_combinations = 100            # cap on C(n,k) combinations tried
```

In retry mode, the daemon keeps existing shares, returns to accepting new ones, and retries reconstruction with all available combinations. The blake3 checksum ensures only the correct combination triggers the action.

## Lockdown mode

For maximum security posture, enable lockdown mode via `--lockdown` flag or `lockdown = true` in config:

```bash
keyquorum daemon -c /etc/keyquorum/config.toml --lockdown
keyquorum-split -n 5 -k 3 --lockdown -o files -d ./shares/
```

Lockdown currently enforces:
- Rejects `stdout` action type (secrets must not be written to stdout)
- Forces `on_failure = "wipe"` (no retry mode)
- Implies `strict_hardening = true`
- Rejects `--output stdout` in keyquorum-split

Lockdown may gain new restrictions between versions. Use it when you want the strongest available defaults and accept potential breaking changes on upgrade.

### Strict hardening

By default (`strict_hardening = true`), the daemon and split tool reject operations if memory protections (`mlock`, `madvise`) fail on secret buffers. This ensures secret material is never held in swappable, dumpable, or forkable memory. Individual protection failures are logged at WARN level with the specific protection name and error.

Disable with `strict_hardening = false` in config or `--no-strict-hardening` on the CLI if your environment cannot provide these guarantees (e.g. unprivileged container without `IPC_LOCK`). Not recommended for production. Lockdown always implies strict hardening regardless of the config value.

## Recommended configuration

For most deployments, this configuration provides a good balance of fault tolerance and auditability:

**Generating shares:**
```bash
# Default V1 format: envelope + metadata + CRC32 + blake3 checksum
# Generate N = K + 2 shares (two spare shares for fault tolerance)
echo -n "my-secret" | keyquorum-split -n 5 -k 3 -o files -d ./shares/
```

Generating two more shares than the threshold means a single bad share doesn't block reconstruction, and a second spare covers the case where you need to identify who submitted garbage versus retrying with a replacement.

**Daemon config:**
```toml
[daemon]
socket_path = "/run/keyquorum/keyquorum.sock"

[session]
threshold = 3
total_shares = 5
timeout_secs = 1800
on_failure = "retry"
max_retries = 3
# verification = "embedded-blake3"  # the default
# max_combinations = 100            # the default
require_metadata = true

[action]
type = "luks"
device = "/dev/sda2"
name = "cryptdata"

[logging]
log_participation = true
level = "info"
```

What this gives you:

- **`on_failure = "retry"` + blake3 verification**: if a share is corrupted or malicious, the daemon automatically tries other combinations instead of wiping everything. Bad shares are excluded by blake3 hash mismatch.
- **`require_metadata = true`**: shares without a PEM envelope and metadata headers are rejected. The daemon cross-validates threshold and total_shares against its config, catching shares generated with wrong parameters.
- **`log_participation = true`**: the daemon logs who submitted which share index and when. Combined with retry mode, if reconstruction succeeds with shares excluded, the daemon logs which indices were used and which were excluded at WARN level — giving you a trail to identify the problematic share holder.
- **N = K + 2**: two spare shares means you can tolerate one bad share (retry finds the working combination) and still have one spare if a participant is unavailable.

For higher-stakes deployments, also consider `--lockdown` (forces `on_failure = "wipe"`, rejects stdout action, implies `strict_hardening`). Note that lockdown and retry mode are mutually exclusive — lockdown prioritizes wiping secrets over fault tolerance.

## Security

This is a security-critical tool. The design assumes the host is trusted but participants may not be in the same room.

**Memory protection:**
- `mlock()` on all buffers containing shares or the reconstructed secret — never swapped to disk
- `madvise(MADV_DONTFORK)` on secret buffers — no copy-on-write leaks to child processes
- `madvise(MADV_DONTDUMP)` — secret pages excluded from core dumps even if dumpable is re-enabled
- `Zeroize` on drop for all sensitive data, including embedded checksum bytes
- Reconstructed secret is used immediately then zeroized and munlocked

**Process hardening:**
- `prctl(PR_SET_DUMPABLE, 0)` at startup — no core dumps, no `/proc/self/mem` reads
- `prctl(PR_SET_NO_NEW_PRIVS, 1)` — child processes (cryptsetup) cannot gain privileges via setuid/setgid

**Input validation:**
- Share index verified against decoded share data (first byte is the x-coordinate)
- Duplicate share indices rejected
- Total shares capped at configured `total_shares`
- NDJSON messages capped at 64KB to prevent memory exhaustion
- Socket path verified to be an actual socket before cleanup

**Network:**
- TCP binds `127.0.0.1` only (for remote access, participants tunnel via SSH/SSM)
- Unix socket permissions `0o660`

**Logging:**
- Share values are never logged and never included in error messages
- Participation logging (who submitted, when) is opt-in via config

**Architecture:**
- All secret material lives in a single tokio task — no shared mutexes, no `Arc<Mutex>` on secrets
- Connection handlers communicate with the session via message passing (mpsc channels)

## Limitations

- **Not for boot volumes** — the daemon requires a running OS
- **No participant authentication** — anyone with a valid share can submit (share-only trust model)
- **Single session at a time** — one unlock operation at a time per daemon instance
- **Metadata envelope is not signed** — PEM headers are convenience-only and can be forged. See [Metadata is not authenticated](#metadata-is-not-authenticated)
- **Threat model does not currently protect against a malicious dealer** - there are mitigations planned (e.g. per-recipient asymmetric encryption of shares rather than plaintext), but these are not currently meaningfully implemented.

## CLI reference

### keyquorum

```
Usage: keyquorum <COMMAND>

Commands:
  daemon  Start the collection daemon
  submit  Submit a share to the running daemon
  status  Query the current session status
```

**`keyquorum daemon`**
```
Options:
  -c, --config <CONFIG>  Path to config file [default: /etc/keyquorum/config.toml]
      --lockdown              Lockdown mode: maximum security posture
      --no-strict-hardening   Allow operation if memory protections fail
```

**`keyquorum submit`**

Reads share data from stdin (pipe or interactive). Supports PEM envelopes, bare V1, and raw base64/base32.

```
Options:
  -u, --user <USER>      Your identifier (optional, for participation logging)
      --socket <SOCKET>  Socket path or tcp://host:port (overrides config)
  -c, --config <CONFIG>  Path to config file (reads socket_path from it)
```

**`keyquorum status`**
```
Options:
      --socket <SOCKET>  Socket path or tcp://host:port (overrides config)
  -c, --config <CONFIG>  Path to config file (reads socket_path from it)
```

### keyquorum-split

```
Usage: keyquorum-split [OPTIONS] --shares <SHARES> --threshold <THRESHOLD>

Options:
  -n, --shares <SHARES>        Total number of shares to generate (2-255)
  -k, --threshold <THRESHOLD>  Minimum shares needed to reconstruct (2-N)
  -o, --output <OUTPUT>        Output mode: stdout (default) or files
  -d, --dir <DIR>              Output directory for file-per-share mode
      --lockdown               Lockdown mode: rejects stdout output
      --no-strict-hardening    Allow operation if memory protections fail
      --no-checksum            Do not embed blake3 verification checksum
      --no-integrity           Skip per-share CRC32 integrity check
      --no-metadata            Omit metadata headers from PEM envelope
      --bare                   Output V1 binary payload only, no PEM envelope
      --encoding <ENCODING>    Payload encoding: base64 (default) or base32
```

## Protocol

Newline-delimited JSON over Unix socket or TCP. See `example-config.toml` for configuration options.

```
Client → Daemon:  {"type":"submit_share","share":{"index":3,"data":"<share data>"}}
Client → Daemon:  {"type":"status"}
Daemon → Client:  {"type":"share_accepted","status":{...}}
Daemon → Client:  {"type":"quorum_reached","action_result":{...}}
```

## License

Apache-2.0

Trans rights are human rights 🏳️‍⚧️
