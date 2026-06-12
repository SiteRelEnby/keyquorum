# keyquorum

[![CI](https://github.com/SiteRelEnby/keyquorum/actions/workflows/ci.yml/badge.svg)](https://github.com/SiteRelEnby/keyquorum/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/keyquorum.svg)](https://crates.io/crates/keyquorum)
[![License: Apache-2.0](https://img.shields.io/crates/l/keyquorum.svg)](https://github.com/SiteRelEnby/keyquorum/blob/main/LICENSE)

![transrights](https://pride-badges.pony.workers.dev/static/v1?label=trans%20rights&stripeWidth=6&stripeColors=5BCEFA,F5A9B8,FFFFFF,F5A9B8,5BCEFA)
![enbyware](https://pride-badges.pony.workers.dev/static/v1?label=enbyware&labelColor=%23555&stripeWidth=8&stripeColors=FCF434%2CFFFFFF%2C9C59D1%2C2C2C2C)
![pluralmade](https://pride-badges.pony.workers.dev/static/v1?label=plural+made&labelColor=%23555&stripeWidth=8&stripeColors=2e0525%2C553578%2C7675c3%2C89c7b0%2Cf4ecbd)

Shamir secret sharing daemon for distributed teams. Split a secret into shares, distribute them to team members, and reconstruct the secret only when a quorum submits their shares. Nobody ever handles someone else's share or sees the reconstructed key. Shares implemented with [blahaj](https://git.distrust.co/public/blahaj) (maintained fork of sharks with zeroize support).

Built for unlocking LUKS partitions, but works with anything that takes a key on stdin. Other things may be supported in the future.

## Why this instead of …

Plenty of tools split secrets with Shamir's scheme. The gap keyquorum fills is the **collection side**: a daemon that gathers shares from K people who never see each other's shares, verifies the reconstruction, runs an action with the secret, and wipes everything — with memory hardening throughout.

| Tool | What it does | What it doesn't |
|------|--------------|-----------------|
| `ssss` / `horcrux` / other split CLIs | Split and combine shares offline | Someone has to collect all K shares in one place and handle the reconstructed secret by hand — that person becomes the single point of compromise. Zero references to bad fantasy series by hateful people, guaranteed forever. The trans person makes a better tool, of course ;) |
| HashiCorp Vault (unseal keys) | K-of-N unseal of Vault itself | Requires running Vault; the quorum mechanism isn't usable for arbitrary secrets or actions outside Vault |
| clevis / tang | Automatic network-bound LUKS unlock | Trust is in a server being reachable, not in K humans agreeing; no quorum of people |
| age / GPG | Encrypt a secret to one or more recipients | Any single recipient can decrypt — there's no threshold |

keyquorum combines the split (with embedded blake3 verification and optional per-recipient `age` encryption, so the dealer never handles plaintext shares) with a hardened collection daemon (mlock'd memory, no core dumps, zeroize-on-wipe, combinatorial retry against corrupted shares) and pluggable actions (LUKS unlock, arbitrary command, stdout). If you only need offline split/combine, the simpler tools above are fine — keyquorum is for when the *reconstruction event* itself needs to be multi-party, audited, and hands-off.

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

### Running as a systemd service

A hardened unit file is provided in `contrib/systemd/`:

```bash
cp target/release/keyquorum /usr/local/bin/
mkdir -p /etc/keyquorum && cp example-config.toml /etc/keyquorum/config.toml
# edit /etc/keyquorum/config.toml for your deployment
cp contrib/systemd/keyquorum.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now keyquorum
```

The unit sets `LimitMEMLOCK=infinity` (required by `strict_hardening`'s mlock guarantees), creates `/run/keyquorum` for the socket via `RuntimeDirectory`, and applies systemd sandboxing (`ProtectSystem=strict`, `MemoryDenyWriteExecute`, `PrivateTmp`, and friends) on top of the daemon's own process hardening. `PrivateDevices` is intentionally left off so the `luks` action can reach device-mapper — see the comments in the unit file if you want to tighten further for non-device actions. The daemon handles SIGTERM, so `systemctl stop` shuts down gracefully and cleans up the socket.

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

### Encrypting shares to recipients

For distributed teams where the split operator should never see plaintext shares:

```bash
# Create a recipients file (one age public key per line)
cat > recipients.txt << 'EOF'
# Alice
age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
# Bob
age1xyz...
# Carol
age1abc...
EOF

# Generate encrypted shares (operator never sees plaintext)
echo -n "my-secret-key" | keyquorum-split -n 3 -k 2 -o age --recipients recipients.txt -d ./shares/

# Each recipient decrypts their share and submits:
age -d -i identity.txt share-1.txt.age | keyquorum submit -c /etc/keyquorum/config.toml
```

Use `--armor` (or `--armour`) to produce ASCII-armored `.age.txt` files that can be pasted into text channels (Signal, email, etc.) instead of binary `.age` files.

### In-person key ceremonies

For handing out shares in person, `--output interactive` shows one share at a time on the terminal, waits for each holder to record theirs, and clears the screen (and scrollback, where the terminal supports it) between shares — nothing is written to disk and no holder sees another's share:

```bash
echo -n "my-secret-key" | keyquorum-split -n 5 -k 3 -o interactive
```

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

## Duress shares

A duress (canary) share is a tripwire: a designated share index that, when submitted, silently triggers an alert. The submission response, status counters, and daemon log output are **indistinguishable from any other accepted share** — nothing about the detection is ever logged, because logs on the host may be visible to whoever is applying the coercion. The alert program is the only notification channel.

The intended pattern: give each participant their regular share **plus** their own duress share. A participant submitting under coercion uses the duress one. `keyquorum-split --duress N` designates the last N shares as duress and prints the matching config block:

```bash
# 3-of-6: shares 1-3 regular, 4-6 duress (one duress per participant)
echo -n "my-secret-key" | keyquorum-split -n 6 -k 3 --duress 3 -o files -d ./shares/
```

```toml
[session]
threshold = 3
total_shares = 6

[session.duress]
indices = [4, 5, 6]       # printed by keyquorum-split --duress
mode = "alert"            # or "poison"
alert_program = "/usr/local/bin/notify-security"
alert_args = ["--channel", "ops"]
```

Two modes:

- **`alert`** (default) — the session proceeds normally: the duress share is a real share and counts toward quorum, so the unlock still happens, but the alert fires. Choose this when blocking the unlock would itself endanger the coerced participant ("unlock under duress, but security knows").
- **`poison`** — the session looks normal, but reconstruction silently fails with exactly the same messages as a genuine bad-share failure, and the secret is never reconstructed. To the person watching the terminal it looks like someone submitted a corrupted share. An alert program is optional in this mode.

The alert program runs detached and receives no share or secret data.

> ### ⚠️ Security tradeoff: duress shares halve your collusion threshold
>
> **A duress share is a real Shamir share of the same secret — there is no separate "duress key".** If you hand each participant a normal share *and* a duress share, every person now holds **two of the N shares**. An attacker who coerces enough people therefore needs only **⌈K/2⌉ people instead of K** to collect a quorum of shares. A 3-of-6 where each of 3 people holds two shares can be unlocked by coercing just **2** of them. Shamir's information-theoretic guarantee is intact (K−1 shares still reveal nothing), but the *number of people* an adversary must compromise is roughly **halved**.
>
> Account for this when choosing `-n`/`-k`: if you want a true 3-person floor with per-person duress shares, you need a **5-of-10** scheme (each of 5 people holds 2 shares → 3 people = 6 shares ≥ 5), not 3-of-6. `keyquorum-split --duress` prints this warning with your specific numbers.
>
> **For `poison` mode, every participant needs their own distinct duress share.** Poison only protects against the people who actually hold a duress share; if an attacker coerces three people and none of them holds one, the secret reconstructs normally. Do **not** try to share a single duress index among several people — the daemon rejects duplicate indices, which would both break the unlock and look abnormal.
>
> A future scheme could avoid the halving by making duress shares decoys of a *different* polynomial (so they poison without being valid shares of the real secret). The current implementation does not do this.

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
- **No participant authentication** — anyone with a valid share can submit (share-only trust model). With `log_participation = true` the audit log does record the kernel-verified connecting identity (`SO_PEERCRED` uid/gid/pid on the Unix socket), which cannot be forged — but it is a log, not an access control.
- **Single session at a time** — one unlock operation at a time per daemon instance
- **Metadata envelope is not signed** — PEM headers are convenience-only and can be forged. See [Metadata is not authenticated](#metadata-is-not-authenticated)
- **Threat model does not fully protect against a malicious dealer** — `--output age` encrypts shares to recipients so the operator never sees plaintext, but this is defence-in-depth, not a cryptographic guarantee (the operator still generates the shares). VSS (verifiable secret sharing) is planned for a future version.

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
  -o, --output <OUTPUT>        Output mode: stdout (default), files, or age
  -d, --dir <DIR>              Output directory (required for files and age modes)
      --recipients <FILE>      Age recipients file (required for age mode)
      --armor                  ASCII-armor age output (.age.txt instead of .age)
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
