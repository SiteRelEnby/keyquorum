# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Build
- CI `audit` job now runs `cargo audit` directly (instead of `rustsec/audit-check`) so it honors `.cargo/audit.toml`, and that file suppresses RUSTSEC-2026-0173 (`proc-macro-error2` unmaintained) and RUSTSEC-2026-0097 (`rand` unsound only under a custom-logger + `rand::rng()` pattern keyquorum never uses). Both are transitive, warning-class, with no upgrade path. Mirrors the existing `deny.toml` ignore.

## [0.2.0] - 2026-06-12

### Added
- `keyquorum verify` — offline recovery drill: reconstructs a set of shares in hardened memory purely to confirm the embedded blake3 checksum matches, then wipes everything and prints only PASS/FAIL plus which indices reconstructed. Never reveals the secret or runs an action. Threshold is read from share metadata (override with `-k`). Lets operators schedule backup-integrity checks of distributed shares.
- `keyquorum daemon --check-config` — validate the config (applying lockdown/CLI overrides), print the effective settings, and exit without starting the daemon. Surfaces overrides (e.g. lockdown forcing `on_failure = wipe`) and rejects unknown keys.
- `justfile` with dev recipes (`just gate` runs fmt-check + clippy + test + e2e; plus `fuzz`, `build`, `audit`).
- Age-encrypted share output: `--output age --recipients <file>` encrypts each share to a specific recipient's age public key before writing to disk. The split operator never sees plaintext shares. One `age1...` key per line in the recipients file (line order = share order). In lockdown mode, recipient count must exactly match share count.
- `--armor` / `--armour` flag for ASCII-armored age output (`.age.txt` files), useful for text-based channels (Signal, email, etc.)
- `action_timeout_secs` config option (default 120) — bounds post-reconstruction action execution. Previously a hung action (stuck cryptsetup, command that never exits) blocked the session task forever, freezing all clients and bypassing the session timeout. On timeout the child process is killed, shares are wiped, and the session resets.
- `pid_file` daemon config option is now implemented (was previously parsed but ignored)
- SIGTERM is now handled for graceful shutdown (previously only SIGINT), so `systemctl stop` cleans up the socket and pid file
- Envelope `Share:` header share numbers are now range-checked against `total_shares` when `require_metadata` is enabled
- Participation logging (`log_participation = true`) now records the kernel-verified peer identity (`SO_PEERCRED` uid/gid/pid for Unix socket connections, remote address for TCP) alongside the client-claimed `submitted_by`. Unlike `submitted_by`, the peer field cannot be forged by the client.
- Hardened systemd unit file (`contrib/systemd/keyquorum.service`): `LimitMEMLOCK=infinity`, `RuntimeDirectory=keyquorum`, `ProtectSystem=strict`, `MemoryDenyWriteExecute`, and related sandboxing on top of the daemon's own process hardening
- Interactive output mode for in-person key ceremonies (`--output interactive`): shows one share at a time on the controlling terminal (`/dev/tty`), waits for Enter between holders, and clears the screen (including scrollback where supported) between and after shares. Rejected in lockdown mode like stdout output.
- Duress (canary) shares (`[session.duress]`): designated share indices that trigger an alert program when submitted, with the submission otherwise indistinguishable from any other accepted share (same response, status, and logs — detection is never logged, since host logs may be visible to a coercer; the alert program is the only channel). `mode = "alert"` lets the session proceed (unlock under duress); `mode = "poison"` makes reconstruction silently fail with the same messages as a genuine bad-share failure. `keyquorum-split --duress N` designates and reports the duress shares, emits a ready-to-paste config block, and prints the key security tradeoff: because each duress share is a real Shamir share, giving each participant a duress share roughly **halves the people-collusion threshold** (an attacker needs ⌈K/2⌉ people, not K). Documented prominently in the README.

### Changed
- Terminal session states (`Completed`, `Failed`, `TimedOut`) are now held and visible via `status` until the next session starts, instead of resetting straight to `Idle`. Submitting a share while in a terminal state starts a fresh session (shares are still wiped at the transition, as before).

### Fixed
- **Locked memory pages were never released.** `Vec::zeroize()` clears the Vec before `munlock` runs, so every munlock call was a no-op on an empty slice, and share buffers were never munlocked at all. Locked pages accumulated for the life of the daemon; under a memlock rlimit with `strict_hardening` enabled, the daemon would eventually reject all shares until restarted. Wiping now goes through `wipe_and_unlock()`, which zeroizes contents and capacity, munlocks while the region is still addressable, then clears.
- Unknown config keys are now rejected at startup (`deny_unknown_fields`) — previously a typo like `lockdwon = true` silently fell back to the less secure default
- Unix socket is now bound under a restrictive umask — previously there was a brief window between bind and chmod where umask-default permissions could allow any local user to connect
- Blake3 secret verification now uses `blake3::Hash`'s constant-time comparison (was comparing raw byte slices)
- More transient share/secret buffers are zeroized: client stdin read buffer and early-exit error paths, daemon connection line buffer, share-format decode intermediates (including the losing candidate in base64/base32 disambiguation), and the age encryption error path
- Corrected age CLI install hint (`pip install age` installs an unofficial Python reimplementation; the reference CLI comes from distro packages or age-encryption.org)

### Build
- `deny.toml` ignores RUSTSEC-2026-0173 (`proc-macro-error2` unmaintained). It is a build-time-only proc-macro helper reached transitively via `age` → `i18n-embed-fl`, with no upgrade path (i18n-embed-fl 0.9.4 is latest and still depends on it) and no presence in the runtime binary. Not a vulnerability; revisit when `age` drops `i18n-embed-fl`.

## [0.1.1] - 2025-06-14

### Fixed
- `require_metadata` now validates that shares have complete metadata (Share header with share_number, total_shares, and threshold) — previously accepted shares with any single PEM header as "having metadata"
- Action stderr (from cryptsetup or command actions) no longer leaks to clients — clients now receive only the exit code, stderr is logged at debug level only
- Transient share buffers in `keyquorum-split` output paths and `submit` client JSON serialization are now explicitly zeroized after use

### Changed
- Manual approval gate added to the release workflow — requires a maintainer to approve in the GitHub "release" environment before publishing to crates.io or creating a GitHub release

## [0.1.0] - 2025-06-14

### Added
- V1 share format with PEM envelope, binary encoding (`KQ` magic + version + flags + optional CRC32 + sharks data), and base64/base32 encoding support
- Embedded blake3 secret verification — `keyquorum-split` appends a 32-byte blake3 hash to the secret before splitting; daemon verifies candidates in microseconds without executing actions
- Lazy combinatorial iteration (`ComboIter`) for retry mode — generates C(n,k) combinations on-demand, capped by `max_combinations` config
- `strict_hardening` config option (default true) — rejects shares if memory protections (mlock, madvise) fail; `--no-strict-hardening` CLI flag to disable
- `require_metadata` config option — when true, rejects shares without PEM envelope metadata
- `--lockdown` mode — rejects stdout action, forces `on_failure = "wipe"`, implies strict_hardening
- Interactive stdin mode for `submit` — detects TTY, prompts for share input with double-Enter or Ctrl+D termination
- GitHub Actions CI with clippy, cargo-audit, and cargo-deny (license + advisory checks)
- Release workflow with cross-compilation (x86_64/aarch64 Linux, experimental macOS), crates.io publishing, and GitHub Releases
- End-to-end test scripts (`tests/e2e-stdout.sh`, `tests/e2e-luks.sh`) exercising compiled binaries
- Platform detection with startup warning on non-Linux systems
- `AGENTS.md`, `CONTRIBUTING.md`, `SECURITY.md`

### Changed
- Migrated from `sharks` to `blahaj` (maintained fork) — fixes RUSTSEC-2024-0398 (polynomial coefficient bias) and ships with `zeroize_memory` enabled by default
- `--share`/`-s` CLI argument removed — share data is now stdin-only to avoid exposure via `/proc/cmdline` and shell history

### Security
- RUSTSEC-2024-0398: `sharks` polynomial coefficients were sampled from [1, 255] instead of [0, 255], introducing a slight bias. Resolved by migrating to `blahaj` which includes the upstream fix.
- Share data no longer accepted via command-line argument (was readable via `/proc/$pid/cmdline` by any user on the system)
- Action stderr no longer forwarded to clients (could leak secret material from misbehaving scripts)
- Transient buffers containing share data are now zeroized after use in split output and client submission paths

## [0.1.0-alpha.1] - 2025-06-13

### Added
- Initial public pre-release
- Shamir secret sharing daemon with Unix socket and optional TCP (localhost) listeners
- Session state machine: Idle → Collecting → Reconstructing → Completed/Failed
- Actions: LUKS unlock (`cryptsetup luksOpen`), stdout, arbitrary command
- Retry-on-failure mode with combinatorial share matching
- Memory hardening: `mlock`, `madvise(MADV_DONTFORK)`, `madvise(MADV_DONTDUMP)`, `prctl(PR_SET_DUMPABLE, 0)`, `prctl(PR_SET_NO_NEW_PRIVS, 1)`
- `keyquorum-split` tool for generating shares from stdin with file or stdout output
- 127 unit and integration tests
- Newline-delimited JSON protocol over Unix socket or TCP

[0.2.0]: https://github.com/SiteRelEnby/keyquorum/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/SiteRelEnby/keyquorum/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/SiteRelEnby/keyquorum/compare/v0.1.0-alpha.1...v0.1.0
[0.1.0-alpha.1]: https://github.com/SiteRelEnby/keyquorum/releases/tag/v0.1.0-alpha.1
