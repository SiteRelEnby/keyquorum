# AGENTS.md — Guidelines for AI Agents and Contributors

This file is for AI coding agents (Claude Code, Copilot, Codex, Cursor, etc.) and human contributors working on keyquorum. Read this before writing code or opening a PR.

See `CLAUDE.md` for detailed architecture, crate layout, protocol spec, and gotchas.

## What This Is

A security-critical tool for Shamir secret sharing. Shares protect real secrets (LUKS disk encryption keys, production credentials). Mistakes here can leak secrets or lock people out of their data. Act accordingly.

## Guiding Principles

### Memory safety is non-negotiable

Every buffer that touches share data or reconstructed secrets must be:

- **Zeroized** after use (`zeroize` crate, `Zeroize`/`ZeroizeOnDrop` derives)
- **mlocked** to prevent swapping to disk
- **DONTFORK'd** to prevent copy-on-write leaks to child processes
- **DONTDUMP'd** to exclude from core dumps

If you allocate a `Vec<u8>` or `String` that holds share data, even transiently, it must be zeroized before it's dropped. `Vec::truncate()` does NOT zero the capacity — you must zeroize first, then truncate. Review every code path: if a function returns early or errors out, are intermediate buffers still zeroized?

The session task is the **single owner** of all secret material. Do not introduce `Arc<Mutex>` or shared references to secrets. The mpsc/oneshot channel pattern exists for a reason.

### No secret material in logs, errors, or client messages

Share values and reconstructed secrets must never appear in:
- Log messages (any level)
- Error messages returned to clients
- CLI output (stderr or stdout, except for the explicit `stdout` action)
- Debug trait implementations

Action stderr (e.g., from cryptsetup) is logged at `debug` level on the daemon only — never sent to clients, as a misbehaving script could echo the secret.

### Backward compatibility

Do not break:
- The V1 share format (binary encoding or PEM envelope)
- The NDJSON protocol (client/daemon messages)
- Existing config file fields and their defaults
- CLI argument names and behavior

New features should be additive. New config fields must have sensible defaults that preserve existing behavior. If a share format change is needed, use a new version byte (V2), not modifications to V1.

### Don't layer on top of Shamir

Do not implement Feldman VSS, Pedersen VSS, or other verifiable secret sharing schemes as wrappers around the existing `blahaj` Shamir implementation. These schemes have fundamentally different share structures, verification mechanisms, and security properties. If VSS support is added, it should be a separate scheme implementation (likely via `vsss-rs`), selectable via a `Scheme:` header in the share format, not a bolt-on.

Similarly, do not implement custom cryptographic constructions. Use established libraries (`blake3`, `blahaj`, `age`, etc.). If you think you need custom crypto, you're wrong. [This includes attempting novel constructions using 'safe' primitives from widely implemented libraries](https://soatok.blog/2025/01/31/hell-is-overconfident-developers-writing-encryption-code/).

### Test coverage

- Every new feature or bug fix needs tests
- Security-sensitive changes need tests that verify the *negative* case (rejection, zeroization, error handling)
- `cargo test` must pass, `cargo clippy --all-targets -- -D warnings` must be clean
- E2E tests in `tests/` cover real binary invocations — update them if CLI behavior changes
- Don't break the existing ~127 unit tests or ~8 E2E tests

### Threat model awareness

Understand what we defend against and what we don't:

**In scope:**
- Share data leaking via memory (swap, core dumps, CoW, `/proc`)
- Share data leaking via process table, shell history, logs
- Incorrect reconstruction (wrong shares) executing dangerous actions
- Misbehaving action scripts leaking secrets via stderr
- Local privilege escalation via child processes (setuid/setgid)

**Explicitly out of scope (documented limitations):**
- Malicious participants with valid shares (share-only trust model, no authentication yet)
- Network attackers (TCP is localhost-only, remote access is via SSH tunnels)
- Boot volume encryption (daemon can't run before the OS)
- Cryptographic signing of share metadata (PEM headers are advisory only)

Don't add mitigations for out-of-scope threats without discussion. Don't remove existing mitigations.

## Common Pitfalls

These are things that have actually caused bugs in this codebase:

- **`blahaj` (Shamir library) assigns random x-coordinates**, not sequential 1,2,3. Don't assume share indices are predictable. In tests, corrupt bytes within same-split shares rather than mixing shares from different splits.
- **`blahaj::Sharks::recover` always produces output**, even with wrong shares. The embedded blake3 checksum is how we verify correctness, not the reconstruction itself.
- **`ParsedShare` implements `ZeroizeOnDrop`** — you cannot move fields out of it. Clone what you need before it drops.
- **`DaemonMessage` does not implement `Debug`** — use `serde_json::to_string()` for debug output in tests.
- **`Vec::truncate()` leaves data in capacity** — zeroize the bytes first, then truncate.
- **Base32 strings can be valid base64** — `decode_bytes_smart()` handles disambiguation via KQ magic bytes. Don't bypass it.
- **`strict_hardening` and `lockdown` are separate concepts** — lockdown is about operational restrictions (no stdout action, force wipe). Strict hardening is about whether to abort on memory protection failures. Lockdown implies strict_hardening, but not vice versa.
- **`log_participation` is a privacy boundary** — when it's off, log the *event* but not the *user identity*. Don't add user-identifying information to log messages without checking this flag.
- **Linux-only APIs** — `prctl`, `MADV_DONTFORK`, `MADV_DONTDUMP` are gated behind `#[cfg(target_os = "linux")]`. macOS builds are best-effort. Don't add new Linux-only calls without cfg gates.

## PR Expectations

- Explain *why*, not just *what*
- Security-relevant changes need extra scrutiny — explain the threat model implications
- Don't introduce new dependencies without justification (especially for a security tool)
- Run `cargo test`, `cargo clippy`, and ideally `tests/e2e-stdout.sh` before submitting
- If you're an AI agent: state that in the PR description. It's fine, just be transparent.

## Build & Test

```bash
cargo test                           # unit tests
cargo clippy --all-targets           # lint
cargo build --release                # optimized binaries
bash tests/e2e-stdout.sh             # E2E (stdout mode, no root needed)
sudo bash tests/e2e-luks.sh          # E2E (LUKS, needs root + cryptsetup)
```
