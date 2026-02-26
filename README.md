# keyquorum

Shamir secret sharing daemon for distributed teams. Split a secret into shares, distribute them to team members, and reconstruct the secret only when a quorum submits their shares. Nobody ever handles someone else's share or sees the reconstructed key.

Built for unlocking LUKS partitions, but works with anything that takes a key on stdin.

## Install

```bash
cargo install keyquorum keyquorum-split
```

Or build from source:

```bash
cargo build --release
# binaries at target/release/keyquorum and target/release/keyquorum-split
```

## Quick start

### 1. Generate shares

```bash
# Split a secret into 5 shares, any 3 can reconstruct (3-of-5)
echo -n "my-secret-key" | keyquorum-split -n 5 -k 3

# Or write one file per share for easier distribution
echo -n "my-secret-key" | keyquorum-split -n 5 -k 3 -o files -d ./shares/
```

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

# OR: write secret to daemon's stdout
# [action]
# type = "stdout"

# OR: pipe secret to any command's stdin
# [action]
# type = "command"
# program = "/usr/local/bin/unseal-vault"
# args = ["--cluster", "prod"]
```

### 3. Start the daemon

```bash
keyquorum daemon -c /etc/keyquorum/config.toml
```

### 4. Team members submit shares

Each participant SSHes in, etc. and submits their share:

```bash
keyquorum submit -s "BASE64_SHARE_DATA" -c /etc/keyquorum/config.toml
keyquorum submit -s "BASE64_SHARE_DATA" -c /etc/keyquorum/config.toml

# Check progress
keyquorum status -c /etc/keyquorum/config.toml
```

When the threshold is reached, the secret is reconstructed and the configured action runs automatically. All shares are wiped from memory immediately after.

## Security

This is a security-critical tool. The design assumes the host is trusted but participants may not be in the same room.

**Memory protection:**
- `mlock()` on all buffers containing shares or the reconstructed secret — never swapped to disk
- `madvise(MADV_DONTFORK)` on secret buffers — no copy-on-write leaks to child processes
- `Zeroize` on drop for all sensitive data
- Reconstructed secret is used immediately then wiped

**Process hardening:**
- `prctl(PR_SET_DUMPABLE, 0)` at startup — no core dumps, no `/proc/self/mem` reads

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
      --lockdown         Lockdown mode: maximum security posture
```

**`keyquorum submit`**
```
Options:
  -s, --share <SHARE>    Share data (base64). If omitted, reads from stdin
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
      --no-checksum            Do not embed blake3 verification checksum
```

## Protocol

Newline-delimited JSON over Unix socket or TCP. See `example-config.toml` for configuration options.

```
Client → Daemon:  {"type":"submit_share","share":{"index":3,"data":"<base64>"}}
Client → Daemon:  {"type":"status"}
Daemon → Client:  {"type":"share_accepted","status":{...}}
Daemon → Client:  {"type":"quorum_reached","action_result":{...}}
```

## License

Apache-2.0
