use anyhow::{bail, Result};
use clap::{Parser, ValueEnum};
use blahaj::Sharks;
use std::io::Read;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

use keyquorum_core::share_format::{self, ShareEncoding, ShareFormatOptions};

#[derive(Parser)]
#[command(
    name = "keyquorum-split",
    about = "Split a secret into Shamir shares",
    long_about = "Split a secret into Shamir shares.\n\n\
        Reads a secret from stdin and generates N shares, any K of which can reconstruct \
        the original. By default, each share is output as a PEM envelope \
        (KEYQUORUM-SHARE-V1) with metadata headers and a CRC32 integrity check, and \
        a blake3 verification checksum is embedded in the secret before splitting.\n\n\
        Use --bare for the V1 binary payload without the PEM envelope, or --no-metadata \
        to keep the envelope but omit the headers.",
    version,
)]
struct Cli {
    /// Total number of shares to generate (2-255)
    #[arg(short = 'n', long)]
    shares: u8,
    /// Minimum shares needed to reconstruct (2-N)
    #[arg(short = 'k', long)]
    threshold: u8,
    /// Output mode
    #[arg(short, long, value_enum, default_value_t = OutputMode::Stdout)]
    output: OutputMode,
    /// Output directory for file-per-share mode
    #[arg(short, long)]
    dir: Option<PathBuf>,
    /// Lockdown mode: rejects stdout output. May gain new restrictions between versions.
    #[arg(long)]
    lockdown: bool,
    /// Do not embed a blake3 verification checksum in the secret before splitting.
    ///
    /// WARNING: without a checksum, retry mode (on_failure="retry") cannot verify
    /// candidate secrets and will execute the configured action (cryptsetup, command,
    /// etc.) with each incorrect key attempt. This may cause repeated failed
    /// invocations of downstream tools.
    #[arg(long)]
    no_checksum: bool,
    /// Skip per-share CRC32 integrity check
    #[arg(long)]
    no_integrity: bool,
    /// Omit metadata headers (share number, threshold, scheme) from PEM envelope
    #[arg(long)]
    no_metadata: bool,
    /// Output V1 binary payload only, no PEM envelope
    #[arg(long)]
    bare: bool,
    /// Payload encoding
    #[arg(long, value_enum, default_value_t = Encoding::Base64)]
    encoding: Encoding,
    /// Disable strict hardening: allow operation if memory protections
    /// (mlock, madvise) fail. Not recommended for production.
    #[arg(long)]
    no_strict_hardening: bool,
    /// File containing age recipients (one age1... public key per line).
    /// Each share is encrypted to the corresponding recipient before writing.
    /// Requires --output age --dir <path>.
    // Future: --encrypt-to for inline comma-separated keys
    #[arg(long, value_name = "FILE")]
    recipients: Option<PathBuf>,
    /// Output age-encrypted shares as ASCII armor (PEM-like text).
    /// Useful for pasting into text-based channels (Signal, email, etc.).
    /// Files get .age.txt extension instead of .age.
    #[arg(long, alias = "armour")]
    armor: bool,
    // Future: --raw-shares for truly raw sharks bytes (no KQ prefix),
    // for interoperability with other Shamir tools.
}

#[derive(Clone, ValueEnum)]
enum OutputMode {
    /// All shares to stdout (labels to stderr)
    Stdout,
    /// One file per share in the output directory
    Files,
    /// Encrypt each share to an age recipient before writing
    Age,
    // Future: Interactive — show one at a time, clear between
}

#[derive(Clone, ValueEnum)]
enum Encoding {
    Base64,
    Base32,
}

fn main() -> Result<()> {
    keyquorum_core::memory::warn_if_not_linux();
    keyquorum_core::memory::harden_process()?;

    let cli = Cli::parse();

    if cli.threshold < 2 {
        bail!("threshold must be at least 2");
    }
    if cli.threshold > cli.shares {
        bail!(
            "threshold ({}) must be <= total shares ({})",
            cli.threshold,
            cli.shares
        );
    }

    if matches!(cli.output, OutputMode::Files | OutputMode::Age) && cli.dir.is_none() {
        bail!("--dir is required when using --output files or --output age");
    }

    if matches!(cli.output, OutputMode::Age) && cli.recipients.is_none() {
        bail!("--recipients is required when using --output age");
    }

    if cli.recipients.is_some() && !matches!(cli.output, OutputMode::Age) {
        bail!("--recipients requires --output age");
    }

    if cli.armor && !matches!(cli.output, OutputMode::Age) {
        bail!("--armor requires --output age");
    }

    if cli.lockdown && matches!(cli.output, OutputMode::Stdout) {
        bail!("lockdown mode rejects --output stdout: shares must not appear in terminal output. Use --output files --dir <path>");
    }

    // Read secret from stdin
    let mut secret = Vec::new();
    std::io::stdin().read_to_end(&mut secret)?;

    // Strip trailing newline if present (common when piping from echo)
    if secret.last() == Some(&b'\n') {
        secret.pop();
    }

    if secret.is_empty() {
        bail!("no secret provided on stdin");
    }

    // Embed blake3 verification checksum (default behavior).
    // Done before protect_secret so the final buffer (with checksum) is what gets mlocked.
    if !cli.no_checksum {
        // Reserve upfront to avoid reallocation after mlock
        secret.reserve(32);
        let hash = blake3::hash(&secret);
        secret.extend_from_slice(hash.as_bytes());
        eprintln!("Embedded blake3 verification checksum (32 bytes)");
        eprintln!("Use verification = \"embedded-blake3\" in daemon config.");
    } else {
        eprintln!("WARNING: no checksum embedded. If on_failure=\"retry\" is used,");
        eprintln!("the daemon will execute the configured action with each incorrect");
        eprintln!("candidate secret, causing repeated failed invocations of downstream tools.");
        eprintln!("Use verification = \"none\" in daemon config.");
    }

    // Apply memory protections to the final secret buffer (including checksum if appended)
    let strict_hardening = !cli.no_strict_hardening || cli.lockdown;
    if !strict_hardening {
        eprintln!("WARNING: strict_hardening disabled — memory protections will not be enforced");
    }
    let failures = keyquorum_core::memory::protect_secret(&secret);
    if !failures.is_empty() {
        for (name, err) in &failures {
            eprintln!("warning: memory protection {} failed: {}", name, err);
        }
        if strict_hardening {
            bail!("strict_hardening: failed to apply memory protections to secret");
        }
    }

    // Generate shares
    let sharks = Sharks(cli.threshold);
    let dealer = sharks.dealer(&secret);
    let shares: Vec<blahaj::Share> = dealer.take(cli.shares as usize).collect();

    // Build format options from CLI flags
    let encoding = match cli.encoding {
        Encoding::Base64 => ShareEncoding::Base64,
        Encoding::Base32 => ShareEncoding::Base32,
    };

    // Output shares
    match cli.output {
        OutputMode::Stdout => output_stdout(&shares, &cli, encoding),
        OutputMode::Files => {
            output_files(&shares, &cli, encoding, cli.dir.as_ref().expect("validated above"))?
        }
        OutputMode::Age => {
            let recipients = parse_recipients_file(
                cli.recipients.as_ref().expect("validated above"),
            )?;
            if recipients.len() > shares.len() {
                bail!(
                    "too many recipients: {} recipients for {} shares",
                    recipients.len(),
                    shares.len()
                );
            }
            if recipients.len() < shares.len() {
                if cli.lockdown {
                    bail!(
                        "lockdown mode requires exactly {} recipients (one per share), got {}",
                        shares.len(),
                        recipients.len()
                    );
                }
                eprintln!(
                    "WARNING: {} recipients for {} shares — {} shares will be written unencrypted",
                    recipients.len(),
                    shares.len(),
                    shares.len() - recipients.len()
                );
            }
            output_age(
                &shares,
                &cli,
                encoding,
                cli.dir.as_ref().expect("validated above"),
                &recipients,
            )?
        }
    }

    // Zeroize and unlock secret
    secret.zeroize();
    if let Err(e) = keyquorum_core::memory::munlock_slice(&secret) {
        eprintln!("warning: munlock failed: {}", e);
    }

    Ok(())
}

fn make_format_opts(cli: &Cli, encoding: ShareEncoding, share_number: u8) -> ShareFormatOptions {
    ShareFormatOptions {
        encoding,
        include_crc32: !cli.no_integrity,
        include_envelope: !cli.bare,
        include_metadata: !cli.no_metadata && !cli.bare,
        share_number,
        total_shares: cli.shares,
        threshold: cli.threshold,
    }
}

fn output_stdout(shares: &[blahaj::Share], cli: &Cli, encoding: ShareEncoding) {
    for (i, share) in shares.iter().enumerate() {
        let mut sharks_data: Vec<u8> = Vec::from(share);
        let index = sharks_data[0];
        let opts = make_format_opts(cli, encoding, (i + 1) as u8);
        let mut formatted = share_format::format_share(&sharks_data, &opts);
        eprintln!("Share {} (index {}):", i + 1, index);
        println!("{}", formatted);
        sharks_data.zeroize();
        formatted.zeroize();
    }
}

fn output_files(
    shares: &[blahaj::Share],
    cli: &Cli,
    encoding: ShareEncoding,
    dir: &PathBuf,
) -> Result<()> {
    std::fs::create_dir_all(dir).map_err(|e| {
        anyhow::anyhow!("failed to create output directory {}: {}", dir.display(), e)
    })?;

    for (i, share) in shares.iter().enumerate() {
        let mut sharks_data: Vec<u8> = Vec::from(share);
        let index = sharks_data[0];
        let opts = make_format_opts(cli, encoding, (i + 1) as u8);
        let mut formatted = share_format::format_share(&sharks_data, &opts);
        let filename = dir.join(format!("share-{}.txt", i + 1));
        let write_result =
            std::fs::write(&filename, format!("{}\n", formatted));
        sharks_data.zeroize();
        formatted.zeroize();
        write_result.map_err(|e| {
            anyhow::anyhow!("failed to write {}: {}", filename.display(), e)
        })?;
        eprintln!(
            "Share {} (index {}) written to {}",
            i + 1,
            index,
            filename.display()
        );
    }

    eprintln!(
        "\n{} share files written to {}",
        shares.len(),
        dir.display()
    );
    eprintln!("Distribute each file to its holder, then delete this directory.");

    Ok(())
}

fn parse_recipients_file(path: &Path) -> Result<Vec<age::x25519::Recipient>> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("failed to read recipients file {}: {}", path.display(), e))?;

    let mut recipients = Vec::new();
    for (line_num, line) in contents.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let recipient: age::x25519::Recipient = trimmed.parse().map_err(|e| {
            anyhow::anyhow!(
                "invalid age recipient on line {} of {}: {} ({})",
                line_num + 1,
                path.display(),
                trimmed,
                e
            )
        })?;
        recipients.push(recipient);
    }

    if recipients.is_empty() {
        bail!("no valid age recipients found in {}", path.display());
    }

    Ok(recipients)
}

fn output_age(
    shares: &[blahaj::Share],
    cli: &Cli,
    encoding: ShareEncoding,
    dir: &PathBuf,
    recipients: &[age::x25519::Recipient],
) -> Result<()> {
    std::fs::create_dir_all(dir).map_err(|e| {
        anyhow::anyhow!("failed to create output directory {}: {}", dir.display(), e)
    })?;

    for (i, share) in shares.iter().enumerate() {
        let mut sharks_data: Vec<u8> = Vec::from(share);
        let index = sharks_data[0];
        let opts = make_format_opts(cli, encoding, (i + 1) as u8);
        let mut formatted = share_format::format_share(&sharks_data, &opts);

        if i < recipients.len() {
            // Encrypt to the corresponding recipient.
            // Note: age's internal plaintext buffers are outside our zeroize scope,
            // same boundary as blahaj internals.
            let filename = if cli.armor {
                dir.join(format!("share-{}.txt.age.txt", i + 1))
            } else {
                dir.join(format!("share-{}.txt.age", i + 1))
            };

            let write_result = if cli.armor {
                let armored = age::encrypt_and_armor(&recipients[i], formatted.as_bytes())
                    .map_err(|e| anyhow::anyhow!("failed to encrypt share {}: {}", i + 1, e))?;
                std::fs::write(&filename, armored.as_bytes())
            } else {
                let encrypted = age::encrypt(&recipients[i], formatted.as_bytes())
                    .map_err(|e| anyhow::anyhow!("failed to encrypt share {}: {}", i + 1, e))?;
                std::fs::write(&filename, &encrypted)
            };

            sharks_data.zeroize();
            formatted.zeroize();

            write_result.map_err(|e| {
                anyhow::anyhow!("failed to write {}: {}", filename.display(), e)
            })?;

            eprintln!(
                "Share {} (index {}) encrypted and written to {}",
                i + 1,
                index,
                filename.display()
            );
        } else {
            // No recipient for this share — write unencrypted (warning already emitted)
            let filename = dir.join(format!("share-{}.txt", i + 1));
            let write_result = std::fs::write(&filename, format!("{}\n", formatted));

            sharks_data.zeroize();
            formatted.zeroize();

            write_result.map_err(|e| {
                anyhow::anyhow!("failed to write {}: {}", filename.display(), e)
            })?;

            eprintln!(
                "Share {} (index {}) written UNENCRYPTED to {}",
                i + 1,
                index,
                filename.display()
            );
        }
    }

    let encrypted_count = std::cmp::min(recipients.len(), shares.len());
    let unencrypted_count = shares.len() - encrypted_count;
    eprintln!(
        "\n{} share files written to {} ({} encrypted, {} unencrypted)",
        shares.len(),
        dir.display(),
        encrypted_count,
        unencrypted_count,
    );
    if unencrypted_count == 0 {
        eprintln!("Distribute each .age file to its holder. They decrypt with: age -d -i identity.txt share-N.txt.age");
    } else {
        eprintln!("Distribute each file to its holder, then delete this directory.");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn generate_test_pubkeys(n: usize) -> Vec<String> {
        (0..n)
            .map(|_| {
                let identity = age::x25519::Identity::generate();
                identity.to_public().to_string()
            })
            .collect()
    }

    fn write_temp_file(contents: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        f
    }

    #[test]
    fn parse_recipients_valid() {
        let keys = generate_test_pubkeys(3);
        let contents = format!(
            "# Alice\n{}\n\n# Bob\n{}\n# Carol\n{}\n",
            keys[0], keys[1], keys[2]
        );
        let f = write_temp_file(&contents);
        let recipients = parse_recipients_file(f.path()).unwrap();
        assert_eq!(recipients.len(), 3);
    }

    #[test]
    fn parse_recipients_empty() {
        let f = write_temp_file("# only comments\n\n# another comment\n");
        let err = parse_recipients_file(f.path()).unwrap_err();
        assert!(
            err.to_string().contains("no valid age recipients"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn parse_recipients_invalid_key() {
        let keys = generate_test_pubkeys(1);
        let contents = format!("{}\nnot-a-valid-key\n", keys[0]);
        let f = write_temp_file(&contents);
        let err = parse_recipients_file(f.path()).unwrap_err();
        assert!(
            err.to_string().contains("line 2"),
            "expected line number in error: {}",
            err
        );
        assert!(
            err.to_string().contains("not-a-valid-key"),
            "expected offending content in error: {}",
            err
        );
    }

    #[test]
    fn parse_recipients_whitespace() {
        let keys = generate_test_pubkeys(2);
        let contents = format!("  {}  \n\t{}\t\n", keys[0], keys[1]);
        let f = write_temp_file(&contents);
        let recipients = parse_recipients_file(f.path()).unwrap();
        assert_eq!(recipients.len(), 2);
    }
}
