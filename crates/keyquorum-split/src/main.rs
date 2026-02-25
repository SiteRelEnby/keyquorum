use anyhow::{bail, Result};
use base64::Engine;
use clap::{Parser, ValueEnum};
use sharks::Sharks;
use std::io::Read;
use std::path::PathBuf;
use zeroize::Zeroize;

#[derive(Parser)]
#[command(name = "keyquorum-split", about = "Split a secret into Shamir shares", version)]
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
}

#[derive(Clone, ValueEnum)]
enum OutputMode {
    /// All shares to stdout (labels to stderr)
    Stdout,
    /// One file per share in the output directory
    Files,
    // Future modes:
    // Interactive — show one at a time, clear between
    // Age — encrypt each share to a recipient's age public key
}

fn main() -> Result<()> {
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

    if matches!(cli.output, OutputMode::Files) && cli.dir.is_none() {
        bail!("--dir is required when using --output files");
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

    // Apply memory protections to the secret buffer
    let failures = keyquorum_core::memory::protect_secret(&secret);
    if !failures.is_empty() {
        for (name, err) in &failures {
            eprintln!("warning: memory protection {} failed: {}", name, err);
        }
        if cli.lockdown {
            bail!("lockdown mode: failed to apply memory protections to secret");
        }
    }

    // Generate shares
    let sharks = Sharks(cli.threshold);
    let dealer = sharks.dealer(&secret);
    let shares: Vec<sharks::Share> = dealer.take(cli.shares as usize).collect();

    // Output shares
    let engine = base64::engine::general_purpose::STANDARD;
    match cli.output {
        OutputMode::Stdout => output_stdout(&shares, &engine),
        OutputMode::Files => {
            output_files(&shares, &engine, cli.dir.as_ref().expect("validated above"))?
        }
    }

    // Zeroize and unlock secret
    secret.zeroize();
    if let Err(e) = keyquorum_core::memory::munlock_slice(&secret) {
        eprintln!("warning: munlock failed: {}", e);
    }

    Ok(())
}

fn output_stdout(shares: &[sharks::Share], engine: &base64::engine::GeneralPurpose) {
    for (i, share) in shares.iter().enumerate() {
        let bytes: Vec<u8> = Vec::from(share);
        let index = bytes[0];
        let encoded = engine.encode(&bytes);
        eprintln!("Share {} (index {}):", i + 1, index);
        println!("{}", encoded);
    }
}

fn output_files(
    shares: &[sharks::Share],
    engine: &base64::engine::GeneralPurpose,
    dir: &PathBuf,
) -> Result<()> {
    std::fs::create_dir_all(dir).map_err(|e| {
        anyhow::anyhow!("failed to create output directory {}: {}", dir.display(), e)
    })?;

    for (i, share) in shares.iter().enumerate() {
        let bytes: Vec<u8> = Vec::from(share);
        let index = bytes[0];
        let encoded = engine.encode(&bytes);
        let filename = dir.join(format!("share-{}.txt", i + 1));
        std::fs::write(&filename, format!("{}\n", encoded)).map_err(|e| {
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
