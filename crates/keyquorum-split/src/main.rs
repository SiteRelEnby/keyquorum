use anyhow::{bail, Result};
use base64::Engine;
use clap::Parser;
use sharks::Sharks;
use std::io::Read;
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

    // mlock the secret buffer
    let _ = keyquorum_core::memory::mlock_slice(&secret);

    // Generate shares
    let sharks = Sharks(cli.threshold);
    let dealer = sharks.dealer(&secret);
    let shares: Vec<sharks::Share> = dealer.take(cli.shares as usize).collect();

    // Output each share
    let engine = base64::engine::general_purpose::STANDARD;
    for (i, share) in shares.iter().enumerate() {
        let bytes: Vec<u8> = Vec::from(share);
        let index = bytes[0];
        let encoded = engine.encode(&bytes);
        eprintln!("Share {} (index {}):", i + 1, index);
        println!("{}", encoded);
    }

    // Zeroize secret
    secret.zeroize();
    let _ = keyquorum_core::memory::munlock_slice(&secret);

    Ok(())
}
