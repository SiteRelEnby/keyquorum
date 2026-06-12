//! Offline share verification — the "recovery drill".
//!
//! Reconstructs a secret from a set of shares purely to confirm that some K of
//! them produce a secret whose embedded blake3 checksum matches, then discards
//! it. The reconstructed secret is never printed, written, or returned — only a
//! pass/fail verdict and which share indices reconstructed it. This lets an
//! operator periodically confirm that distributed shares still reconstruct
//! WITHOUT exposing the secret or running the configured action.
//!
//! The verification relies on the embedded blake3 checksum (the default in
//! keyquorum-split). Shares generated with `--no-checksum` cannot be verified
//! this way, because there is nothing to check the reconstruction against
//! short of revealing the secret.

use std::collections::HashSet;
use std::path::PathBuf;

use anyhow::{bail, Result};
use zeroize::Zeroize;

use crate::daemon::session::ComboIter;

pub enum VerifyOutcome {
    /// A checksum-valid secret was reconstructed from these share indices.
    Verified {
        used_indices: Vec<u8>,
        payload_len: usize,
    },
    /// No tried combination produced a checksum-valid secret.
    NoValidCombination,
}

/// Try up to `max_combinations` K-subsets of `shares`; return `Verified` if any
/// reconstructs a secret with a matching embedded blake3 checksum. The
/// candidate secret is memory-protected while in use and wiped immediately —
/// it never leaves this function.
pub fn verify_shares(
    shares: &[(u8, Vec<u8>)],
    threshold: u8,
    max_combinations: usize,
) -> VerifyOutcome {
    let k = threshold as usize;
    let n = shares.len();
    if n < k {
        return VerifyOutcome::NoValidCombination;
    }
    let sharks = blahaj::Sharks(threshold);

    for combo in ComboIter::new(n, k).take(max_combinations) {
        let subset: Vec<blahaj::Share> = combo
            .iter()
            .filter_map(|&i| blahaj::Share::try_from(shares[i].1.as_slice()).ok())
            .collect();
        if subset.len() != k {
            continue;
        }
        let mut secret = match sharks.recover(&subset) {
            Ok(s) => s,
            Err(_) => continue,
        };
        if secret.len() < 32 {
            secret.zeroize();
            continue;
        }
        // Protect the candidate while we hash it, then wipe + munlock.
        let _ = keyquorum_core::memory::protect_secret(&secret);
        let payload_len = secret.len() - 32;
        // blake3::Hash's PartialEq<[u8]> is constant-time.
        let ok = blake3::hash(&secret[..payload_len]) == secret[payload_len..];
        keyquorum_core::memory::wipe_and_unlock(&mut secret);
        if ok {
            let used_indices = combo.iter().map(|&i| shares[i].0).collect();
            return VerifyOutcome::Verified {
                used_indices,
                payload_len,
            };
        }
    }
    VerifyOutcome::NoValidCombination
}

/// CLI entry point for `keyquorum verify`. Reads each share file, reconstructs
/// offline, and prints PASS/FAIL without ever revealing the secret.
pub fn run(files: Vec<PathBuf>, threshold: Option<u8>, max_combinations: usize) -> Result<()> {
    // No core dumps / /proc/self/mem while a secret is briefly in memory.
    keyquorum_core::memory::harden_process()?;

    if files.is_empty() {
        bail!("no share files given; usage: keyquorum verify [-k N] <share-file>...");
    }
    if max_combinations == 0 {
        bail!("--max-combinations must be > 0");
    }

    let mut shares: Vec<(u8, Vec<u8>)> = Vec::new();
    let mut meta_threshold: Option<u8> = None;
    let mut seen = HashSet::new();

    for path in &files {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("failed to read {}: {}", path.display(), e))?;
        let parsed = keyquorum_core::share_format::parse_share(&content)
            .map_err(|e| anyhow::anyhow!("{}: invalid share: {}", path.display(), e))?;

        // Pick up the threshold from envelope metadata if present (first wins).
        if let Some(meta) = &parsed.metadata {
            if let Some(t) = meta.threshold {
                meta_threshold.get_or_insert(t);
            }
        }

        let idx = parsed.index;
        let mut bytes = parsed.sharks_data.clone();
        drop(parsed);

        if blahaj::Share::try_from(bytes.as_slice()).is_err() {
            bytes.zeroize();
            wipe_all(&mut shares);
            bail!("{}: not a valid share", path.display());
        }
        if !seen.insert(idx) {
            eprintln!(
                "warning: duplicate share index {} ({}), skipping",
                idx,
                path.display()
            );
            bytes.zeroize();
            continue;
        }
        let _ = keyquorum_core::memory::protect_secret(&bytes);
        shares.push((idx, bytes));
    }

    let k = match threshold.or(meta_threshold) {
        Some(k) => k,
        None => {
            wipe_all(&mut shares);
            bail!(
                "threshold unknown: pass -k/--threshold (the shares carry no metadata threshold)"
            );
        }
    };
    if k < 2 {
        wipe_all(&mut shares);
        bail!("threshold must be at least 2");
    }
    if shares.len() < k as usize {
        let have = shares.len();
        wipe_all(&mut shares);
        bail!(
            "need at least {} distinct shares to verify, got {}",
            k,
            have
        );
    }

    let outcome = verify_shares(&shares, k, max_combinations);
    wipe_all(&mut shares);

    match outcome {
        VerifyOutcome::Verified {
            used_indices,
            payload_len,
        } => {
            println!(
                "PASS: a quorum of {} share(s) reconstructs a checksum-valid {}-byte secret.",
                k, payload_len
            );
            println!(
                "      Verified using share indices {:?}. The secret was NOT revealed.",
                used_indices
            );
            Ok(())
        }
        VerifyOutcome::NoValidCombination => {
            eprintln!(
                "FAIL: no combination of the given shares reconstructs a checksum-valid secret."
            );
            eprintln!("      Possible causes:");
            eprintln!(
                "        - one or more shares are wrong, corrupted, or from a different split"
            );
            eprintln!("        - fewer than the threshold of matching shares were provided");
            eprintln!(
                "        - shares were generated with --no-checksum (this tool needs the embedded"
            );
            eprintln!("          blake3 checksum to verify without revealing the secret)");
            std::process::exit(1);
        }
    }
}

fn wipe_all(shares: &mut [(u8, Vec<u8>)]) {
    for (_, bytes) in shares.iter_mut() {
        keyquorum_core::memory::wipe_and_unlock(bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blahaj::Sharks;

    /// Generate raw sharks shares (index, bytes) for a secret with an embedded
    /// blake3 checksum, matching keyquorum-split's default.
    fn checksummed_shares(secret: &[u8], threshold: u8, n: u8) -> Vec<(u8, Vec<u8>)> {
        let mut payload = secret.to_vec();
        payload.extend_from_slice(blake3::hash(&payload).as_bytes());
        let sharks = Sharks(threshold);
        sharks
            .dealer(&payload)
            .take(n as usize)
            .map(|s| {
                let bytes = Vec::<u8>::from(&s);
                (bytes[0], bytes)
            })
            .collect()
    }

    #[test]
    fn verifies_valid_quorum() {
        let shares = checksummed_shares(b"drill-secret", 3, 5);
        match verify_shares(&shares[..3], 3, 100) {
            VerifyOutcome::Verified {
                used_indices,
                payload_len,
            } => {
                assert_eq!(used_indices.len(), 3);
                assert_eq!(payload_len, b"drill-secret".len());
            }
            _ => panic!("expected Verified"),
        }
    }

    #[test]
    fn finds_valid_combo_among_a_bad_share() {
        // 3 good + 1 from a different split; C(4,3) includes one all-good combo.
        let mut shares = checksummed_shares(b"real", 3, 3);
        let other = checksummed_shares(b"different", 3, 5);
        // Append a share whose index doesn't collide with 1,2,3
        shares.push(other[3].clone()); // index 4
        assert!(matches!(
            verify_shares(&shares, 3, 100),
            VerifyOutcome::Verified { .. }
        ));
    }

    #[test]
    fn fails_below_threshold() {
        let shares = checksummed_shares(b"x", 3, 5);
        assert!(matches!(
            verify_shares(&shares[..2], 3, 100),
            VerifyOutcome::NoValidCombination
        ));
    }

    #[test]
    fn fails_without_checksum() {
        // Shares with no embedded checksum — nothing to verify against.
        let sharks = Sharks(2);
        let shares: Vec<(u8, Vec<u8>)> = sharks
            .dealer(b"no-checksum")
            .take(3)
            .map(|s| {
                let b = Vec::<u8>::from(&s);
                (b[0], b)
            })
            .collect();
        assert!(matches!(
            verify_shares(&shares, 2, 100),
            VerifyOutcome::NoValidCombination
        ));
    }

    #[test]
    fn respects_combination_cap() {
        // Only the all-good combo verifies, but cap at 1 so it isn't reached
        // (the first combo includes the wrong share).
        let mut shares = checksummed_shares(b"capped", 2, 2);
        let other = checksummed_shares(b"wrong", 2, 5);
        // Insert a wrong share at the front so combo #1 {0,1} mixes splits
        shares.insert(0, other[4].clone()); // index 5, wrong split
                                            // Shares now: [wrong#5, good#1, good#2]; C(3,2) first combo is {0,1}=mixed
        match verify_shares(&shares, 2, 1) {
            VerifyOutcome::NoValidCombination => {}
            VerifyOutcome::Verified { .. } => panic!("cap of 1 should stop before the good combo"),
        }
    }
}
