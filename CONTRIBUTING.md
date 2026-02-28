# Contributing to keyquorum

Thanks for your interest in contributing to keyquorum.

## Before You Start

This is a security-critical tool that protects real secrets. Please read:

- **[AGENTS.md](AGENTS.md)** — mandatory reading. Covers memory safety rules, threat model, common pitfalls, and what not to do. Applies to both human and AI contributors.

## Submitting a PR

1. **Open an issue first** for non-trivial changes. Security tools benefit from design discussion before implementation.
2. **Fork and branch** from `main`.
3. **Write tests.** Security-sensitive changes need tests for both the positive case (it works) and the negative case (it correctly rejects/fails/zeroizes).
4. **Run the checks:**
   ```bash
   cargo test
   cargo clippy --all-targets -- -D warnings
   bash tests/e2e-stdout.sh    # needs release build: cargo build --release
   ```
5. **Explain why, not just what** in your PR description. For security-relevant changes, explain the threat model implications.

## What We're Looking For

- Bug fixes with test coverage
- Security improvements backed by clear threat analysis
- Documentation improvements
- New output modes for `keyquorum-split` (e.g., `age` encryption, interactive ceremony mode)
- Platform support improvements (especially macOS — maintainer has no Apple hardware)

## What We'll Push Back On

- Breaking changes to the V1 share format, NDJSON protocol, config fields, or CLI args
- Custom cryptographic constructions (use established libraries)
- Layering verification schemes on top of Shamir instead of implementing them properly (see AGENTS.md)
- New dependencies without clear justification
- Changes that weaken the memory safety model

## AI-Generated Contributions

AI-assisted PRs are welcome. Please:
- State in the PR description that AI was used and which tool
- Review the output yourself before submitting — AI agents make confident mistakes in security code
- Pay extra attention to memory safety (zeroization, mlock) — AI agents routinely miss these
- Be prepared to justify your agent's architectural decisions and reasoning in your own words

## Platform Notes

- **Linux** is the primary and tested target
- **macOS** builds are best-effort and untested by the maintainer. macOS PRs are welcome but please don't open issues requesting Apple support.

## Code Style

- `cargo fmt` — don't fight the formatter
- `cargo clippy` — must be clean, no `#[allow]` without justification
- Comments where the logic isn't self-evident, not on every line
- No unnecessary abstractions — three similar lines beats a premature helper function

## License

By contributing, you agree that your contributions will be licensed under Apache-2.0, the same license as the project.
