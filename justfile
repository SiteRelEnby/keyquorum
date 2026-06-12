# keyquorum dev tasks. Install just: https://github.com/casey/just
# Run `just` or `just --list` to see recipes.

# Show available recipes
default:
    @just --list

# Format all code
fmt:
    cargo fmt

# Check formatting without modifying (CI-style)
fmt-check:
    cargo fmt --check

# Run the full test suite
test:
    cargo test

# Clippy with warnings denied (matches CI)
clippy:
    cargo clippy --all-targets -- -D warnings

# Build optimized release binaries
build:
    cargo build --release

# End-to-end tests against release binaries (builds first)
e2e: build
    bash tests/e2e-stdout.sh ./target/release

# LUKS end-to-end tests (needs root + cryptsetup)
e2e-luks: build
    sudo bash tests/e2e-luks.sh "$(pwd)/target/release"

# Smoke-fuzz both share-parser targets (~30s each; needs nightly + cargo-fuzz)
fuzz seconds="30":
    cargo +nightly fuzz run parse_share -- -max_total_time={{seconds}}
    cargo +nightly fuzz run decode_payload -- -max_total_time={{seconds}}

# The full pre-push gate: everything CI runs except the scheduled fuzz
gate: fmt-check clippy test e2e
    @echo "All gates passed."

# Dependency + advisory checks (needs cargo-deny / cargo-audit)
audit:
    cargo deny check
    cargo audit
