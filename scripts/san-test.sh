#!/usr/bin/env bash
set -euo pipefail

# Source cargo environment if not already in PATH
if ! command -v rustup &> /dev/null; then
    if [ -f "$HOME/.cargo/env" ]; then
        source "$HOME/.cargo/env"
    else
        echo "ERROR: rustup not found - run ./scripts/setup-rust.sh first"
        exit 1
    fi
fi

# Install nightly if needed
if ! rustup toolchain list | grep -q nightly; then
    rustup toolchain install nightly || exit 1
fi

# Verify sanitizer works
set +e
LEAK_OUTPUT=$(RUSTFLAGS="-Z sanitizer=leak" \
    cargo +nightly test --target x86_64-unknown-linux-gnu \
    intentional_leak_for_sanitizer_validation -- --ignored 2>&1)
set -e
if ! echo "$LEAK_OUTPUT" | grep -q "LeakSanitizer: detected memory leaks"; then
    echo "ERROR: LeakSanitizer not working"
    exit 1
fi

# Run tests based on argument
if [ "${1:-}" = "pqc" ]; then
    # PQC tests with OpenSSL 3.5
    LD_PRELOAD="openssl-3.5.5/libcrypto.so.3 openssl-3.5.5/libssl.so.3" \
        RUSTFLAGS="-Z sanitizer=address" \
        cargo +nightly test --target x86_64-unknown-linux-gnu --features pqc || exit 1
    
    LD_PRELOAD="openssl-3.5.5/libcrypto.so.3 openssl-3.5.5/libssl.so.3" \
        RUSTFLAGS="-Z sanitizer=leak" \
        cargo +nightly test --target x86_64-unknown-linux-gnu --features pqc || exit 1
else
    # Basic tests without PQC
    RUSTFLAGS="-Z sanitizer=address" cargo +nightly test --target x86_64-unknown-linux-gnu || exit 1
    RUSTFLAGS="-Z sanitizer=leak" cargo +nightly test --target x86_64-unknown-linux-gnu || exit 1
fi
