#!/usr/bin/env sh
cross build --target x86_64-unknown-linux-musl --target-dir target --release || exit 1
mkdir -p bin/ || exit 1
cp target/x86_64-unknown-linux-musl/release/anonycast bin/ || exit 1
