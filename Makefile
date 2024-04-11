# Copyright (C) Nitrokey GmbH
# SPDX-License-Identifier: CC0-1.0

.PHONY: all
all: check lint test

.PHONY: check
check:
	cargo check --all-targets
	cargo check --all-targets --no-default-features
	cargo check --all-targets --all-features

.PHONY: lint
lint:
	cargo clippy --all-targets --all-features
	cargo fmt -- --check
	cargo doc --all-features --no-deps

.PHONY: test
test:
	cargo test --all-features

.PHONY: ci
ci: export RUSTFLAGS=-Dwarnings
ci: export RUSTDOCFLAGS=-Dwarnings
ci: check lint test
