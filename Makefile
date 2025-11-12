all: test

.PHONY: test
test:
	cargo test
	cargo test --manifest-path=./crates/bytecode/Cargo.toml
	cargo test --manifest-path=./crates/context/Cargo.toml
	cargo test --manifest-path=./crates/handler/Cargo.toml
	cargo test --manifest-path=./crates/helpers/Cargo.toml
	cargo test --manifest-path=./crates/inspector/Cargo.toml
	cargo test --manifest-path=./crates/interpreter/Cargo.toml
	cargo test --manifest-path=./crates/op-revm/Cargo.toml
	cargo test --manifest-path=./crates/precompile/Cargo.toml
	cargo test --manifest-path=./crates/primitives/Cargo.toml
	cargo test --manifest-path=./crates/revm/Cargo.toml
	cargo test --manifest-path=./crates/state/Cargo.toml
	cargo test --manifest-path=./crates/statetest-types/Cargo.toml
