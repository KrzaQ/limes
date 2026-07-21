# Convenience wrapper around cargo, plus machine-local targets via Makefile.local.

.PHONY: build release test install fmt clippy help

build: ## debug build
	cargo build

release: ## optimized build
	cargo build --release

test: ## run tests
	cargo test

install: ## install the `lim` binary into ~/.cargo/bin
	cargo install --path .

fmt: ## format
	cargo fmt

clippy: ## lint
	cargo clippy --all-targets

help: ## list targets
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

# Personal/per-machine targets (e.g. `push` to a private mirror). Untracked.
-include Makefile.local
