# Convenience wrapper around cargo, plus machine-local targets via Makefile.local.

.PHONY: build release test install fmt clippy hooks unhooks help

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

# core.hooksPath is per-clone config, so the hooks ship with the repo but stay opt-in.
hooks: ## enable the repo's git hooks (pre-commit fmt check)
	@git config core.hooksPath .githooks
	@echo "git hooks enabled — .githooks/pre-commit will check rustfmt"

unhooks: ## disable the repo's git hooks
	@git config --unset core.hooksPath 2>/dev/null || true
	@echo "git hooks disabled"

help: ## list targets
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "; w = 12} { k[NR] = $$1; v[NR] = $$2; if (length($$1) > w) w = length($$1) } \
		     END { for (i = 1; i <= NR; i++) printf "  \033[36m%-*s\033[0m %s\n", w, k[i], v[i] }'

# Personal/per-machine targets (e.g. `push` to a private mirror). Untracked.
-include Makefile.local
