#!/usr/bin/env bash
# scripts/preflight.sh — local reproduction of the CI gates before `git push`.
# Every command is the one CI runs. A step this file does not cover is a step
# that can only fail remotely — when a workflow step is added, add it here in
# the same commit. Run `--quick` before every push.
#
# usage: scripts/preflight.sh [--quick]   (--quick skips the test suites)
set -euo pipefail
cd "$(dirname "$0")/.."

quick=0
[[ "${1:-}" == "--quick" ]] && quick=1

step() { printf '\n\033[1;34m== %s\033[0m\n' "$*"; }
# `cargo clippy` reuses fresh `cargo check` artifacts and then lints nothing;
# touching the crate roots invalidates only this repo's fingerprints.
relint() { git ls-files | grep -E '(^|/)src/(lib|main)\.rs$' | xargs -r touch; }
need() { command -v "$1" >/dev/null 2>&1 || { echo "missing tool: $1 ($2)" >&2; exit 1; }; }

# Steps CI runs that this file cannot reproduce locally:
#   - ci.yml:float-environment on windows-latest and macos-latest (other OS)

need actionlint "brew install actionlint"
export CARGO_TERM_COLOR="always" RUSTFLAGS="-Dwarnings"

step "ci.yml / fmt: Check formatting"
cargo fmt -- --check

step "actionlint"
actionlint .github/workflows/*.yml

step "ci.yml / clippy: Clippy (default, all targets)"
relint
cargo clippy --all-targets -- -D warnings

step "ci.yml / clippy: Clippy (rand, all targets)"
relint
cargo clippy --all-targets --features rand -- -D warnings

step "ci.yml / clippy: Clippy canary data (generator tests, generated from clippy.toml, no drift)"
python3 scripts/test_gen_clippy_canary_calls.py
python3 scripts/gen_clippy_canary_calls.py --check

step "ci.yml / clippy: Clippy canary (tests)"
python3 scripts/test_clippy_canary.py

step "ci.yml / clippy: Clippy canary (every planted banned call is flagged)"
python3 scripts/clippy_canary.py

step "ci.yml / no_std: Build and clippy (thumbv7em-none-eabihf)"
rustup target list --installed | grep -q '^thumbv7em-none-eabihf$' || rustup target add thumbv7em-none-eabihf
cargo build --lib --target thumbv7em-none-eabihf
cargo clippy --lib --target thumbv7em-none-eabihf -- -D warnings

step "ci.yml / float-environment: run_tests.sh and build configuration guard (tests, then check)"
python3 scripts/test_run_tests.py
python3 scripts/test_build_config_guard.py
python3 scripts/build_config_guard.py
python3 scripts/test_build_flags_check.py

step "ci.yml / float-environment: Effective rustc flags (default, rand, no default features)"
python3 scripts/build_flags_check.py -- cargo check --release --lib
python3 scripts/build_flags_check.py -- cargo check --release --lib --features rand
python3 scripts/build_flags_check.py -- cargo check --release --lib --no-default-features

step "public-text.yml: Public text (ALICE-Law checker at the pin)"
python3 scripts/test_public_text.py
scripts/public_text.sh

if [[ $quick -eq 1 ]]; then
  echo; echo "preflight --quick OK (test suites skipped)"; exit 0
fi

step "ci.yml / float-environment: Float environment (debug and release)"
scripts/run_tests.sh float_environment=2 -- cargo test --test float_environment
scripts/run_tests.sh float_environment=2 -- cargo test --release --test float_environment

step "ci.yml / float-environment: Golden byte layouts (debug and release)"
cargo test --test golden
cargo test --release --test golden

step "ci.yml / test: Test (default, rand)"
cargo test
cargo test --features rand
scripts/run_tests.sh verify_strict=8 -- cargo test --test verify_strict
scripts/run_tests.sh leading_zeros=3 -- cargo test --test leading_zeros

step "ci.yml / doc: Doc (rand)"
RUSTDOCFLAGS="-Dwarnings" cargo doc --no-deps --features rand

echo; echo "preflight OK"
