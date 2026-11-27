# Raijin: the Burp extension jar (Gradle, JDK 25) and the `raijin` CLI (Cargo workspace).

set shell := ["bash", "-euo", "pipefail", "-c"]

# List recipes.
default:
    @just --list

# Build the jar and the release CLI.
build: jar cli

# Extension jar: build/libs/raijin.jar.
jar:
    ./gradlew build -x test

# Release CLI: target/release/raijin.
cli:
    cargo build --release --locked -p cli

# Debug CLI build.
cli-dev:
    cargo build --locked -p cli

# All tests: Kotlin and Rust.
test: test-jar test-cli

test-jar:
    ./gradlew test

test-cli:
    cargo test --locked

# What CI runs: fmt check, clippy, all tests.
check: fmt-check lint test

lint:
    cargo clippy --locked -p cli --no-deps --all-targets -- -D warnings

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

# Regenerate src/main/resources/catalog/tools.json after changing a tool.
catalog:
    RAIJIN_UPDATE_CATALOG=1 ./gradlew test --tests '*ToolCatalogTest'

# Build the jar, then the CLI pinned to its SHA-256 (it only loads a raijin.jar beside itself
# whose digest matches, `crates/cli/src/jar.rs`), and copy both into DIR (default: ~/.local/bin).
install dir=(env("HOME") / ".local/bin"): jar
    RAIJIN_JAR_SHA256="$(shasum -a 256 build/libs/raijin.jar | cut -d' ' -f1)" \
        cargo build --release --locked -p cli
    mkdir -p "{{ dir }}"
    install -m 755 target/release/raijin "{{ dir }}/raijin"
    install -m 644 build/libs/raijin.jar "{{ dir }}/raijin.jar"
    @echo "installed raijin and raijin.jar into {{ dir }}"

# Run the CLI from source, e.g. `just run mcp`.
run *args:
    cargo run --locked -p cli -- {{ args }}

clean:
    ./gradlew clean
    cargo clean
