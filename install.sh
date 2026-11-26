#!/bin/sh
# Installs the raijin CLI and the Raijin Burp extension (raijin.jar, beside it) from a GitHub release:
#   curl -LsSf https://github.com/bitbytelabio/raijin/releases/latest/download/install.sh | sh
# Environment:
#   RAIJIN_VERSION      release to install, e.g. 2.2.1 or v2.2.1 (default: latest)
#   RAIJIN_INSTALL_DIR  destination folder (default: $HOME/.local/bin)
set -eu

REPO="https://github.com/bitbytelabio/raijin"

say() {
    printf 'raijin-install: %s\n' "$1" >&2
}

die() {
    say "$1"
    exit 1
}

# fetch URL FILE
fetch() {
    if [ "$downloader" = curl ]; then
        curl -fsSL -o "$2" "$1"
    else
        wget -qO "$2" "$1"
    fi
}

# fetch_verified BASE NAME: downloads BASE/NAME into $tmp and checks it against BASE/NAME.sha256.
fetch_verified() {
    fetch "$1/$2" "$tmp/$2" || die "download failed: $1/$2"
    fetch "$1/$2.sha256" "$tmp/$2.sha256" || die "download failed: $1/$2.sha256"
    expected=$(awk '{ print $1; exit }' "$tmp/$2.sha256")
    if command -v sha256sum >/dev/null 2>&1; then
        actual=$(sha256sum "$tmp/$2" | awk '{ print $1 }')
    elif command -v shasum >/dev/null 2>&1; then
        actual=$(shasum -a 256 "$tmp/$2" | awk '{ print $1 }')
    else
        die "need sha256sum or shasum to verify the download"
    fi
    [ -n "$expected" ] && [ "$expected" = "$actual" ] || die "checksum mismatch for $2"
}

# install_file SRC DEST MODE
install_file() {
    if command -v install >/dev/null 2>&1; then
        install -m "$3" "$1" "$2"
    else
        cp "$1" "$2"
        chmod "$3" "$2"
    fi
}

# Final URL of the "latest release" redirect; no GitHub API, so no rate limit.
latest_url() {
    if [ "$downloader" = curl ]; then
        curl -fsSLI -o /dev/null -w '%{url_effective}' "$REPO/releases/latest"
    else
        wget -S --spider "$REPO/releases/latest" 2>&1 | sed -n 's/^ *[Ll]ocation: *\([^ ]*\).*/\1/p' | tail -n 1
    fi
}

# Everything runs from main, called on the last line: under `curl | sh`, a download cut short
# defines nothing instead of running a partial command.
main() {
    if command -v curl >/dev/null 2>&1; then
        downloader=curl
    elif command -v wget >/dev/null 2>&1; then
        downloader=wget
    else
        die "need curl or wget"
    fi

    os=$(uname -s)
    arch=$(uname -m)
    case "$os $arch" in
        "Darwin arm64" | "Darwin aarch64") target=aarch64-apple-darwin ;;
        "Linux x86_64" | "Linux amd64") target=x86_64-unknown-linux-gnu ;;
        "Linux aarch64" | "Linux arm64") target=aarch64-unknown-linux-gnu ;;
        *) die "unsupported platform: $os $arch" ;;
    esac

    version=${RAIJIN_VERSION:-}
    if [ -z "$version" ]; then
        url=$(latest_url) || die "could not resolve latest release"
        url=$(printf '%s' "$url" | tr -d '\r')
        case "$url" in
            */tag/*) version=${url##*/tag/} ;;
            *) version= ;;
        esac
        [ -n "$version" ] || die "could not resolve latest release"
    fi
    version=${version#v}

    install_dir=${RAIJIN_INSTALL_DIR:-${HOME:?HOME is not set}/.local/bin}

    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT

    asset="raijin-cli-$version-$target.tar.gz"
    jar="raijin-$version.jar"
    base="$REPO/releases/download/v$version"
    say "downloading raijin $version ($target) and $jar"
    fetch_verified "$base" "$asset"
    fetch_verified "$base" "$jar"

    tar -xzf "$tmp/$asset" -C "$tmp" raijin || die "could not extract $asset"
    mkdir -p "$install_dir"
    install_file "$tmp/raijin" "$install_dir/raijin" 755
    install_file "$tmp/$jar" "$install_dir/raijin.jar" 644

    say "installed raijin $version to $install_dir/raijin"
    say "installed the Burp extension to $install_dir/raijin.jar"
    case ":$PATH:" in
        *":$install_dir:"*) ;;
        *) say "add it to PATH: export PATH=\"$install_dir:\$PATH\"" ;;
    esac
}

main "$@"
