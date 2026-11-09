#!/bin/bash
set -euo pipefail
# Restrict new PIN, token and configuration files even under a permissive umask.
umask 077

# Provisions a PKCS#11 v3.2 software token with ML-DSA for crypto11's
# TestMLDSAOnPKCS11v32Token: Kryoptic, built from a pinned tag unless --module
# names an existing library. The default feature set of Kryoptic has no ML-DSA,
# so the build asks for "pqc", which needs OpenSSL 3.5 and SQLite development
# files, a Rust toolchain and libclang. The fixture holds a PIN and a module
# that gets loaded, so it lives under HOME by default, not the shared /tmp.

KRYOPTIC_VERSION_DEFAULT=v1.5.4
KRYOPTIC_REPO=https://github.com/latchset/kryoptic.git
OPENSSL_VERSION_MIN=3.5
FIXTURE_DIR_DEFAULT=.xpki/kryoptic
CONFIG_NAME_DEFAULT=token.json
TOKEN_LABEL=xpki_mldsa
TOKEN_SLOT=1

usage() {
    cat <<'USAGE'
Usage: config-kryoptic.sh [options]
  -m, --module FILE    Existing libkryoptic_pkcs11.so (otherwise build it)
  -v, --version TAG    Kryoptic tag to build
  -d, --dir DIR        Fixture directory (default: ~/.xpki/kryoptic)
  -o, --out-cfg FILE   Token JSON configuration (default: DIR/token.json)
  -h, --help           Show this help
The token is created anew, erasing the previous one. Set KRYOPTIC_CONF to
DIR/token.conf for the process that loads the module. PINs are never printed.
A location other users can replace is refused: every directory on the way to
DIR, FILE and the module must be owned by this user or root, and not writable
by group or others unless sticky, like /tmp.
USAGE
}

die() { printf '%s\n' "$*" >&2; exit 1; }
require_tool() { command -v "$1" >/dev/null || die "Please install $1"; }

# The configuration is read from other directories, so its paths are absolute.
absolute() {
    case "$1" in
        /*) printf '%s' "$1" ;;
        *) printf '%s/%s' "$PWD" "$1" ;;
    esac
}

# protected_dir prints the physical path of the directory $1, which has no
# symlink left to swap, after checking it and every ancestor. Whoever can rename
# one of them can substitute what it holds, whatever the fixture's own owner and
# mode say. Assign its output on its own line, for set -e to see a refusal.
protected_dir() {
    local physical dir
    physical=$(cd -- "$1" && pwd -P) || die "not a directory: $1"
    dir=$physical
    while :; do
        [[ -n $(find "$dir" -maxdepth 0 \( -user 0 -o -user "$UID" \) \
            \( \( ! -perm -020 ! -perm -002 \) -o -perm -1000 \)) ]] \
            || die "other users can replace $dir: fix its owner or mode, or choose another location"
        [[ "$dir" != / ]] || break
        dir=$(dirname -- "$dir")
    done
    printf '%s' "$physical"
}

# A quote, backslash or control character would break the TOML and JSON below.
require_plain_path() {
    [[ "$2" != *[\"\\[:cntrl:]]* ]] || die "invalid $1: $2"
}

MODULE=
VERSION=$KRYOPTIC_VERSION_DEFAULT
DIR=$HOME/$FIXTURE_DIR_DEFAULT
CONFIG_FILE=

while [[ $# -gt 0 ]]; do
    case "$1" in
        -m|--module|-v|--version|-d|--dir|-o|--out-cfg)
            [[ $# -ge 2 && "$2" != --* ]] || die "$1 requires a value"
            case "$1" in
                -m|--module) MODULE=$2 ;;
                -v|--version) VERSION=$2 ;;
                -d|--dir) DIR=$2 ;;
                -o|--out-cfg) CONFIG_FILE=$2 ;;
            esac
            shift 2
            ;;
        -h|--help) usage; exit 0 ;;
        *) die "invalid argument $1: use --help to see the options" ;;
    esac
done

[[ "$VERSION" =~ ^v[0-9]+(\.[0-9]+)*$ ]] || die "invalid version: $VERSION"
DIR=$(absolute "$DIR")
CONFIG_FILE=$(absolute "${CONFIG_FILE:-$DIR/$CONFIG_NAME_DEFAULT}")
if [[ -n "$MODULE" ]]; then MODULE=$(absolute "$MODULE"); fi

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
config_dir=$(dirname -- "$CONFIG_FILE")
mkdir -p -- "$DIR" "$config_dir"
# The directory holds a PIN and a build that gets run: it has to be this user's
# own and closed to the others, and so does everything on the way to it.
[[ -d "$DIR" && ! -L "$DIR" && -O "$DIR" ]] || die "not a directory owned by this user: $DIR"
chmod 700 -- "$DIR"
DIR=$(protected_dir "$DIR")
require_plain_path 'fixture directory' "$DIR"
config_dir=$(protected_dir "$config_dir")
CONFIG_FILE=$config_dir/$(basename -- "$CONFIG_FILE")

if [[ -z "$MODULE" ]]; then
    require_tool git
    require_tool cargo
    require_tool pkg-config
    # cargo reports a missing library only at the final link, minutes from now.
    pkg-config --exists sqlite3 \
        || die 'Please install the SQLite development files (libsqlite3-dev or sqlite-devel)'
    pkg-config --atleast-version="$OPENSSL_VERSION_MIN" openssl \
        || die "Please install the OpenSSL $OPENSSL_VERSION_MIN development files (libssl-dev or openssl-devel)"
    src="$DIR/src-$VERSION"
    if [[ ! -d "$src" ]]; then
        # through a temporary name, so an interrupted clone is not built later
        rm -rf -- "$src.tmp"
        git clone --depth 1 --branch "$VERSION" "$KRYOPTIC_REPO" "$src.tmp"
        mv -- "$src.tmp" "$src"
    fi
    (cd -- "$src" && cargo build --release -p kryoptic --features pqc)
    MODULE="$src/target/release/libkryoptic_pkcs11.so"
fi
[[ -f "$MODULE" ]] || die "Kryoptic module not found: $MODULE"
module_dir=$(protected_dir "$(dirname -- "$MODULE")")
MODULE=$module_dir/$(basename -- "$MODULE")
require_plain_path 'module path' "$MODULE"

require_tool go
require_tool openssl

PIN_FILE="$DIR/pin.txt"
export KRYOPTIC_CONF="$DIR/token.conf"
# Removed, not truncated: a file left behind keeps its mode, and a symlink would
# send the PIN elsewhere.
rm -f -- "$PIN_FILE" "$KRYOPTIC_CONF" "$DIR/token.sql" "$CONFIG_FILE"

openssl rand -hex 16 > "$PIN_FILE"
[[ -s "$PIN_FILE" ]] || die 'PIN generation returned an empty value'

printf '[[slots]]\nslot = %d\ndbtype = "sqlite"\ndbargs = "%s/token.sql"\n' \
    "$TOKEN_SLOT" "$DIR" > "$KRYOPTIC_CONF"

# go run needs the module, wherever this script was started from
(cd -- "$script_dir/.." && go run scripts/p11-init-token.go \
    --module "$MODULE" --slot "$TOKEN_SLOT" --label "$TOKEN_LABEL" --pin-file "$PIN_FILE")

printf '{"Manufacturer":"SoftHSM","Path":"%s","TokenLabel":"%s","Pin":"file:%s"}\n' \
    "$MODULE" "$TOKEN_LABEL" "$PIN_FILE" > "$CONFIG_FILE"
printf 'Token configuration written to %s\n' "$CONFIG_FILE"
printf 'Run with: KRYOPTIC_CONF=%s XPKI_PKCS11_V32_CONFIG=%s\n' "$KRYOPTIC_CONF" "$CONFIG_FILE"
