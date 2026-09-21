#!/bin/bash
set -euo pipefail
# Restrict new PIN and configuration files even under a permissive caller umask.
umask 077

usage() {
    cat <<'USAGE'
Usage: config-softhsm.sh --slot LABEL [options]
  -p, --pin PIN           Use an explicit PIN (takes precedence over --pin-file)
  -f, --pin-file FILE     Read a PIN, or save a generated PIN to this file
  -g, --generate-pin      Generate a PIN if no nonempty PIN is available
  -s, --slot LABEL        Token label
  -m, --module FILE       PKCS#11 module (otherwise discover SoftHSM)
  -d, --tokens-dir DIR    Token storage (default: ~/softhsm2/tokens)
  -c, --cfg-dir DIR       Config directory (default: ~/.config/softhsm2)
  -o, --out-cfg FILE      Write token JSON configuration with mode 0600
      --list-slots       List slots using pkcs11-tool
      --list-object      List objects using pkcs11-tool
      --delete           Delete the matching token before initializing it
      --force            Remove token storage and recreate softhsm2.conf
  -h, --help             Show this help
Generated PINs require --pin-file or --out-cfg; PINs are never printed.
USAGE
}

die() { printf '%s\n' "$*" >&2; exit 1; }
require_tool() { command -v "$1" || die "Please install $1"; }

HSM_PIN=${HSM_PIN:-}
HSM_PINFILE=${HSM_PINFILE:-}
HSM_SLOT=${HSM_SLOT:-}
HSM_MODULE=${HSM_MODULE:-}
TOKEN_DIR=${TOKEN_DIR:-}
SOFTHSM2_CONF_DIR=${SOFTHSM2_CONF_DIR:-}
CONFIG_FILE=${CONFIG_FILE:-}
GENERATE_PIN=${GENERATE_PIN:-NO}
LIST_SLOTS=${LIST_SLOTS:-NO}
LIST_OBJECTS=${LIST_OBJECTS:-NO}
FORCE=${FORCE:-NO}
DELETE_TOKEN=${DELETE_TOKEN:-NO}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -p|--pin|-f|--pin-file|-s|--slot|-m|--module|-d|--tokens-dir|-c|--cfg-dir|-o|--out-cfg)
            [[ $# -ge 2 && "$2" != --* ]] || die "$1 requires a value"
            case "$1" in
                -p|--pin) HSM_PIN=$2 ;;
                -f|--pin-file) HSM_PINFILE=$2 ;;
                -s|--slot) HSM_SLOT=$2 ;;
                -m|--module) HSM_MODULE=$2 ;;
                -d|--tokens-dir) TOKEN_DIR=$2 ;;
                -c|--cfg-dir) SOFTHSM2_CONF_DIR=$2 ;;
                -o|--out-cfg) CONFIG_FILE=$2 ;;
            esac
            shift 2
            ;;
        -g|--generate-pin) GENERATE_PIN=YES; shift ;;
        --list-slots) LIST_SLOTS=YES; shift ;;
        --list-object) LIST_OBJECTS=YES; shift ;;
        --force) FORCE=YES; shift ;;
        --delete) DELETE_TOKEN=YES; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "invalid argument $1: use --help to see the options" ;;
    esac
done

[[ -n "$HSM_SLOT" ]] || die '--slot is not provided'
SOFTHSM_TOOL=$(require_tool softhsm2-util)
PKCS11_TOOL=
if [[ "$LIST_SLOTS" == YES || "$LIST_OBJECTS" == YES ]]; then
    PKCS11_TOOL=$(require_tool pkcs11-tool)
fi

if [[ -z "$HSM_MODULE" ]]; then
    platform=$(uname -s)
    case "$platform" in
        Darwin)
            BREW=$(require_tool brew)
            brew_prefix=$("$BREW" --prefix softhsm)
            HSM_MODULE="$brew_prefix/lib/softhsm/libsofthsm2.so"
            ;;
        Linux)
            for candidate in \
                /usr/lib/softhsm/libsofthsm2.so \
                /usr/local/lib/softhsm/libsofthsm2.so \
                /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
                /usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so \
                /usr/lib64/pkcs11/libsofthsm2.so; do
                if [[ -f "$candidate" ]]; then
                    HSM_MODULE=$candidate
                    break
                fi
            done
            ;;
        *) die "unsupported platform $platform: specify --module" ;;
    esac
fi
[[ -n "$HSM_MODULE" && -f "$HSM_MODULE" ]] || die "HSM module not found: $HSM_MODULE; specify --module"

TOKEN_DIR=${TOKEN_DIR:-$HOME/softhsm2/tokens}
SOFTHSM2_CONF_DIR=${SOFTHSM2_CONF_DIR:-$HOME/.config/softhsm2}
# A newline would create a second directive in softhsm2.conf.
[[ "$TOKEN_DIR" != *$'\n'* && "$TOKEN_DIR" != *$'\r'* ]] || die 'invalid token directory'

HSM_PIN_VAL=$HSM_PIN
if [[ -z "$HSM_PIN_VAL" && -n "$HSM_PINFILE" && -e "$HSM_PINFILE" ]]; then
    [[ -f "$HSM_PINFILE" ]] || die 'PIN file is not a regular file'
    chmod 600 "$HSM_PINFILE"
    HSM_PIN_VAL=$(cat -- "$HSM_PINFILE")
    # Match the Go config loader: strip trailing CR/LF, preserve other spaces.
    while [[ "$HSM_PIN_VAL" == *$'\r' || "$HSM_PIN_VAL" == *$'\n' ]]; do
        HSM_PIN_VAL=${HSM_PIN_VAL%?}
    done
    if [[ -n "$HSM_PIN_VAL" ]]; then HSM_PIN="file:$HSM_PINFILE"; fi
fi
if [[ -z "$HSM_PIN_VAL" && "$GENERATE_PIN" == YES ]]; then
    [[ -n "$HSM_PINFILE" || -n "$CONFIG_FILE" ]] || die 'generated PIN requires --pin-file or --out-cfg'
    OPENSSL=$(require_tool openssl)
    HSM_PIN_VAL=$("$OPENSSL" rand -hex 16)
    [[ -n "$HSM_PIN_VAL" ]] || die 'PIN generation returned an empty value'
    if [[ -n "$HSM_PINFILE" ]]; then
        printf '%s' "$HSM_PIN_VAL" > "$HSM_PINFILE"
        HSM_PIN="file:$HSM_PINFILE"
    else
        HSM_PIN=$HSM_PIN_VAL
    fi
fi
[[ -n "$HSM_PIN_VAL" ]] || die 'pin is not provided, use --pin | --pin-file | --generate-pin'

if [[ "$FORCE" == YES ]]; then
    # Resolve existing paths before a recursive removal, including symlinks/.. .
    if [[ -d "$TOKEN_DIR" ]]; then
        token_path=$(cd -- "$TOKEN_DIR" && pwd -P)
        [[ "$token_path" != / && "$token_path" != "${HOME:-}" ]] || die 'refusing to remove root or home token directory'
    fi
    rm -rf -- "$TOKEN_DIR"
    rm -f -- "$SOFTHSM2_CONF_DIR/softhsm2.conf"
fi
mkdir -p -- "$TOKEN_DIR" "$SOFTHSM2_CONF_DIR"
export SOFTHSM2_CONF="$SOFTHSM2_CONF_DIR/softhsm2.conf"
if [[ ! -f "$SOFTHSM2_CONF" ]]; then
    printf 'directories.tokendir = %s\n' "$TOKEN_DIR" > "$SOFTHSM2_CONF"
fi

# Fetch separately so a tool failure cannot be mistaken for an absent token.
slots=$("$SOFTHSM_TOOL" --show-slots --module "$HSM_MODULE")
token_exists=NO
while IFS= read -r line; do
    [[ "$line" == *Label:* ]] || continue
    label=${line#*Label:}
    label=${label#"${label%%[![:space:]]*}"}
    label=${label%"${label##*[![:space:]]}"}
    if [[ "$label" == "$HSM_SLOT" ]]; then
        token_exists=YES
        break
    fi
done <<< "$slots"

if [[ "$DELETE_TOKEN" == YES && "$token_exists" == YES ]]; then
    "$SOFTHSM_TOOL" --module "$HSM_MODULE" --delete-token --token "$HSM_SLOT"
    token_exists=NO
fi
if [[ "$token_exists" == NO ]]; then
    "$SOFTHSM_TOOL" --module "$HSM_MODULE" --init-token --free --label "$HSM_SLOT" \
        --force --pin "$HSM_PIN_VAL" --so-pin "so$HSM_PIN_VAL"
fi

# Encode JSON strings without adding a runtime dependency on Python or jq.
json_string() {
    local value=$1 char code i
    printf '"'
    for ((i = 0; i < ${#value}; i++)); do
        char=${value:i:1}
        case "$char" in
            \\|\") printf '\\%s' "$char" ;;
            *)
                printf -v code '%d' "'$char"
                if ((code < 32)); then
                    printf '\\u%04x' "$code"
                else
                    printf '%s' "$char"
                fi
                ;;
        esac
    done
    printf '"'
}

if [[ -n "$CONFIG_FILE" ]]; then
    # chmod before truncation also repairs previously world-readable output.
    if [[ -e "$CONFIG_FILE" ]]; then chmod 600 "$CONFIG_FILE"; fi
    {
        printf '{"Manufacturer":"SoftHSM","Path":'
        json_string "$HSM_MODULE"
        printf ',"TokenLabel":'
        json_string "$HSM_SLOT"
        printf ',"Pin":'
        json_string "$HSM_PIN"
        printf '}\n'
    } > "$CONFIG_FILE"
    printf 'Token configuration written to %s\n' "$CONFIG_FILE"
fi
if [[ "$LIST_SLOTS" == YES ]]; then
    "$PKCS11_TOOL" --module "$HSM_MODULE" --list-slots
fi
if [[ "$LIST_OBJECTS" == YES ]]; then
    "$PKCS11_TOOL" --module "$HSM_MODULE" --login --pin "$HSM_PIN_VAL" \
        --token-label "$HSM_SLOT" --list-object
fi
