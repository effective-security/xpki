#!/bin/bash
# Isolated regression checks; no installed HSM, Homebrew, or OpenSC required.
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
script=${SOFTHSM_SETUP_SCRIPT:-$script_dir/config-softhsm.sh}
test_dir=$(mktemp -d)
trap 'rm -rf -- "$test_dir"' EXIT
bash_bin=$(command -v bash)
mkdir -p "$test_dir/bin"
for tool in cat chmod mkdir rm; do
    ln -s "$(command -v "$tool")" "$test_dir/bin/$tool"
done

cat > "$test_dir/stub" <<'STUB'
#!/bin/bash
set -euo pipefail
tool=${0##*/}
case "$tool" in
    uname) printf '%s\n' "${STUB_OS:-Linux}" ;;
    brew)
        [[ "$*" == '--prefix softhsm' ]]
        [[ "${STUB_FAIL:-}" != brew ]] || exit 7
        printf '%s\n' "$CASE_DIR/homebrew"
        ;;
    openssl)
        [[ "$*" == 'rand -hex 16' ]]
        [[ "${STUB_FAIL:-}" != random ]] || exit 7
        printf '%s\n' '0123456789abcdef0123456789abcdef'
        ;;
    softhsm2-util|pkcs11-tool)
        action= pin= label=
        while [[ $# -gt 0 ]]; do
            case "$1" in
                --show-slots|--init-token|--delete-token|--list-slots|--list-object)
                    action=$1 ;;
                --pin) pin=$2; shift ;;
                --label|--token|--token-label) label=$2; shift ;;
                --token=*) label=${1#--token=} ;;
            esac
            shift
        done
        printf '%s\n' "$action" >> "$CASE_DIR/calls"
        [[ "${STUB_FAIL:-}" != "$action" ]] || exit 7
        [[ "${SOFTHSM2_CONF:-}" == "$CASE_DIR/config dir/softhsm2.conf" ]] || exit 8
        case "$action" in
            --show-slots)
                if [[ -f "$CASE_DIR/initialized" ]]; then
                    printf '    Label: %s    \n' "$(cat "$CASE_DIR/initialized")"
                else
                    printf '    Label: %s    \n' "${STUB_LABEL:-}"
                fi
                ;;
            --init-token)
                printf '%s' "$label" > "$CASE_DIR/initialized"
                printf '%s' "$pin" > "$CASE_DIR/received-pin"
                ;;
            --delete-token) rm -f "$CASE_DIR/initialized" ;;
        esac
        ;;
esac
STUB
chmod +x "$test_dir/stub"
for tool in uname brew openssl softhsm2-util pkcs11-tool; do
    ln -s "$test_dir/stub" "$test_dir/bin/$tool"
done

case_count=0
new_case() {
    case_count=$((case_count + 1))
    case_dir="$test_dir/case $case_count"
    mkdir -p "$case_dir"
    module="$case_dir/module file.so"
    : > "$module"
    : > "$case_dir/calls"
    stub_fail=''
    stub_label=''
    stub_os=Linux
}

run_setup() {
    if output=$(
        umask 000
        env -i PATH="$test_dir/bin" CASE_DIR="$case_dir" \
            STUB_FAIL="$stub_fail" STUB_LABEL="$stub_label" STUB_OS="$stub_os" \
            HSM_SLOT='test.[slot]' HSM_MODULE="$module" \
            TOKEN_DIR="$case_dir/token dir" SOFTHSM2_CONF_DIR="$case_dir/config dir" \
            "$bash_bin" "$script" "$@" 2>&1
    ); then
        status=0
    else
        status=$?
    fi
}

fail() { printf 'FAIL case %s: %s\n' "$case_count" "$1" >&2; exit 1; }
success() { [[ $status == 0 ]] || fail "expected success (status $status)"; }
failure() { [[ $status != 0 ]] || fail 'expected failure'; }
contains() { [[ "$output" == *"$1"* ]] || fail "missing diagnostic: $1"; }
no_calls() { [[ ! -s "$case_dir/calls" ]] || fail 'unexpected HSM operation'; }
private_file() {
    [[ $(ls -l "$1") == -rw-------* ]] || fail 'file permissions must be 0600'
}
no_pin_output() { [[ "$output" != *"$1"* ]] || fail 'PIN leaked to output'; }

new_case
run_setup --help
success
contains '--generate-pin'
no_calls

for flag in --invalid positional; do
    new_case
    run_setup "$flag"
    failure
    contains 'invalid argument'
    no_calls
done

for flag in -p --pin -f --pin-file -s --slot -m --module -d --tokens-dir -c --cfg-dir -o --out-cfg; do
    new_case
    run_setup "$flag"
    failure
    contains 'requires a value'
    no_calls
    run_setup "$flag" --generate-pin
    failure
    contains 'requires a value'
done

new_case
run_setup --pin secret --slot ''
failure
no_calls
run_setup --pin secret --module "$case_dir/missing.so"
failure
contains 'module not found'
no_calls

for tool in softhsm2-util pkcs11-tool openssl; do
    new_case
    mv "$test_dir/bin/$tool" "$test_dir/$tool"
    run_setup --generate-pin --pin-file "$case_dir/pin" --list-slots
    mv "$test_dir/$tool" "$test_dir/bin/$tool"
    failure
    contains "$tool"
    no_calls
done

new_case
mv "$test_dir/bin/pkcs11-tool" "$test_dir/pkcs11-tool"
run_setup --pin secret
mv "$test_dir/pkcs11-tool" "$test_dir/bin/pkcs11-tool"
success
no_pin_output secret

new_case
pin_file="$case_dir/pin file"
config_file="$case_dir/token config.json"
# Existing world-readable files must be repaired before writing secrets.
: > "$pin_file"
: > "$config_file"
chmod 666 "$pin_file" "$config_file"
run_setup -g -f "$pin_file" -o "$config_file" --list-slots --list-object
success
private_file "$pin_file"
private_file "$config_file"
pin=$(cat "$pin_file")
[[ "$pin" == 0123456789abcdef0123456789abcdef ]] || fail 'generated PIN not saved'
[[ $(cat "$case_dir/received-pin") == "$pin" ]] || fail 'incorrect initialization PIN'
no_pin_output "$pin"
[[ $(cat "$config_file") == *"\"Pin\":\"file:$pin_file\""* ]] || fail 'missing PIN file reference'
[[ $(cat "$case_dir/config dir/softhsm2.conf") == "directories.tokendir = $case_dir/token dir" ]] || fail 'incorrect token directory'
# Reusing an existing PIN and token must not require randomness or initialize again.
: > "$case_dir/calls"
stub_fail=random
run_setup --generate-pin --pin-file "$pin_file" --out-cfg "$config_file"
success
[[ $(cat "$case_dir/calls") == --show-slots ]] || fail 'existing token recreated'
[[ $(cat "$pin_file") == "$pin" ]] || fail 'existing PIN replaced'

new_case
printf 'existing-pin\r\n' > "$case_dir/pin"
run_setup --pin-file "$case_dir/pin"
success
private_file "$case_dir/pin"
[[ $(cat "$case_dir/received-pin") == existing-pin ]] || fail 'PIN line ending not trimmed'
no_pin_output existing-pin

new_case
run_setup --generate-pin
failure
contains '--pin-file or --out-cfg'
no_calls
run_setup --generate-pin --out-cfg "$case_dir/config.json"
success
private_file "$case_dir/config.json"
no_pin_output 0123456789abcdef0123456789abcdef

new_case
# Verify quoting and JSON escaping, including control characters.
run_setup --pin $'a"b\\c\td\001' --slot 'quoted "slot"' --out-cfg "$case_dir/config.json"
success
expected='{"Manufacturer":"SoftHSM","Path":"'"$module"'","TokenLabel":"quoted \"slot\"","Pin":"a\"b\\c\u0009d\u0001"}'
[[ $(cat "$case_dir/config.json") == "$expected" ]] || fail 'invalid JSON escaping'

new_case
stub_label='testXsslotZ' # Matches the old regexp, but is a different token.
run_setup --pin secret --delete
success
[[ $(cat "$case_dir/calls") == $'--show-slots\n--init-token' ]] || fail 'inexact label match'
run_setup --pin secret --delete
success
[[ $(tail -n 3 "$case_dir/calls") == $'--show-slots\n--delete-token\n--init-token' ]] || fail 'token not recreated'

for action in --show-slots --delete-token --init-token --list-slots --list-object random; do
    new_case
    stub_fail=$action
    if [[ "$action" == --delete-token ]]; then stub_label='test.[slot]'; fi
    run_setup --generate-pin --pin-file "$case_dir/pin" --out-cfg "$case_dir/config.json" --delete --list-slots --list-object
    failure
    no_pin_output 0123456789abcdef0123456789abcdef
    case "$action" in
        --show-slots|--delete-token|--init-token|random)
            [[ ! -e "$case_dir/config.json" ]] || fail 'configuration published after failure' ;;
    esac
done

new_case
run_setup --pin secret --cfg-dir "$module/subdir"
failure
no_calls

new_case
run_setup --pin secret --out-cfg "$module/subdir"
failure
no_pin_output secret

new_case
mkdir -p "$case_dir/token dir" "$case_dir/config dir"
: > "$case_dir/token dir/old token"
: > "$case_dir/config dir/unrelated file"
printf 'old config' > "$case_dir/config dir/softhsm2.conf"
run_setup --pin secret --force
success
[[ ! -e "$case_dir/token dir/old token" ]] || fail 'force retained old token storage'
[[ -e "$case_dir/config dir/unrelated file" ]] || fail 'force removed unrelated configuration'
[[ $(cat "$case_dir/config dir/softhsm2.conf") == "directories.tokendir = $case_dir/token dir" ]] || fail 'force retained old configuration'
run_setup --pin secret --force --tokens-dir /
failure
contains 'refusing to remove'

new_case
stub_os=Darwin
module=
mkdir -p "$case_dir/homebrew/lib/softhsm"
: > "$case_dir/homebrew/lib/softhsm/libsofthsm2.so"
run_setup --pin secret --out-cfg "$case_dir/config.json"
success
[[ $(cat "$case_dir/config.json") == *"$case_dir/homebrew/lib/softhsm/libsofthsm2.so"* ]] || fail 'Homebrew prefix ignored'
stub_fail=brew
run_setup --pin secret
failure
stub_fail=
rm "$case_dir/homebrew/lib/softhsm/libsofthsm2.so"
run_setup --pin secret
failure
contains 'module not found'

new_case
stub_os=Unsupported
module=
run_setup --pin secret
failure
contains '--module'
no_calls

printf 'SoftHSM setup: %s isolated cases passed\n' "$case_count"
