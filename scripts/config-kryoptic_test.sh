#!/bin/bash
# Isolated checks of config-kryoptic.sh with stub tools: no Kryoptic, Rust or
# network is needed. The stubs record their arguments.
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(cd -- "$script_dir/.." && pwd)
script=$script_dir/config-kryoptic.sh
# Under /tmp and not TMPDIR, which may be one the script refuses to use. The
# physical path, because the script reports paths without symlinks.
test_dir=$(cd -- "$(mktemp -d /tmp/config-kryoptic-test.XXXXXX)" && pwd -P)
trap 'rm -rf -- "$test_dir"' EXIT
export CALLS="$test_dir/calls"

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

stub() {
    cat > "$test_dir/bin/$1" <<'STUB'
#!/bin/bash
tool=${0##*/}
printf '%s %s\n' "$tool" "$*" >> "$CALLS"
case "$tool" in
    openssl) printf '0123456789abcdef0123456789abcdef\n' ;;
    pkg-config)
        # the package is the last argument
        [[ "${@: -1}" != "${STUB_PKG_MISSING:-}" ]]
        ;;
    git)
        [[ -z "${STUB_GIT_FAIL:-}" ]] || exit 7
        # git clone --depth 1 --branch TAG REPO DEST
        mkdir -p "${@: -1}"
        ;;
    cargo)
        mkdir -p target/release
        : > target/release/libkryoptic_pkcs11.so
        ;;
    go)
        printf 'go-cwd %s\n' "$PWD" >> "$CALLS"
        [[ -z "${STUB_GO_FAIL:-}" ]]
        ;;
esac
STUB
    chmod +x "$test_dir/bin/$1"
}

private() { [[ -n $(find "$1" -perm "$2") ]]; }

mkdir -p "$test_dir/bin"
for tool in openssl git cargo go pkg-config; do stub "$tool"; done
export PATH="$test_dir/bin:$PATH"

# --module: no build, the token is initialized, the files are private
fixture="$test_dir/with module"
module="$test_dir/libkryoptic_pkcs11.so"
: > "$module"
out=$("$script" --module "$module" --dir "$fixture" --out-cfg "$fixture/token.json")
if grep -qE '^(git|cargo|pkg-config) ' "$CALLS"; then fail '--module must not build'; fi
grep -qF "go run scripts/p11-init-token.go --module $module --slot 1 --label xpki_mldsa --pin-file $fixture/pin.txt" "$CALLS" \
    || fail 'the token was not initialized'
grep -qF "go-cwd $repo_root" "$CALLS" || fail 'go run did not run in the module'
grep -qF "dbargs = \"$fixture/token.sql\"" "$fixture/token.conf" || fail 'token.conf has no database'
grep -qF "\"Path\":\"$module\"" "$fixture/token.json" || fail 'the JSON has no module'
grep -qF "\"TokenLabel\":\"xpki_mldsa\"" "$fixture/token.json" || fail 'the JSON has no label'
grep -qF "\"Pin\":\"file:$fixture/pin.txt\"" "$fixture/token.json" || fail 'the JSON has no PIN file'
for file in pin.txt token.conf token.json; do
    private "$fixture/$file" 600 || fail "$file is not private"
done
private "$fixture" 700 || fail 'the fixture directory is not private'
case "$out" in *0123456789abcdef*) fail 'the PIN was printed' ;; esac

# a second run replaces the token, and repairs what a permissive run left
: > "$fixture/token.sql"
chmod 755 "$fixture"
chmod 644 "$fixture/pin.txt" "$fixture/token.conf"
"$script" --module "$module" --dir "$fixture" --out-cfg "$fixture/token.json" >/dev/null
[[ ! -e "$fixture/token.sql" ]] || fail 'the old token was kept'
private "$fixture" 700 || fail 'the directory mode was not repaired'
private "$fixture/pin.txt" 600 || fail 'the PIN file mode was not repaired'
private "$fixture/token.conf" 600 || fail 'the token.conf mode was not repaired'

# a symlink does not send the PIN elsewhere
target="$test_dir/world-readable"
: > "$target"
chmod 644 "$target"
rm -f "$fixture/pin.txt"
ln -s "$target" "$fixture/pin.txt"
"$script" --module "$module" --dir "$fixture" --out-cfg "$fixture/token.json" >/dev/null
[[ ! -s "$target" ]] || fail 'the PIN followed a symlink'
[[ ! -L "$fixture/pin.txt" ]] || fail 'the PIN file is still a symlink'

# relative paths are made absolute, since the module is loaded from elsewhere
: > "$CALLS"
(
    cd "$test_dir"
    "$script" --module libkryoptic_pkcs11.so --dir relative --out-cfg relative/token.json >/dev/null
)
grep -qF "\"Path\":\"$test_dir/libkryoptic_pkcs11.so\"" "$test_dir/relative/token.json" || fail 'the module path is relative'
grep -qF "\"Pin\":\"file:$test_dir/relative/pin.txt\"" "$test_dir/relative/token.json" || fail 'the PIN path is relative'
grep -qF "dbargs = \"$test_dir/relative/token.sql\"" "$test_dir/relative/token.conf" || fail 'the database path is relative'

# without --module: the pinned tag is built with the ML-DSA feature
: > "$CALLS"
fixture="$test_dir/build"
"$script" --dir "$fixture" --out-cfg "$fixture/token.json" >/dev/null
grep -qF "git clone --depth 1 --branch v1.5.4 https://github.com/latchset/kryoptic.git $fixture/src-v1.5.4.tmp" "$CALLS" \
    || fail 'the pinned tag was not cloned'
grep -q 'cargo build --release -p kryoptic --features pqc' "$CALLS" || fail 'pqc was not enabled'
grep -qF "$fixture/src-v1.5.4/target/release/libkryoptic_pkcs11.so" "$fixture/token.json" || fail 'the JSON has no built module'

# the default location is per user, not the shared /tmp, and the configuration
# is written next to the token
home="$test_dir/home"
mkdir -m 700 "$home"
HOME=$home "$script" --module "$module" >/dev/null
default_dir="$home/.xpki/kryoptic"
grep -qF "dbargs = \"$default_dir/token.sql\"" "$default_dir/token.conf" || fail 'the default directory is not in HOME'
grep -qF "\"Pin\":\"file:$default_dir/pin.txt\"" "$default_dir/token.json" || fail 'the default configuration is not in the fixture'
private "$default_dir" 700 || fail 'the default directory is not private'

# refuse_location NEEDLE ARGS...: the run fails naming NEEDLE and writes no PIN
refuse_location() {
    local needle=$1 out
    shift
    if out=$("$script" "$@" 2>&1); then fail "this location must fail: $*"; fi
    case "$out" in
        *"other users can replace $needle"*) ;;
        *) fail "$needle was not named: $out" ;;
    esac
}

# A directory others can write lets them rename the fixture and substitute a
# symlink, which the checks on the fixture itself cannot see.
for mode in 775 757 777; do
    shared="$test_dir/shared-$mode"
    mkdir -m "$mode" "$shared"
    refuse_location "$shared" --module "$module" --dir "$shared/fixture" --out-cfg "$shared/fixture/token.json"
    [[ ! -e "$shared/fixture/pin.txt" ]] || fail "a PIN was written under a $mode directory"
    # at any depth
    mkdir -p "$shared/a/b"
    refuse_location "$shared" --module "$module" --dir "$shared/a/b/fixture" --out-cfg "$shared/a/b/fixture/token.json"
done
shared="$test_dir/shared-775"
safe="$test_dir/safe"
mkdir -m 700 "$safe"
# the configuration names the module to load, and the module gets loaded
refuse_location "$shared" --module "$module" --dir "$safe/fixture" --out-cfg "$shared/token.json"
[[ ! -e "$shared/token.json" ]] || fail 'a configuration was written under a shared directory'
cp "$module" "$shared/module.so"
refuse_location "$shared" --module "$shared/module.so" --dir "$safe/fixture" --out-cfg "$safe/fixture/token.json"
# a symlink does not hide where the fixture really is
ln -s "$shared" "$test_dir/shared-link"
refuse_location "$shared" --module "$module" --dir "$test_dir/shared-link/fixture" --out-cfg "$safe/fixture/token.json"

# sticky, like /tmp: others cannot rename what they do not own
mkdir -m 1777 "$test_dir/sticky"
"$script" --module "$module" --dir "$test_dir/sticky/fixture" --out-cfg "$test_dir/sticky/fixture/token.json" >/dev/null
# a safe location behind a symlink is used by its physical path, so the symlink
# cannot be swapped later
ln -s "$safe" "$test_dir/safe-link"
"$script" --module "$module" --dir "$test_dir/safe-link/fixture" --out-cfg "$test_dir/safe-link/fixture/token.json" >/dev/null
grep -qF "dbargs = \"$safe/fixture/token.sql\"" "$safe/fixture/token.conf" || fail 'the symlink was kept in token.conf'
grep -qF "\"Pin\":\"file:$safe/fixture/pin.txt\"" "$safe/fixture/token.json" || fail 'the symlink was kept in the configuration'

# a missing library stops the run before the clone, not at the final link
: > "$CALLS"
fixture="$test_dir/no-library"
for library in sqlite3 openssl; do
    out=$(STUB_PKG_MISSING=$library "$script" --dir "$fixture" --out-cfg "$fixture/token.json" 2>&1) \
        && fail "a missing $library must fail"
    case "$out" in
        *'Please install'*) ;;
        *) fail "a missing $library was not named: $out" ;;
    esac
done
if grep -qE '^(git|cargo) ' "$CALLS"; then fail 'a missing library must stop before the build'; fi
grep -q 'pkg-config --atleast-version=3.5 openssl' "$CALLS" || fail 'the OpenSSL version was not checked'

# an interrupted clone is not built by the next run
: > "$CALLS"
fixture="$test_dir/interrupted"
if STUB_GIT_FAIL=1 "$script" --dir "$fixture" --out-cfg "$fixture/token.json" >/dev/null 2>&1; then
    fail 'a failed clone must fail'
fi
[[ ! -e "$fixture/src-v1.5.4" ]] || fail 'a failed clone left the source directory'
"$script" --dir "$fixture" --out-cfg "$fixture/token.json" >/dev/null
grep -q 'cargo build' "$CALLS" || fail 'the next run did not build'

# failures
if "$script" --module "$test_dir/missing.so" --dir "$fixture" 2>/dev/null; then fail 'a missing module must fail'; fi
if "$script" --dir "$test_dir/quote\"d" --module "$module" 2>/dev/null; then fail 'a quoted directory must fail'; fi
if "$script" --dir "$test_dir/tab	bed" --module "$module" 2>/dev/null; then fail 'a tab in the directory must fail'; fi
if "$script" --version ../../evil --module "$module" --dir "$fixture" 2>/dev/null; then fail 'a path as a version must fail'; fi
if "$script" --bad 2>/dev/null; then fail 'an unknown option must fail'; fi
ln -s "$fixture" "$test_dir/link"
if "$script" --dir "$test_dir/link" --module "$module" 2>/dev/null; then fail 'a symlinked directory must fail'; fi
if STUB_GO_FAIL=1 "$script" --module "$module" --dir "$fixture" --out-cfg "$fixture/after.json" >/dev/null 2>&1; then
    fail 'a failed token initialization must fail'
fi
[[ ! -e "$fixture/after.json" ]] || fail 'a configuration was written for a token that failed'

printf 'config-kryoptic.sh: ok\n'
