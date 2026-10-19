#!/usr/bin/env bash
#
# Source-level security audit for mcp-kdbx.
#
# This catches the obvious slip-ups that would violate the spec's security
# invariants, the kind a reviewer can miss but a grep cannot. It is a
# lightweight backstop, not a substitute for the test suite. Run it in CI and
# locally:
#
#   bash scripts/ci-audit.sh
#
# Each check prints PASS or FAIL with context. The script exits non-zero if any
# check fails.
#
# grep returning 1 (no match) is an expected, non-fatal outcome here, so this
# script does not use `set -e`; failures are tracked explicitly.

set -uo pipefail

cd "$(dirname "$0")/.."

fail=0
pass() { printf 'PASS  %s\n' "$1"; }
problem() {
    printf 'FAIL  %s\n' "$1"
    if [ -n "${2:-}" ]; then
        printf '%s\n' "$2" | sed 's/^/        /'
    fi
    fail=1
}

# ---------------------------------------------------------------------------
# A. stdout is the JSON-RPC channel: a stray println! corrupts the wire.
#    Server sources must not print to stdout. (src/bin/ holds dev helpers like
#    gen-fixtures, which legitimately print; they are not the server.)
# ---------------------------------------------------------------------------
hits=$(grep -rn 'println!' src --include='*.rs' | grep -v '/bin/' | grep -v 'eprintln!' || true)
if [ -n "$hits" ]; then
    problem "println! in server source (stdout is reserved for JSON-RPC; use tracing/eprintln)" "$hits"
else
    pass "no println! in server source"
fi

# ---------------------------------------------------------------------------
# B. No leftover dbg! macros anywhere in src/. dbg! writes to stderr, but it is
#    a debugging artifact that must not ship.
# ---------------------------------------------------------------------------
hits=$(grep -rn 'dbg!' src --include='*.rs' || true)
if [ -n "$hits" ]; then
    problem "dbg! macro left in source" "$hits"
else
    pass "no dbg! macros in source"
fi

# ---------------------------------------------------------------------------
# C. Reveal handlers must fingerprint the value with the session's keyed audit
#    key, never log it and never hash it unkeyed. The reveals module must call
#    Vault::fingerprint (kdbx-core's keyed HMAC) for field values and for
#    attachment bytes, and must not compute a plain digest.
# ---------------------------------------------------------------------------
reveals="src/adapter/reveals.rs"
if [ ! -f "$reveals" ]; then
    problem "expected reveal handlers at $reveals (file missing)"
elif ! grep -q 'fingerprint(Domain::Field' "$reveals"; then
    problem "$reveals does not fingerprint revealed field values (vault.fingerprint(Domain::Field, ..))"
elif ! grep -q 'fingerprint(Domain::Attachment' "$reveals"; then
    problem "$reveals does not fingerprint downloaded attachments (vault.fingerprint(Domain::Attachment, ..))"
elif grep -qE 'sha2|Sha256|hash_revealed' "$reveals"; then
    problem "$reveals computes an unkeyed digest (reveal events must carry keyed fingerprints only)"
else
    pass "reveal handlers log keyed fingerprints only"
fi

# ---------------------------------------------------------------------------
# G. No unkeyed hash of vault content. An unkeyed digest of a low-entropy
#    secret is a lookup oracle, so SHA-256 is allowed only where it hashes the
#    encrypted vault file for save-conflict detection (engine/vault_file.rs).
#    Fingerprints of secrets come from kdbx-core's keyed FingerprintKey.
# ---------------------------------------------------------------------------
hits=$(grep -rlnE 'sha2::|Sha256' src --include='*.rs' | grep -v '^src/engine/vault_file.rs$' || true)
if [ -n "$hits" ]; then
    problem "SHA-256 used outside engine/vault_file.rs (fingerprint secrets with kdbx-core's keyed FingerprintKey instead)" "$hits"
else
    pass "SHA-256 only hashes the vault file (no unkeyed digest of a secret)"
fi

# ---------------------------------------------------------------------------
# D. Secret-bearing fields must not render in Debug. Structurally: in any
#    struct that derives Debug, a field whose name marks it as secret material
#    (password, unlock_cmd, keyfile_bytes, secret, value, base64, bytes, code)
#    must not hold a raw String or Vec<u8> (optionally in an Option). It must
#    be wrapped in engine::secret::Secret, whose Debug prints <redacted>.
#    A struct with a hand-written Debug is not matched (it has no derive).
#    This covers every current and future struct, not a list of named types.
# ---------------------------------------------------------------------------
hits=$(find src -name '*.rs' -print0 | xargs -0 awk '
FNR == 1 { derive_debug = 0; in_struct = 0 }
/^[[:space:]]*#\[derive\(/ { if ($0 ~ /Debug/) derive_debug = 1 }
/^[[:space:]]*(pub(\([a-z]+\))?[[:space:]]+)?struct[[:space:]]+[A-Za-z0-9_]+.*\{[[:space:]]*$/ {
    if (derive_debug) { in_struct = 1; name = $0; sub(/.*struct[[:space:]]+/, "", name); sub(/[^A-Za-z0-9_].*/, "", name) }
    derive_debug = 0
    next
}
/^[[:space:]]*(pub(\([a-z]+\))?[[:space:]]+)?(enum|fn|impl|mod|trait|type|const|static)[[:space:]]/ { derive_debug = 0 }
in_struct && /^[[:space:]]*\}/ { in_struct = 0; next }
in_struct {
    line = $0
    if (match(line, /^[[:space:]]*(pub(\([a-z]+\))?[[:space:]]+)?(password|unlock_cmd|keyfile_bytes|secret|value|base64|bytes|code):[[:space:]]*/)) {
        field = line; sub(/^[[:space:]]*(pub(\([a-z]+\))?[[:space:]]+)?/, "", field); sub(/:.*/, "", field)
        type = substr(line, RSTART + RLENGTH); sub(/,[[:space:]]*$/, "", type)
        if (type ~ /^(Option<)?(String|Vec<u8>)>?$/) printf "%s:%d: %s.%s: %s\n", FILENAME, FNR, name, field, type
    }
}
' || true)
if [ -n "$hits" ]; then
    problem "secret-named field with a raw String/Vec<u8> in a struct deriving Debug (wrap it in Secret<..>)" "$hits"
else
    pass "secret-named fields in Debug-deriving structs are all Secret<..>"
fi

# ---------------------------------------------------------------------------
# E. rmcp's tracing verbosity is capped so the SDK never debug-logs raw
#    JSON-RPC payloads (which carry the password and revealed secrets).
# ---------------------------------------------------------------------------
if grep -q 'rmcp=warn' src/main.rs; then
    pass "rmcp tracing is capped (rmcp=warn) in main.rs"
else
    problem "main.rs does not cap rmcp tracing (rmcp=warn); the SDK could log raw payloads"
fi

# ---------------------------------------------------------------------------
# F. The MCP adapter layer is free of direct filesystem writes: all disk I/O
#    goes through engine (vault, stage, audit). A write appearing in the
#    adapter is a layering break worth a second look.
# ---------------------------------------------------------------------------
hits=$(grep -rn 'fs::write\|File::create\|OpenOptions' src/adapter --include='*.rs' || true)
if [ -n "$hits" ]; then
    problem "direct filesystem write in the adapter layer (disk I/O belongs in engine)" "$hits"
else
    pass "no direct filesystem writes in the adapter layer"
fi

echo
if [ "$fail" -ne 0 ]; then
    echo "ci-audit: one or more checks FAILED"
    exit 1
fi
echo "ci-audit: all checks passed"
