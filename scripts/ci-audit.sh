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
# C. Audit events carry audit-keyed fingerprints; tool responses carry
#    session-keyed ones; nothing hashes a secret unkeyed. Two keys exist:
#    Vault::audit_fingerprint (the stable Argon2-derived key, audit file only)
#    and Vault::fingerprint (the random per-session key, tool responses only).
#    The types keep them apart (an audit event's fingerprint is a
#    KeyedFingerprint, which only AuditKey::fingerprint builds); this check
#    pins that structure and the call sites:
#    C1. the reveal variants of AuditEvent hold Option<KeyedFingerprint>, and
#        no AuditEvent field holds a bare Fingerprint;
#    C2. KeyedFingerprint has no pub field, and outside the tests its only
#        literal construction is inside `impl AuditKey`;
#    C3. each reveal handler (kdbx_reveal_password, kdbx_reveal_protected,
#        kdbx_download_attachment) calls vault.audit_fingerprint(..);
#    C4. the session-keyed vault.fingerprint(..) is called in the adapter only
#        by kdbx_download_attachment, whose response reports it;
#    C5. the reveal module computes no plain digest.
# ---------------------------------------------------------------------------
reveals="src/adapter/reveals.rs"
audit_rs="src/engine/audit.rs"
c_fail=""
if [ ! -f "$reveals" ] || [ ! -f "$audit_rs" ]; then
    c_fail="expected $reveals and $audit_rs (file missing)"
else
    # The non-test part of audit.rs (everything before #[cfg(test)]).
    audit_src=$(awk '/^#\[cfg\(test\)\]/ { exit } { print }' "$audit_rs")
    # C1: fields declared inside `pub enum AuditEvent { .. }`.
    enum_fields=$(printf '%s\n' "$audit_src" | awk '
        /^pub enum AuditEvent/ { inside = 1; next }
        inside && /^}/ { inside = 0 }
        inside && /^        fingerprint:/ { print }')
    keyed=$(printf '%s\n' "$enum_fields" | grep -c 'fingerprint: Option<KeyedFingerprint>,' || true)
    other=$(printf '%s\n' "$enum_fields" | grep -v 'fingerprint: Option<KeyedFingerprint>,' | grep -c . || true)
    if [ "$keyed" -ne 3 ] || [ "$other" -ne 0 ]; then
        c_fail="AuditEvent's reveal variants must hold fingerprint: Option<KeyedFingerprint> (found $keyed keyed, $other other)"
    fi
    # C2: KeyedFingerprint's fields are private, and it is built only by AuditKey.
    if [ -z "$c_fail" ]; then
        pub_fields=$(printf '%s\n' "$audit_src" | awk '
            /^pub struct KeyedFingerprint/ { inside = 1; next }
            inside && /^}/ { inside = 0 }
            inside && /^    pub / { print }')
        stray=$(printf '%s\n' "$audit_src" | awk '
            /^impl AuditKey/ { in_impl = 1 }
            in_impl && /^}/ { in_impl = 0 }
            /^ *\/\// { next }
            !in_impl {
                # Drop the declarations (struct, impl, return type), then any
                # remaining `KeyedFingerprint {` is a struct literal.
                line = $0
                gsub(/(struct|impl|->) KeyedFingerprint \{/, "", line)
                if (line ~ /KeyedFingerprint \{/) print NR": "$0
            }')
        if [ -n "$pub_fields" ]; then
            c_fail="KeyedFingerprint must keep its fields private (only AuditKey::fingerprint builds it)"
        elif [ -n "$stray" ]; then
            c_fail="KeyedFingerprint built outside impl AuditKey in $audit_rs: $stray"
        fi
    fi
    # C3 and C4: per-function call sites in the adapter.
    if [ -z "$c_fail" ]; then
        sites=$(awk '
            match($0, /fn [a-z_0-9]+/) { fn = substr($0, RSTART + 3, RLENGTH - 3) }
            /vault\.audit_fingerprint\(/ { print "audit " fn }
            /vault\.fingerprint\(/ { print "session " fn " " FILENAME ":" FNR }
        ' src/adapter/*.rs)
        for handler in kdbx_reveal_password kdbx_reveal_protected kdbx_download_attachment; do
            if ! printf '%s\n' "$sites" | grep -qx "audit $handler"; then
                c_fail="$handler does not fingerprint its audit event with vault.audit_fingerprint(..)"
                break
            fi
        done
        session_elsewhere=$(printf '%s\n' "$sites" | awk '$1 == "session" && $2 != "kdbx_download_attachment" { print $3 }')
        if [ -z "$c_fail" ] && [ -n "$session_elsewhere" ]; then
            c_fail="session-keyed vault.fingerprint(..) used outside kdbx_download_attachment's response: $session_elsewhere"
        fi
    fi
    # C5: no plain digest in the reveal module.
    if [ -z "$c_fail" ] && grep -qE 'sha2|Sha256|hash_revealed' "$reveals"; then
        c_fail="$reveals computes an unkeyed digest (reveal events carry keyed fingerprints only)"
    fi
fi
if [ -n "$c_fail" ]; then
    problem "$c_fail"
else
    pass "audit events use the audit key, tool responses the session key, nothing unkeyed"
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
