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
# C. Reveal handlers must hash the value, never log it. The reveals module must
#    reference hash_revealed (the domain-separated reveal hash) and sha256 (the
#    attachment content fingerprint).
# ---------------------------------------------------------------------------
reveals="src/adapter/reveals.rs"
if [ ! -f "$reveals" ]; then
    problem "expected reveal handlers at $reveals (file missing)"
elif ! grep -q 'hash_revealed' "$reveals"; then
    problem "$reveals does not reference hash_revealed (reveal events must log a hash, not the value)"
elif ! grep -q 'sha256' "$reveals"; then
    problem "$reveals does not reference sha256 (attachment reveals must log a content fingerprint)"
else
    pass "reveal handlers use hash_revealed and sha256"
fi

# ---------------------------------------------------------------------------
# D. The secret-bearing types must keep their hand-written redacting Debug. A
#    derived Debug would let a stray tracing::debug!(?x) leak the master
#    password. A manual impl alongside a derive does not compile, so the
#    presence of the manual impl guarantees no derive.
# ---------------------------------------------------------------------------
if grep -q 'impl std::fmt::Debug for Config' src/kdbx_core/config.rs; then
    pass "Config has a hand-written redacting Debug"
else
    problem "Config is missing its hand-written redacting Debug (src/kdbx_core/config.rs)"
fi
if grep -q 'impl std::fmt::Debug for UnlockParams' src/adapter/lifecycle.rs; then
    pass "UnlockParams has a hand-written redacting Debug"
else
    problem "UnlockParams is missing its hand-written redacting Debug (src/adapter/lifecycle.rs)"
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
#    goes through kdbx_core (vault, stage, audit). A write appearing in the
#    adapter is a layering break worth a second look.
# ---------------------------------------------------------------------------
hits=$(grep -rn 'fs::write\|File::create\|OpenOptions' src/adapter --include='*.rs' || true)
if [ -n "$hits" ]; then
    problem "direct filesystem write in the adapter layer (disk I/O belongs in kdbx_core)" "$hits"
else
    pass "no direct filesystem writes in the adapter layer"
fi

echo
if [ "$fail" -ne 0 ]; then
    echo "ci-audit: one or more checks FAILED"
    exit 1
fi
echo "ci-audit: all checks passed"
