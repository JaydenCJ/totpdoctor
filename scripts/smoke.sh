#!/usr/bin/env bash
# Smoke test for totpdoctor: generate codes at a fixed instant, diagnose a
# skewed code, a wrong-algorithm code, and a never-decoded secret, then lint
# a mangled secret and audit an otpauth URI. Self-contained: pure stdlib,
# no network, idempotent (works from a clean tree, no install needed).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-python3}"
if [ -x "$ROOT/.venv/bin/python" ]; then
  PYTHON="$ROOT/.venv/bin/python"
fi

# Zero runtime dependencies, so running from src/ needs no install.
export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/totpdoctor-smoke.XXXXXX")"
trap 'rm -rf "$WORKDIR"' EXIT

fail() { echo "SMOKE FAIL: $1" >&2; exit 1; }

echo "[smoke] python: $("$PYTHON" --version 2>&1)"

# Fixed inputs: the RFC 4226/6238 shared secret and a frozen reference time.
SECRET="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
AT="2026-07-12T12:00:00Z"

# 1. gen: the RFC secret at t=59 must yield the RFC 6238 SHA1 vector 287082.
gen_out="$("$PYTHON" -m totpdoctor gen --secret "$SECRET" --at 59)"
echo "$gen_out" | sed 's/^/[gen] /'
echo "$gen_out" | grep -q "287082" || fail "gen did not reproduce the RFC 6238 vector"

# 2. diagnose: a code from 90 seconds ago must be explained as clock skew.
skewed="$("$PYTHON" -m totpdoctor gen --secret "$SECRET" --at 2026-07-12T11:58:30Z --json \
  | "$PYTHON" -c 'import json,sys; print(json.load(sys.stdin)["codes"][1]["code"])')"
diag_out="$("$PYTHON" -m totpdoctor diagnose --secret "$SECRET" --code "$skewed" --at "$AT")"
echo "$diag_out" | sed 's/^/[diagnose] /'
echo "$diag_out" | grep -q "clock skew: -90 s" || fail "skew of -90 s not diagnosed"

# 3. diagnose: a SHA256-generated code against a SHA1 baseline.
sha256_code="$("$PYTHON" -m totpdoctor gen --secret "$SECRET" --algorithm SHA256 \
  --at "$AT" --json | "$PYTHON" -c 'import json,sys; print(json.load(sys.stdin)["codes"][1]["code"])')"
algo_out="$("$PYTHON" -m totpdoctor diagnose --secret "$SECRET" --code "$sha256_code" --at "$AT")"
echo "$algo_out" | grep -q "algorithm mismatch: SHA256 vs SHA1" \
  || fail "algorithm mismatch not diagnosed"

# 4. diagnose: a client that HMACs the base32 string instead of the key bytes.
raw_code="$("$PYTHON" -c "
import sys; sys.path.insert(0, '$ROOT/src')
from totpdoctor import totp
from totpdoctor.cli import parse_when
print(totp(b'$SECRET', parse_when('$AT')))")"
raw_out="$("$PYTHON" -m totpdoctor diagnose --secret "$SECRET" --code "$raw_code" --at "$AT")"
echo "$raw_out" | grep -q "secret decoding mismatch (raw-ascii)" \
  || fail "raw-ascii secret misuse not diagnosed"

# 5. diagnose: an unmatchable code must exit 1 and say NO MATCH.
set +e
nomatch_out="$("$PYTHON" -m totpdoctor diagnose --secret "$SECRET" --code 000001 --at "$AT")"
nomatch_rc=$?
set -e
[ "$nomatch_rc" -eq 1 ] || fail "no-match should exit 1, got $nomatch_rc"
echo "$nomatch_out" | grep -q "NO MATCH" || fail "no-match verdict missing"

# 6. diagnose --json is valid JSON with the verdict field.
"$PYTHON" -m totpdoctor diagnose --secret "$SECRET" --code "$skewed" --at "$AT" --json \
  > "$WORKDIR/diag.json"
"$PYTHON" -c "
import json
payload = json.load(open('$WORKDIR/diag.json'))
assert payload['verdict'] == 'match', payload['verdict']
assert payload['matches'][0]['skew_seconds'] == -90
" || fail "JSON output malformed"

# 7. secret: a mangled secret is linted with a repair candidate; exits 1.
set +e
lint_out="$("$PYTHON" -m totpdoctor secret 'jbsw 0ehk')"
lint_rc=$?
set -e
[ "$lint_rc" -eq 1 ] || fail "undecodable secret should exit 1, got $lint_rc"
echo "$lint_out" | sed 's/^/[secret] /'
echo "$lint_out" | grep -q "repair candidate: JBSWOEHK" || fail "repair candidate missing"

# 8. uri: audit flags the algorithm-interop pitfall.
uri_out="$("$PYTHON" -m totpdoctor uri \
  "otpauth://totp/Example:alice@example.test?secret=$SECRET&issuer=Example&algorithm=SHA256")"
echo "$uri_out" | grep -q "ignore this parameter" || fail "uri audit warning missing"

# 9. --version agrees with the package.
version_out="$("$PYTHON" -m totpdoctor --version)"
pkg_version="$("$PYTHON" -c 'import totpdoctor; print(totpdoctor.__version__)')"
[ "$version_out" = "totpdoctor $pkg_version" ] \
  || fail "--version mismatch: '$version_out' vs package '$pkg_version'"

echo "SMOKE OK"
