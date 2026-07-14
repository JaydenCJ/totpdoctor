#!/usr/bin/env bash
# Walk through every fault class totpdoctor can diagnose, one at a time.
# Deterministic: the reference time is pinned, no network, no install needed.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-python3}"
export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"

SECRET="JBSWY3DPEHPK3PXP"
AT="2026-07-12T12:00:00Z"

# Helper: current code for arbitrary generator-side parameters.
code_with() {
  "$PYTHON" - "$@" <<'PY'
import sys
from totpdoctor import totp, decode_secret
from totpdoctor.cli import parse_when

secret, at = sys.argv[1], parse_when(sys.argv[2])
kwargs = dict(kv.split("=") for kv in sys.argv[3:])
key = secret.encode() if kwargs.pop("raw", "") else decode_secret(secret)
print(totp(key, at + int(kwargs.pop("shift", 0)),
           period=int(kwargs.pop("period", 30)),
           digits=int(kwargs.pop("digits", 6)),
           algorithm=kwargs.pop("algorithm", "SHA1")))
PY
}

section() { printf '\n=== %s ===\n' "$1"; }

section "1. clock skew: the user's phone is 90 seconds slow"
"$PYTHON" -m totpdoctor diagnose --secret "$SECRET" --at "$AT" \
  --code "$(code_with "$SECRET" "$AT" shift=-90)"

section "2. wrong algorithm: generator uses SHA256, verifier expects SHA1"
"$PYTHON" -m totpdoctor diagnose --secret "$SECRET" --at "$AT" \
  --code "$(code_with "$SECRET" "$AT" algorithm=SHA256)"

section "3. wrong digits: generator makes 8-digit codes"
"$PYTHON" -m totpdoctor diagnose --secret "$SECRET" --at "$AT" \
  --code "$(code_with "$SECRET" "$AT" digits=8)"

section "4. wrong period: generator steps every 60 s"
"$PYTHON" -m totpdoctor diagnose --secret "$SECRET" --at "$AT" \
  --code "$(code_with "$SECRET" "$AT" period=60)"

section "5. base32 never decoded: client HMACs the secret string itself"
"$PYTHON" -m totpdoctor diagnose --secret "$SECRET" --at "$AT" \
  --code "$(code_with "$SECRET" "$AT" raw=1)"

section "6. nothing matches: wrong secret entirely (exit code 1)"
"$PYTHON" -m totpdoctor diagnose --secret "$SECRET" --at "$AT" --code 000001 || true

echo
echo "WALKTHROUGH DONE"
