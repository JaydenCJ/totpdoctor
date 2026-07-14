#!/usr/bin/env python3
"""Use totpdoctor as a library: diagnose a mismatch inside your own tooling.

Deterministic and offline: the reference time is pinned, the "observed" code
is manufactured with a known fault (a 60-second-slow clock), and the script
asserts that the engine attributes it correctly.
"""

from __future__ import annotations

import os
import sys

# Allow running from a fresh checkout without installation.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from totpdoctor import Baseline, decode_secret, diagnose, explain_match, totp

SECRET = "JBSWY3DPEHPK3PXP"
AT = 1783857600  # 2026-07-12 12:00:00 UTC


def main() -> int:
    key = decode_secret(SECRET)

    # A user submits the code their phone showed 60 seconds ago.
    observed = totp(key, AT - 60)

    result = diagnose(
        SECRET,
        observed,
        at=AT,
        baseline=Baseline(mode="totp", algorithm="SHA1", digits=6, period=30),
    )

    print("verdict: %s" % result.verdict)
    print("candidates tested: %d" % result.candidates_tested)
    print("chance-collision risk: %.4f%%" % (result.collision_risk * 100))

    top = result.matches[0]
    explanation = explain_match(top)
    print("top match: %s" % explanation.headline)
    print("fix: %s" % explanation.fix)

    assert result.verdict == "match"
    assert top.skew_seconds == -60, top.skew_seconds
    print("LIBRARY EXAMPLE OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
