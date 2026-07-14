"""Shared fixtures: RFC test keys and an in-process CLI runner.

Everything here is deterministic — fixed secrets, fixed timestamps passed via
``--at`` — so the suite never touches the wall clock or the network.
"""

from __future__ import annotations

import io
import os
import sys

import pytest

# Make a bare clone testable: prefer the in-repo package over any installed one.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from totpdoctor.cli import main  # noqa: E402  (path setup must come first)

# The shared secrets from RFC 4226 appendix D / RFC 6238 appendix B.
RFC_KEY_SHA1 = b"12345678901234567890"
RFC_KEY_SHA256 = b"12345678901234567890123456789012"
RFC_KEY_SHA512 = b"1234567890123456789012345678901234567890123456789012345678901234"

# base32 of RFC_KEY_SHA1 — what an enrollment QR would carry.
RFC_SECRET_B32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

# A fixed "now" for tests: 2026-07-12 12:00:00 UTC, exactly on a 30s boundary.
FIXED_AT = 1783857600


@pytest.fixture
def run_cli():
    """Run the CLI in-process; returns (exit_code, stdout, stderr)."""

    def _run(*argv: str):
        out, err = io.StringIO(), io.StringIO()
        code = main(list(argv), out=out, err=err)
        return code, out.getvalue(), err.getvalue()

    return _run
