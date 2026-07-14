"""RFC 4226 (HOTP) and RFC 6238 (TOTP) primitives.

Pure functions over explicit inputs — key bytes, counter, timestamp — with no
hidden clock access, so every caller (and every test) is deterministic. The
current wall clock only ever enters at the CLI boundary.
"""

from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timezone
from typing import Tuple

from .errors import ParameterError

#: Supported HMAC hash algorithms, in the order the diagnosis engine tries them.
ALGORITHMS = ("SHA1", "SHA256", "SHA512")

_HASHES = {
    "SHA1": hashlib.sha1,
    "SHA256": hashlib.sha256,
    "SHA512": hashlib.sha512,
}

#: Digit counts that RFC 4226 dynamic truncation can meaningfully produce.
MIN_DIGITS = 4
MAX_DIGITS = 10

MIN_PERIOD = 1
MAX_PERIOD = 3600


def normalize_algorithm(name: str) -> str:
    """Return the canonical (upper-case, dash-free) algorithm name.

    Accepts spellings seen in the wild in otpauth URIs: ``sha1``, ``SHA-256``.
    """
    canonical = name.strip().upper().replace("-", "")
    if canonical not in _HASHES:
        raise ParameterError(
            "unsupported algorithm %r (supported: %s)" % (name, ", ".join(ALGORITHMS))
        )
    return canonical


def validate_digits(digits: int) -> int:
    if not MIN_DIGITS <= digits <= MAX_DIGITS:
        raise ParameterError(
            "digits must be between %d and %d, got %d" % (MIN_DIGITS, MAX_DIGITS, digits)
        )
    return digits


def validate_period(period: int) -> int:
    if not MIN_PERIOD <= period <= MAX_PERIOD:
        raise ParameterError(
            "period must be between %ds and %ds, got %d" % (MIN_PERIOD, MAX_PERIOD, period)
        )
    return period


def hotp(key: bytes, counter: int, digits: int = 6, algorithm: str = "SHA1") -> str:
    """Compute an RFC 4226 HOTP value as a zero-padded decimal string.

    Leading zeros are significant — ``"007392"`` is a different observed code
    than ``"7392"`` — which is exactly why this returns ``str`` and not ``int``.
    """
    validate_digits(digits)
    if counter < 0:
        raise ParameterError("counter must be non-negative, got %d" % counter)
    algorithm = normalize_algorithm(algorithm)
    message = counter.to_bytes(8, "big")
    digest = hmac.new(key, message, _HASHES[algorithm]).digest()
    offset = digest[-1] & 0x0F
    binary = int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFFFFFF
    return str(binary % (10 ** digits)).zfill(digits)


def time_step(at: int, period: int = 30, t0: int = 0) -> int:
    """Return the TOTP time step (RFC 6238 ``T``) for a Unix timestamp."""
    validate_period(period)
    return (at - t0) // period


def totp(
    key: bytes,
    at: int,
    period: int = 30,
    digits: int = 6,
    algorithm: str = "SHA1",
    t0: int = 0,
) -> str:
    """Compute an RFC 6238 TOTP value for the given Unix timestamp."""
    step = time_step(at, period, t0)
    if step < 0:
        raise ParameterError("timestamp %d is before the epoch offset t0=%d" % (at, t0))
    return hotp(key, step, digits=digits, algorithm=algorithm)


def step_window(step: int, period: int = 30, t0: int = 0) -> Tuple[int, int]:
    """Return the ``[start, end)`` Unix-time interval covered by a time step."""
    validate_period(period)
    start = t0 + step * period
    return start, start + period


def seconds_remaining(at: int, period: int = 30, t0: int = 0) -> int:
    """Seconds until the current TOTP code rolls over (1..period)."""
    step = time_step(at, period, t0)
    _, end = step_window(step, period, t0)
    return end - at


def format_utc(ts: int) -> str:
    """Render a Unix timestamp as a compact UTC string for reports."""
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
