"""RFC 4226 / RFC 6238 conformance and primitive-level behavior.

The published appendix vectors are the ground truth for the whole tool: if
these fail, every diagnosis built on top of them would be fiction.
"""

from __future__ import annotations

import pytest

from totpdoctor.errors import ParameterError
from totpdoctor.otp import (
    format_utc,
    hotp,
    normalize_algorithm,
    seconds_remaining,
    step_window,
    time_step,
    totp,
)

from conftest import RFC_KEY_SHA1, RFC_KEY_SHA256, RFC_KEY_SHA512

# RFC 4226 appendix D: HOTP(SHA1, 6 digits) for counters 0..9.
RFC4226_VECTORS = [
    (0, "755224"),
    (1, "287082"),
    (2, "359152"),
    (3, "969429"),
    (4, "338314"),
    (5, "254676"),
    (6, "287922"),
    (7, "162583"),
    (8, "399871"),
    (9, "520489"),
]

# RFC 6238 appendix B: 8-digit TOTP at six instants for all three algorithms.
RFC6238_VECTORS = [
    (59, "94287082", "46119246", "90693936"),
    (1111111109, "07081804", "68084774", "25091201"),
    (1111111111, "14050471", "67062674", "99943326"),
    (1234567890, "89005924", "91819424", "93441116"),
    (2000000000, "69279037", "90698825", "38618901"),
    (20000000000, "65353130", "77737706", "47863826"),
]


def test_hotp_matches_rfc4226_appendix_d():
    for counter, expected in RFC4226_VECTORS:
        assert hotp(RFC_KEY_SHA1, counter) == expected, "counter %d" % counter


@pytest.mark.parametrize(
    "key,algorithm,column",
    [
        (RFC_KEY_SHA1, "SHA1", 1),
        (RFC_KEY_SHA256, "SHA256", 2),
        (RFC_KEY_SHA512, "SHA512", 3),
    ],
)
def test_totp_matches_rfc6238_appendix_b(key, algorithm, column):
    for row in RFC6238_VECTORS:
        at, expected = row[0], row[column]
        assert totp(key, at, digits=8, algorithm=algorithm) == expected, "t=%d" % at


def test_hotp_preserves_leading_zeros_as_string():
    # RFC 6238's t=1111111109 SHA1 vector starts with '0' — the classic case
    # that breaks integer-typed implementations.
    code = totp(RFC_KEY_SHA1, 1111111109, digits=8)
    assert code == "07081804"
    assert len(code) == 8


def test_hotp_six_digits_is_suffix_of_eight_digits():
    # Dynamic truncation then modulo means the 6-digit code is the 8-digit
    # code's suffix; the diagnosis engine's digits hypothesis relies on this.
    assert totp(RFC_KEY_SHA1, 59, digits=8).endswith(totp(RFC_KEY_SHA1, 59, digits=6))


def test_hotp_rejects_out_of_range_parameters():
    for digits in (3, 11, 0, -1):
        with pytest.raises(ParameterError):
            hotp(RFC_KEY_SHA1, 0, digits=digits)
    with pytest.raises(ParameterError):
        hotp(RFC_KEY_SHA1, -1)  # negative counter
    with pytest.raises(ParameterError):
        totp(RFC_KEY_SHA1, 59, period=0)  # absurd period


def test_normalize_algorithm_accepts_wild_spellings():
    # Spellings seen in real otpauth URIs must all canonicalize.
    for spelling in ("sha1", "SHA-256", "sha-512", "Sha256"):
        assert normalize_algorithm(spelling) in ("SHA1", "SHA256", "SHA512")
    with pytest.raises(ParameterError):
        normalize_algorithm("MD5")


def test_time_step_window_and_remaining_agree():
    step = time_step(1783857612, period=30)
    start, end = step_window(step, period=30)
    assert start <= 1783857612 < end
    assert end - start == 30
    # On a boundary a fresh code has the full period ahead of it.
    assert seconds_remaining(1783857600, period=30) == 30
    assert seconds_remaining(1783857629, period=30) == 1


def test_totp_rejects_time_before_epoch_offset():
    with pytest.raises(ParameterError):
        totp(RFC_KEY_SHA1, 10, t0=100)


def test_format_utc_is_stable_and_utc():
    assert format_utc(1783857600) == "2026-07-12 12:00:00Z"
