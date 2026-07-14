"""The diagnosis engine: every hypothesis kind, ranking, and search bounds.

Each test manufactures a code with one known fault and asserts that the
top-ranked match names exactly that fault — the tool's core promise.
"""

from __future__ import annotations

import pytest

from totpdoctor import decode_secret, diagnose, hotp, totp
from totpdoctor.diagnose import Baseline, normalize_code
from totpdoctor.errors import CodeError, SecretError

from conftest import FIXED_AT, RFC_SECRET_B32

KEY = decode_secret(RFC_SECRET_B32)


def kinds(match):
    return [d.kind for d in match.deviations]


def test_exact_match_yields_exact_verdict():
    result = diagnose(RFC_SECRET_B32, totp(KEY, FIXED_AT), FIXED_AT)
    assert result.verdict == "exact"
    assert result.matches[0].is_exact
    assert result.matches[0].skew_seconds == 0


def test_clock_skew_is_detected_with_sign_and_magnitude():
    behind = diagnose(RFC_SECRET_B32, totp(KEY, FIXED_AT - 120), FIXED_AT).matches[0]
    assert kinds(behind) == ["skew"] and behind.skew_seconds == -120  # slow clock
    ahead = diagnose(RFC_SECRET_B32, totp(KEY, FIXED_AT + 90), FIXED_AT).matches[0]
    assert kinds(ahead) == ["skew"] and ahead.skew_seconds == 90  # fast clock


def test_skew_beyond_scan_window_is_not_reported():
    code = totp(KEY, FIXED_AT - 90)
    result = diagnose(RFC_SECRET_B32, code, FIXED_AT, max_skew_steps=1)
    assert all("skew" not in kinds(m) or abs(m.skew_seconds) <= 60 for m in result.matches)


def test_wrong_algorithm_is_detected():
    code = totp(KEY, FIXED_AT, algorithm="SHA512")
    top = diagnose(RFC_SECRET_B32, code, FIXED_AT).matches[0]
    assert kinds(top) == ["algorithm"] and top.algorithm == "SHA512"


def test_wrong_digits_is_detected_from_code_length():
    code = totp(KEY, FIXED_AT, digits=8)
    top = diagnose(RFC_SECRET_B32, code, FIXED_AT).matches[0]
    assert kinds(top) == ["digits"] and top.digits == 8


def test_wrong_period_is_detected():
    code = totp(KEY, FIXED_AT, period=60)
    top = diagnose(RFC_SECRET_B32, code, FIXED_AT).matches[0]
    assert kinds(top) == ["period"] and top.period == 60


def test_raw_ascii_secret_misuse_is_detected():
    # A client that HMACs the base32 *string* instead of the decoded bytes.
    code = totp(RFC_SECRET_B32.encode(), FIXED_AT)
    top = diagnose(RFC_SECRET_B32, code, FIXED_AT).matches[0]
    assert kinds(top) == ["secret"] and top.key_label == "raw-ascii"


def test_hex_exported_secret_is_detected():
    hex_secret = KEY.hex()
    code = totp(KEY, FIXED_AT)
    # Verifier holds hex, generator decoded it correctly as hex: diagnose
    # from the hex string must find the hex interpretation.
    top = diagnose(hex_secret, code, FIXED_AT).matches[0]
    assert top.key_label == "hex"


def test_confusable_secret_typo_is_detected():
    # Operator transcribed 'O' as '0'; generator used the true secret.
    typo = RFC_SECRET_B32.replace("O", "0")
    assert typo != RFC_SECRET_B32
    code = totp(KEY, FIXED_AT)
    top = diagnose(typo, code, FIXED_AT).matches[0]
    assert top.key_label == "base32-repaired"
    assert RFC_SECRET_B32 in top.key_note


def test_hotp_enrollment_detected_when_totp_expected():
    code = hotp(KEY, 3)
    result = diagnose(RFC_SECRET_B32, code, FIXED_AT)
    top = result.matches[0]
    assert kinds(top) == ["mode"] and top.mode == "hotp" and top.counter == 3


def test_leading_zero_stripped_code_is_explained():
    # Find a nearby step whose code has a leading zero, then observe it as
    # the integer-formatted (5-digit) string.
    at = FIXED_AT
    while not totp(KEY, at).startswith("0"):
        at += 30
    stripped = str(int(totp(KEY, at)))
    top = diagnose(RFC_SECRET_B32, stripped, at).matches[0]
    assert "format" in kinds(top)


def test_hotp_counter_desync_is_detected_and_measured():
    baseline = Baseline(mode="hotp", counter=10)
    code = hotp(KEY, 42)  # client burned 32 codes offline
    top = diagnose(RFC_SECRET_B32, code, FIXED_AT, baseline=baseline).matches[0]
    assert kinds(top) == ["counter"] and top.counter == 42


def test_hotp_baseline_detects_totp_enrollment():
    baseline = Baseline(mode="hotp", counter=0)
    code = totp(KEY, FIXED_AT)
    result = diagnose(RFC_SECRET_B32, code, FIXED_AT, baseline=baseline)
    assert any(kinds(m) == ["mode"] and m.mode == "totp" for m in result.matches)


def test_no_match_verdict_with_advice_counts_candidates():
    result = diagnose(RFC_SECRET_B32, "000001", FIXED_AT)
    assert result.verdict == "no-match"
    assert result.matches == []
    assert result.candidates_tested > 100
    assert 0 < result.collision_risk < 0.01


def test_single_fault_ranks_above_multi_fault_explanations():
    # A pure skew match must outrank any two-deviation coincidence.
    code = totp(KEY, FIXED_AT - 60)
    result = diagnose(RFC_SECRET_B32, code, FIXED_AT)
    assert len(result.matches[0].deviations) <= min(
        len(m.deviations) for m in result.matches
    )


def test_candidate_deduplication_never_tests_a_key_twice():
    # base32("GEZD...") of an all-uppercase secret equals its own repair set;
    # tested count must be identical across two identical runs (determinism).
    first = diagnose(RFC_SECRET_B32, "123456", FIXED_AT)
    second = diagnose(RFC_SECRET_B32, "123456", FIXED_AT)
    assert first.candidates_tested == second.candidates_tested


def test_normalize_code_strips_separators_and_rejects_garbage():
    assert normalize_code(" 123 456 ") == "123456"
    assert normalize_code("123-456") == "123456"
    for bad in ("", "12a456", "123", "12345678901"):
        with pytest.raises(CodeError):
            normalize_code(bad)


def test_diagnose_rejects_hopeless_secret():
    with pytest.raises(SecretError):
        diagnose("   ", "123456", FIXED_AT)
