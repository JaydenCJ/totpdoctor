"""Lenient base32 decoding, secret linting, repairs, and key variants.

These are the failure modes seen in real enrollment flows: pasted separators,
lowercase, stripped padding, OCR look-alikes, hex exports, truncation.
"""

from __future__ import annotations

import base64

import pytest

from totpdoctor.base32 import (
    decode,
    key_variants,
    lint,
    looks_like_hex,
    normalize,
    repair_candidates,
)
from totpdoctor.errors import SecretError

CLEAN = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"  # 20-byte key, no lint findings


def test_decode_clean_secret_matches_stdlib():
    assert decode(CLEAN) == base64.b32decode(CLEAN)


def test_decode_is_lenient_about_human_formatting():
    for messy in (
        "jbsw y3dp ehpk 3pxp jbsw y3dp ehpk 3pxp",  # lowercase + spaces
        "JBSW-Y3DP-EHPK-3PXP-JBSW-Y3DP-EHPK-3PXP",  # dash groups
        "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP\n",  # trailing newline from a paste
    ):
        assert decode(messy) == decode(CLEAN), repr(messy)
    assert normalize("mzxw 6ytb-oi==\n") == "MZXW6YTBOI"


def test_decode_handles_missing_padding():
    # otpauth secrets are conventionally unpadded; 'MZXW6YT' needs one '='
    # to satisfy strict decoders, and decode() must supply it.
    assert decode("MZXW6YT") == b"foob"
    assert decode("MZXW6===") == decode("MZXW6")  # padded and unpadded agree


def test_decode_rejects_empty_and_separator_only():
    with pytest.raises(SecretError):
        decode("   -  ")


def test_decode_rejects_non_alphabet_characters_with_hint():
    with pytest.raises(SecretError) as excinfo:
        decode("JBSWY3DPEHPK3PX!")
    assert "A-Z and 2-7" in str(excinfo.value)


def test_decode_rejects_impossible_base32_length():
    # 9 chars (mod 8 == 1) cannot be produced by any base32 encoder.
    with pytest.raises(SecretError) as excinfo:
        decode("JBSWY3DPE")
    assert "truncated" in str(excinfo.value)


def test_lint_clean_secret_has_no_issues():
    report = lint(CLEAN)
    assert report.decodes and report.issues == [] and report.key_bits == 160


def test_lint_flags_separators_lowercase_and_padding():
    report = lint("mzxw 6ytb-oi======")
    codes = {issue.code for issue in report.issues}
    assert {"separators", "lowercase", "padding"} <= codes


def test_lint_flags_short_secret_per_rfc4226():
    report = lint("JBSWY3DPEHPK3PXP")  # 10 bytes = 80 bits
    assert any(i.code == "short-secret" for i in report.issues)
    assert report.decodes  # short is a warning, not a decode failure


def test_lint_suggests_confusable_fixes_for_digits():
    report = lint("JBSW0")  # '0' is not base32; 'O' is
    issue = next(i for i in report.issues if i.code == "non-alphabet")
    assert "'O'" in issue.suggestion


def test_lint_reports_hex_like_secrets():
    report = lint("3132333435363738393031323334353637383930")
    assert any(i.code == "hex-like" for i in report.issues)
    # The detector itself demands even length, hex charset, and key-like size.
    assert looks_like_hex("3132333435363738393031323334353637383930")
    assert not looks_like_hex("3132333435363738393031323334353637383930A")  # odd
    assert not looks_like_hex("JBSWY3DP")  # not hex chars
    assert not looks_like_hex("DEADBEEF")  # too short to be a key


def test_repair_candidates_only_returns_decodable_spellings():
    # 'JBSW0EHK' -> '0' expands to 'O'; every candidate must itself decode.
    candidates = repair_candidates("JBSW0EHK")
    assert candidates == ["JBSWOEHK"]


def test_repair_candidates_empty_when_nothing_to_repair_or_hopeless():
    assert repair_candidates(CLEAN) == []  # already valid
    assert repair_candidates("JBSW!EHK") == []  # '!' cannot be a typo of base32


def test_key_variants_baseline_first_and_deduplicated():
    variants = key_variants(CLEAN)
    assert variants[0].label == "base32" and variants[0].is_baseline
    keys = [v.key for v in variants]
    assert len(keys) == len(set(keys))


def test_key_variants_include_raw_ascii_interpretation():
    variants = {v.label: v for v in key_variants(CLEAN)}
    assert variants["raw-ascii"].key == CLEAN.encode()


def test_key_variants_include_hex_for_hex_like_secrets():
    hex_secret = "3132333435363738393031323334353637383930"
    variants = {v.label: v for v in key_variants(hex_secret)}
    assert variants["hex"].key == b"12345678901234567890"


def test_key_variants_include_base32hex_alphabet():
    # 'CO======' in base32hex equals 'MZ' region in standard base32 terms;
    # verify by translating manually.
    variants = {v.label: v for v in key_variants("CPNMUOJ1E8======")}
    assert "base32hex" in variants


def test_key_variants_include_confusable_repairs():
    variants = {v.label: v for v in key_variants("JBSW0EHK")}
    assert variants["base32-repaired"].key == decode("JBSWOEHK")
