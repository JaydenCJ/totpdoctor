"""otpauth:// URI parsing and the interoperability audit.

The warnings are load-bearing: parameters that popular authenticator apps
silently ignore are a leading cause of "the code never matches" reports.
"""

from __future__ import annotations

import pytest

from totpdoctor.errors import UriError
from totpdoctor.uri import parse

FULL = (
    "otpauth://totp/Example:alice@example.test"
    "?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA1&digits=6&period=30"
)


def test_parse_full_totp_uri():
    parsed = parse(FULL)
    assert parsed.mode == "totp"
    assert parsed.secret == "JBSWY3DPEHPK3PXP"
    assert parsed.account == "alice@example.test"
    assert parsed.issuer == "Example"
    assert (parsed.algorithm, parsed.digits, parsed.period) == ("SHA1", 6, 30)


def test_parse_applies_rfc_defaults_when_params_absent():
    parsed = parse("otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP")
    assert (parsed.algorithm, parsed.digits, parsed.period) == ("SHA1", 6, 30)
    assert parsed.counter is None


def test_parse_decodes_percent_encoded_labels():
    parsed = parse("otpauth://totp/Big%20Corp%3Aalice?secret=JBSWY3DPEHPK3PXP")
    assert parsed.label_issuer == "Big Corp"
    assert parsed.account == "alice"


def test_parse_hotp_requires_and_reads_counter():
    with pytest.raises(UriError) as excinfo:
        parse("otpauth://hotp/alice?secret=JBSWY3DPEHPK3PXP")
    assert "counter" in str(excinfo.value)
    parsed = parse("otpauth://hotp/alice?secret=JBSWY3DPEHPK3PXP&counter=7")
    assert parsed.mode == "hotp" and parsed.counter == 7


def test_parse_rejects_malformed_uris():
    for bad in (
        "https://example.test/?secret=JBSWY3DPEHPK3PXP",  # wrong scheme
        "otpauth://steam/alice?secret=JBSWY3DPEHPK3PXP",  # unknown type
        "otpauth://totp/alice",  # no secret at all
        "otpauth://totp/alice?secret=",  # empty secret
        "otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP&digits=nine",  # non-int
        "otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP&digits=12",  # out of range
        "otpauth://totp/alice?secret=A&secret=B",  # duplicate param
        "otpauth://hotp/alice?secret=JBSWY3DPEHPK3PXP&counter=-1",  # negative
    ):
        with pytest.raises(UriError):
            parse(bad)


def test_audit_warns_on_issuer_label_disagreement():
    parsed = parse(
        "otpauth://totp/Alpha:alice?secret=JBSWY3DPEHPK3PXP&issuer=Beta"
    )
    assert any("disagrees" in w for w in parsed.warnings)


def test_audit_warns_when_no_issuer_anywhere():
    parsed = parse("otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP")
    assert any("no issuer" in w for w in parsed.warnings)


def test_audit_warns_on_non_sha1_algorithm():
    parsed = parse(
        "otpauth://totp/E:alice?secret=JBSWY3DPEHPK3PXP&issuer=E&algorithm=SHA256"
    )
    assert any("ignore this parameter" in w for w in parsed.warnings)


def test_audit_warns_on_non_default_digits_and_period():
    parsed = parse(
        "otpauth://totp/E:alice?secret=JBSWY3DPEHPK3PXP&issuer=E&digits=8&period=60"
    )
    assert any("digits=8" in w for w in parsed.warnings)
    assert any("period=60s" in w for w in parsed.warnings)


def test_audit_flags_padded_and_undecodable_secrets():
    parsed = parse("otpauth://totp/E:alice?secret=MZXW6===&issuer=E")
    assert any("padding" in w for w in parsed.warnings)
    parsed = parse("otpauth://totp/E:alice?secret=JBSW0!&issuer=E")
    assert any(w.startswith("secret:") for w in parsed.warnings)


def test_clean_uri_produces_no_warnings():
    parsed = parse(FULL)
    assert parsed.warnings == []
