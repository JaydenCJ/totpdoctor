"""Rendering: the text report a human reads and the JSON contract scripts use.

Rendering is a pure function of a Diagnosis, so these tests build real
diagnoses (fixed secret, fixed time) and assert on the output's substance.
"""

from __future__ import annotations

import json

from totpdoctor import decode_secret, diagnose, totp
from totpdoctor.diagnose import Baseline
from totpdoctor.explain import explain_match, no_match_advice
from totpdoctor.report import MAX_REPORTED_MATCHES, render_json, render_text, to_dict

from conftest import FIXED_AT, RFC_SECRET_B32

KEY = decode_secret(RFC_SECRET_B32)


def _skewed():
    return diagnose(RFC_SECRET_B32, totp(KEY, FIXED_AT - 60), FIXED_AT)


def test_text_report_names_the_fault_and_the_fix():
    text = render_text(_skewed())
    assert "verdict: MATCH" in text
    assert "clock skew: -60 s" in text
    assert "fix:" in text


def test_text_report_shows_search_receipts():
    # The candidate count and collision risk are what make a match credible.
    text = render_text(_skewed())
    assert "candidates tested" in text
    assert "chance-collision risk" in text


def test_text_report_exact_verdict():
    text = render_text(diagnose(RFC_SECRET_B32, totp(KEY, FIXED_AT), FIXED_AT))
    assert "verdict: EXACT" in text
    assert "the code is correct" in text
    assert "replay protection" in text  # points at validation policy, not codegen


def test_text_report_no_match_prints_advice():
    text = render_text(diagnose(RFC_SECRET_B32, "000001", FIXED_AT))
    assert "verdict: NO MATCH" in text
    assert "mistyped" in text


def test_json_report_round_trips_and_is_sorted():
    rendered = render_json(_skewed())
    payload = json.loads(rendered)
    assert payload["verdict"] == "match"
    assert payload["matches"][0]["skew_seconds"] == -60
    assert list(payload.keys()) == sorted(payload.keys())


def test_json_baseline_block_reflects_inputs():
    baseline = Baseline(mode="hotp", algorithm="SHA256", digits=8, counter=5)
    result = diagnose(RFC_SECRET_B32, "12345678", FIXED_AT, baseline=baseline)
    payload = to_dict(result)
    assert payload["baseline"] == {
        "mode": "hotp",
        "algorithm": "SHA256",
        "digits": 8,
        "period": 30,
        "counter": 5,
    }


def test_json_includes_secret_lint_summary():
    payload = to_dict(_skewed())
    assert payload["secret"]["decodes"] is True
    assert payload["secret"]["key_bits"] == 160


def test_json_no_match_carries_advice():
    payload = to_dict(diagnose(RFC_SECRET_B32, "000001", FIXED_AT))
    assert payload["verdict"] == "no-match"
    assert any("candidates" in line for line in payload["advice"])


def test_report_caps_reported_matches():
    payload = to_dict(_skewed())
    assert len(payload["matches"]) <= MAX_REPORTED_MATCHES


def test_explain_match_produces_fix_for_every_kind():
    # Manufacture one diagnosis per deviation kind and require a non-empty fix.
    cases = [
        totp(KEY, FIXED_AT - 60),  # skew
        totp(KEY, FIXED_AT, algorithm="SHA256"),  # algorithm
        totp(KEY, FIXED_AT, digits=8),  # digits
        totp(KEY, FIXED_AT, period=60),  # period
        totp(RFC_SECRET_B32.encode(), FIXED_AT),  # secret (raw-ascii)
    ]
    for code in cases:
        result = diagnose(RFC_SECRET_B32, code, FIXED_AT)
        explanation = explain_match(result.matches[0])
        assert explanation.headline and explanation.fix


def test_no_match_advice_mentions_undecodable_secret():
    result = diagnose("JBSW0!AA", "999999", FIXED_AT)
    if not result.matches:  # raw-ascii interpretation almost surely misses
        advice = " ".join(no_match_advice(result))
        assert "does not decode as base32" in advice
