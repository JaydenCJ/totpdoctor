"""Render a :class:`~totpdoctor.diagnose.Diagnosis` as text or JSON.

Text output is written for a human staring at a failing 2FA integration;
JSON output is stable, sorted, and designed to be piped into scripts. Both
views are pure functions of the diagnosis, so rendering is fully testable.
"""

from __future__ import annotations

import json
import textwrap
from typing import List

from .diagnose import Diagnosis, Match
from .explain import explain_match, no_match_advice
from .otp import format_utc

#: Report at most this many matches; later ones are chance-collision fodder.
MAX_REPORTED_MATCHES = 5


def _describe_baseline(diagnosis: Diagnosis) -> str:
    b = diagnosis.baseline
    if b.mode == "totp":
        return "TOTP %s, %d digits, %ds period" % (b.algorithm, b.digits, b.period)
    return "HOTP %s, %d digits, counter %d" % (b.algorithm, b.digits, b.counter)


def _verdict_line(diagnosis: Diagnosis) -> str:
    risk = diagnosis.collision_risk
    stats = "%d candidates tested, chance-collision risk %.2f%%" % (
        diagnosis.candidates_tested,
        risk * 100.0,
    )
    if diagnosis.verdict == "exact":
        return "verdict: EXACT — the code is valid as-is (%s)" % stats
    if diagnosis.verdict == "match":
        count = min(len(diagnosis.matches), MAX_REPORTED_MATCHES)
        return "verdict: MATCH — %d explanation%s found (%s)" % (
            count,
            "" if count == 1 else "s",
            stats,
        )
    return "verdict: NO MATCH (%s)" % stats


def render_text(diagnosis: Diagnosis) -> str:
    """Multi-line human report, ranked simplest explanation first."""
    lines: List[str] = [
        "observed %s | expected %s | at %s"
        % (diagnosis.observed, _describe_baseline(diagnosis), format_utc(diagnosis.at)),
        "",
        _verdict_line(diagnosis),
    ]
    if not diagnosis.matches:
        lines.append("")
        for tip in no_match_advice(diagnosis):
            lines.append("  - %s" % tip)
        return "\n".join(lines)
    for rank, match in enumerate(diagnosis.matches[:MAX_REPORTED_MATCHES], start=1):
        explanation = explain_match(match)
        lines.append("")
        lines.append("  %d. %s" % (rank, explanation.headline))
        for detail in explanation.details:
            lines.extend(_wrap(detail, "     "))
        lines.extend(_wrap("fix: %s" % explanation.fix, "     "))
    dropped = len(diagnosis.matches) - MAX_REPORTED_MATCHES
    if dropped > 0:
        lines.append("")
        lines.append(
            "  (%d further lower-ranked match%s suppressed)"
            % (dropped, "" if dropped == 1 else "es")
        )
    return "\n".join(lines)


def _match_dict(match: Match) -> dict:
    explanation = explain_match(match)
    payload = {
        "code": match.code,
        "mode": match.mode,
        "algorithm": match.algorithm,
        "digits": match.digits,
        "key_variant": match.key_label,
        "deviations": [
            {
                "kind": d.kind,
                "summary": d.summary,
                "expected": d.expected,
                "actual": d.actual,
            }
            for d in match.deviations
        ],
        "explanation": {
            "headline": explanation.headline,
            "details": explanation.details,
            "fix": explanation.fix,
        },
    }
    if match.mode == "totp":
        payload["period"] = match.period
        payload["step"] = match.step
        payload["skew_seconds"] = match.skew_seconds
        payload["valid_from"] = match.valid_from
        payload["valid_until"] = match.valid_until
    else:
        payload["counter"] = match.counter
    return payload


def to_dict(diagnosis: Diagnosis) -> dict:
    """Stable dict form of a diagnosis (the JSON contract)."""
    b = diagnosis.baseline
    payload = {
        "observed": diagnosis.observed,
        "at": diagnosis.at,
        "verdict": diagnosis.verdict,
        "candidates_tested": diagnosis.candidates_tested,
        "collision_risk": round(diagnosis.collision_risk, 6),
        "baseline": {
            "mode": b.mode,
            "algorithm": b.algorithm,
            "digits": b.digits,
            "period": b.period,
            "counter": b.counter,
        },
        "matches": [
            _match_dict(m) for m in diagnosis.matches[:MAX_REPORTED_MATCHES]
        ],
    }
    if diagnosis.verdict == "no-match":
        payload["advice"] = no_match_advice(diagnosis)
    report = diagnosis.secret_report
    if report is not None:
        payload["secret"] = {
            "decodes": report.decodes,
            "key_bits": report.key_bits,
            "issues": [i.code for i in report.issues],
        }
    return payload


def render_json(diagnosis: Diagnosis) -> str:
    """The dict contract serialized with sorted keys for clean diffs."""
    return json.dumps(to_dict(diagnosis), indent=2, sort_keys=True)


def _wrap(text: str, indent: str, width: int = 78) -> List[str]:
    """Wrap a paragraph with a uniform indent for the text report."""
    return textwrap.wrap(
        text, width=width, initial_indent=indent, subsequent_indent=indent
    )
