"""Turn deviations into human explanations with concrete fixes.

The diagnosis engine speaks in parameter tuples; operators debugging a 2FA
integration need sentences. Each deviation kind maps to a headline, a detail
paragraph tailored to the actual values, and a recommended fix.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

from .diagnose import Deviation, Diagnosis, Match
from .otp import format_utc


@dataclass(frozen=True)
class Explanation:
    """A ranked, human-readable account of one match."""

    headline: str
    details: List[str]
    fix: str


def _explain_skew(deviation: Deviation, match: Match) -> tuple:
    skew = match.skew_seconds
    direction = "behind" if skew < 0 else "ahead of"
    detail = (
        "The code is valid for %s - %s, i.e. the generating device's clock is "
        "about %d seconds %s the verifier's."
        % (
            format_utc(match.valid_from or 0),
            format_utc(match.valid_until or 0),
            abs(skew),
            direction,
        )
    )
    if abs(skew) <= match.period:
        fix = (
            "This is within one step. Accept a validation window of +/-1 step "
            "server-side (RFC 6238 section 5.2 recommends it), or just retry."
        )
    else:
        fix = (
            "Sync the generating device's clock via NTP; if skew persists, widen "
            "the server's accepted window or investigate the device's timezone/DST "
            "handling."
        )
    steps = skew // match.period
    headline = "clock skew: %+d s (%+d step%s)" % (
        skew,
        steps,
        "" if abs(steps) == 1 else "s",
    )
    return headline, detail, fix


def _explain_algorithm(deviation: Deviation, match: Match) -> tuple:
    detail = (
        "HMAC-%s over the same secret and time step reproduces the observed code; "
        "HMAC-%s does not. Client and server disagree on the hash algorithm — "
        "commonly because an otpauth URI said %s but one side ignored it."
        % (deviation.actual, deviation.expected, deviation.actual)
    )
    fix = (
        "Configure both sides to %s explicitly, or re-enroll with the default "
        "SHA1 for maximum client compatibility." % deviation.actual
    )
    return "algorithm mismatch: %s vs %s" % (deviation.actual, deviation.expected), detail, fix


def _explain_digits(deviation: Deviation, match: Match) -> tuple:
    detail = (
        "The generator is configured for %s-digit codes while the verifier "
        "expects %s digits. The observed code is internally consistent — only "
        "the length differs." % (deviation.actual, deviation.expected)
    )
    fix = (
        "Align the digits parameter on both sides; 6 is the interoperable "
        "default, 8 needs explicit support in every client."
    )
    return "digit-count mismatch: %s vs %s" % (deviation.actual, deviation.expected), detail, fix


def _explain_period(deviation: Deviation, match: Match) -> tuple:
    detail = (
        "The code matches when time steps are %s long instead of the expected "
        "%s. Both sides count time differently, so codes only coincide by luck."
        % (deviation.actual, deviation.expected)
    )
    fix = (
        "Set period=%s on the verifier or re-enroll the token; note some "
        "authenticator apps hard-code 30 s." % deviation.actual.rstrip("s")
    )
    return "period mismatch: %s vs %s" % (deviation.actual, deviation.expected), detail, fix


def _explain_secret(deviation: Deviation, match: Match) -> tuple:
    detail = "The key bytes differ from a straight base32 decode: %s." % match.key_note
    if match.key_label == "raw-ascii":
        fix = (
            "Fix the client to base32-decode the secret before HMAC; using the "
            "ASCII string as the key is the single most common integration bug."
        )
    elif match.key_label == "hex":
        fix = (
            "Export/import the secret consistently: either share base32 "
            "everywhere or hex everywhere, never mixed."
        )
    elif match.key_label == "base32-repaired":
        fix = (
            "Correct the stored secret to the repaired spelling shown above "
            "(look-alike characters were transcribed wrong)."
        )
    else:
        fix = (
            "Use the standard RFC 4648 base32 alphabet on both sides "
            "(A-Z, 2-7); base32hex is not interoperable."
        )
    return "secret decoding mismatch (%s)" % match.key_label, detail, fix


def _explain_mode(deviation: Deviation, match: Match) -> tuple:
    if deviation.actual == "hotp":
        detail = (
            "The observed value is an HOTP code at counter %d for this secret. "
            "The token was likely enrolled as counter-based (hotp) while the "
            "verifier runs time-based validation." % (match.counter or 0)
        )
    else:
        detail = (
            "The observed value is a TOTP code for the reference time. The "
            "token was likely enrolled as time-based while the verifier runs "
            "counter-based validation."
        )
    fix = (
        "Check the enrollment record's otpauth type (totp vs hotp) and make "
        "the verifier match it."
    )
    return "mode mismatch: %s vs %s" % (deviation.actual, deviation.expected), detail, fix


def _explain_counter(deviation: Deviation, match: Match) -> tuple:
    delta = (match.counter or 0)
    detail = (
        "The code verifies at counter %d, not the expected %s. Positive drift "
        "means the client generated codes that never reached the server."
        % (delta, deviation.expected.split()[-1])
    )
    fix = (
        "Resynchronize: accept the match and fast-forward the server counter "
        "to %d, per RFC 4226 section 7.4's look-ahead protocol." % (delta + 1)
    )
    return deviation.summary, detail, fix


def _explain_format(deviation: Deviation, match: Match) -> tuple:
    detail = (
        "The full code is %s; formatted as an integer it loses its leading "
        "zero(s) and becomes %s. Roughly 1 in 10 codes starts with a zero."
        % (match.code, str(int(match.code)))
    )
    fix = (
        "Treat OTP codes as strings end to end; when comparing, zero-pad the "
        "submitted code to the configured digit count."
    )
    return "leading zero(s) stripped by integer formatting", detail, fix


_EXPLAINERS = {
    "skew": _explain_skew,
    "algorithm": _explain_algorithm,
    "digits": _explain_digits,
    "period": _explain_period,
    "secret": _explain_secret,
    "mode": _explain_mode,
    "counter": _explain_counter,
    "format": _explain_format,
}


def explain_match(match: Match) -> Explanation:
    """Build the ranked explanation for one match."""
    if match.is_exact:
        return explain_exact(match)
    headlines: List[str] = []
    details: List[str] = []
    fixes: List[str] = []
    for deviation in match.deviations:
        explainer = _EXPLAINERS.get(deviation.kind)
        if explainer is None:  # pragma: no cover - future deviation kinds
            headlines.append(deviation.summary)
            continue
        headline, detail, fix = explainer(deviation, match)
        headlines.append(headline)
        details.append(detail)
        fixes.append(fix)
    return Explanation(
        headline=" + ".join(headlines),
        details=details,
        fix=" ".join(dict.fromkeys(fixes)),
    )


def explain_exact(match: Match) -> Explanation:
    """The code is correct — the mismatch must be outside code generation."""
    window = ""
    if match.valid_from is not None and match.valid_until is not None:
        window = " for %s - %s" % (
            format_utc(match.valid_from),
            format_utc(match.valid_until),
        )
    return Explanation(
        headline="the code is correct%s" % window,
        details=[
            "The observed code is exactly what the expected parameters produce "
            "at the reference time. If the server still rejects it, the failure "
            "is in validation policy, not code generation."
        ],
        fix=(
            "Check for: replay protection rejecting a reused code, a zero-width "
            "validation window, rate limiting, or the server reading a different "
            "secret than the one you diagnosed with."
        ),
    )


def no_match_advice(diagnosis: Diagnosis) -> List[str]:
    """Actionable next steps when nothing in the hypothesis space matched."""
    advice = [
        "No tested hypothesis reproduces the code (%d candidates tried)."
        % diagnosis.candidates_tested,
        "Most likely: the secret you diagnosed with is not the secret the "
        "generator holds, or the code was mistyped.",
        "Try: re-copy the secret from the enrollment record, widen the scan "
        "with --max-skew, or raise --hotp-scan if the token might be HOTP.",
    ]
    report = diagnosis.secret_report
    if report is not None and not report.decodes:
        advice.insert(
            1,
            "Note: the secret does not decode as base32 at all — run "
            "'totpdoctor secret' on it for repair suggestions.",
        )
    return advice
