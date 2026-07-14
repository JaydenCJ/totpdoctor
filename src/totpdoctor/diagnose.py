"""The mismatch diagnosis engine.

Given a secret, an observed code, and the parameters the verifier *believes*
are in effect, the engine enumerates every plausible single-fault deviation —
clock skew, wrong digits, wrong algorithm, wrong period, mis-decoded secret,
HOTP/TOTP mode confusion, counter desync, stripped leading zeros — computes
the code each deviation would have produced, and reports the ones that
reproduce the observed code, ranked so the simplest explanation comes first.

Search discipline: the more parameters a candidate changes, the narrower its
time window. That keeps the candidate count (and therefore the probability of
a chance 1-in-10^digits collision) small enough that a reported match is
evidence, not noise. The exact count tested and the resulting collision risk
are part of every :class:`Diagnosis`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Tuple

from . import base32
from .errors import CodeError, SecretError
from .otp import (
    ALGORITHMS,
    MAX_DIGITS,
    MIN_DIGITS,
    hotp,
    step_window,
    time_step,
    validate_period,
)

#: How far the zero-deviation candidate scans for pure clock skew (steps).
DEFAULT_MAX_SKEW_STEPS = 40
#: HOTP counters tried for the "actually enrolled as HOTP" hypothesis.
DEFAULT_HOTP_SCAN = 16
#: HOTP baseline: how far behind / ahead of the expected counter to search.
DEFAULT_LOOK_BEHIND = 3
DEFAULT_LOOK_AHEAD = 64

#: Periods worth testing besides the baseline (common real-world values).
PERIOD_AXIS = (30, 60, 15)

#: Ranking weight per deviation kind — lower is the more ordinary failure.
_KIND_WEIGHT = {
    "skew": 1,
    "counter": 1,
    "format": 2,
    "digits": 3,
    "algorithm": 3,
    "period": 4,
    "secret": 5,
    "mode": 6,
}


@dataclass(frozen=True)
class Deviation:
    """One way a candidate differs from the expected verification setup."""

    kind: str
    summary: str
    expected: str
    actual: str
    magnitude: int = 0


@dataclass(frozen=True)
class Baseline:
    """What the verifier believes should be true."""

    mode: str = "totp"  # "totp" or "hotp"
    algorithm: str = "SHA1"
    digits: int = 6
    period: int = 30
    counter: int = 0
    t0: int = 0


@dataclass
class Match:
    """A candidate parameter set that reproduces the observed code."""

    code: str
    mode: str
    algorithm: str
    digits: int
    period: int
    key_label: str
    key_note: str
    deviations: Tuple[Deviation, ...]
    step: Optional[int] = None
    counter: Optional[int] = None
    skew_seconds: int = 0
    valid_from: Optional[int] = None
    valid_until: Optional[int] = None

    @property
    def is_exact(self) -> bool:
        return not self.deviations

    def sort_key(self) -> Tuple[int, int, int, str]:
        weight = sum(_KIND_WEIGHT.get(d.kind, 9) for d in self.deviations)
        magnitude = sum(abs(d.magnitude) for d in self.deviations)
        return (len(self.deviations), weight, magnitude, self.key_label)


@dataclass
class Diagnosis:
    """The full result of one diagnosis run."""

    observed: str
    at: int
    baseline: Baseline
    matches: List[Match] = field(default_factory=list)
    candidates_tested: int = 0
    secret_report: Optional[base32.SecretReport] = None

    @property
    def verdict(self) -> str:
        if not self.matches:
            return "no-match"
        if self.matches[0].is_exact:
            return "exact"
        return "match"

    @property
    def collision_risk(self) -> float:
        """Probability that at least one tested candidate matched by chance."""
        space = 10 ** len(self.observed)
        return 1.0 - (1.0 - 1.0 / space) ** self.candidates_tested


def normalize_code(code: str) -> str:
    """Strip separators from an observed code and validate it is decimal."""
    cleaned = "".join(ch for ch in code if ch not in " \t-")
    if not cleaned:
        raise CodeError("observed code is empty")
    if not cleaned.isdigit():
        raise CodeError("observed code %r contains non-digit characters" % code)
    if not MIN_DIGITS <= len(cleaned) <= MAX_DIGITS:
        raise CodeError(
            "observed code has %d digits; OTP codes have %d-%d"
            % (len(cleaned), MIN_DIGITS, MAX_DIGITS)
        )
    return cleaned


class _Search:
    """Bounded candidate enumeration with de-duplication and counting."""

    def __init__(self, observed: str, baseline: Baseline, at: int):
        self.observed = observed
        self.baseline = baseline
        self.at = at
        self.tested = 0
        self.matches: List[Match] = []
        self._seen = set()

    def try_totp(
        self,
        variant: base32.KeyVariant,
        algorithm: str,
        digits: int,
        period: int,
        offset: int,
        extra: Tuple[Deviation, ...],
        compare_stripped: bool = False,
    ) -> None:
        step = time_step(self.at, period, self.baseline.t0) + offset
        if step < 0:
            return
        fingerprint = (variant.key, algorithm, digits, period, step, compare_stripped)
        if fingerprint in self._seen:
            return
        self._seen.add(fingerprint)
        self.tested += 1
        code = hotp(variant.key, step, digits=digits, algorithm=algorithm)
        produced = str(int(code)) if compare_stripped else code
        if produced != self.observed:
            return
        deviations = list(extra)
        if offset != 0:
            skew = offset * period
            deviations.append(
                Deviation(
                    kind="skew",
                    summary="clock skew of %+d s (%+d step%s of %ds)"
                    % (skew, offset, "" if abs(offset) == 1 else "s", period),
                    expected="step at reference time",
                    actual="%+d steps" % offset,
                    magnitude=abs(skew),
                )
            )
        start, end = step_window(step, period, self.baseline.t0)
        self.matches.append(
            Match(
                code=code,
                mode="totp",
                algorithm=algorithm,
                digits=digits,
                period=period,
                key_label=variant.label,
                key_note=variant.note,
                deviations=tuple(deviations),
                step=step,
                skew_seconds=offset * period,
                valid_from=start,
                valid_until=end,
            )
        )

    def try_hotp(
        self,
        variant: base32.KeyVariant,
        algorithm: str,
        digits: int,
        counter: int,
        extra: Tuple[Deviation, ...],
    ) -> None:
        if counter < 0:
            return
        fingerprint = (variant.key, algorithm, digits, "hotp", counter)
        if fingerprint in self._seen:
            return
        self._seen.add(fingerprint)
        self.tested += 1
        code = hotp(variant.key, counter, digits=digits, algorithm=algorithm)
        if code != self.observed:
            return
        deviations = list(extra)
        delta = counter - self.baseline.counter
        if self.baseline.mode == "hotp" and delta != 0:
            deviations.append(
                Deviation(
                    kind="counter",
                    summary="counter desync of %+d (matched at counter %d, expected %d)"
                    % (delta, counter, self.baseline.counter),
                    expected="counter %d" % self.baseline.counter,
                    actual="counter %d" % counter,
                    magnitude=abs(delta),
                )
            )
        self.matches.append(
            Match(
                code=code,
                mode="hotp",
                algorithm=algorithm,
                digits=digits,
                period=self.baseline.period,
                key_label=variant.label,
                key_note=variant.note,
                deviations=tuple(deviations),
                counter=counter,
            )
        )


def _param_deviations(
    variant: base32.KeyVariant,
    algorithm: str,
    digits: int,
    period: int,
    baseline: Baseline,
    observed_len: int,
) -> Tuple[Deviation, ...]:
    deviations: List[Deviation] = []
    if not variant.is_baseline:
        deviations.append(_secret_deviation(variant))
    if algorithm != baseline.algorithm:
        deviations.append(
            Deviation(
                kind="algorithm",
                summary="algorithm mismatch: code was generated with %s, verifier "
                "expects %s" % (algorithm, baseline.algorithm),
                expected=baseline.algorithm,
                actual=algorithm,
            )
        )
    if digits != baseline.digits:
        deviations.append(
            Deviation(
                kind="digits",
                summary="digit-count mismatch: the %d-digit observed code was "
                "generated with digits=%d, verifier expects %d"
                % (observed_len, digits, baseline.digits),
                expected=str(baseline.digits),
                actual=str(digits),
            )
        )
    if period != baseline.period:
        deviations.append(
            Deviation(
                kind="period",
                summary="period mismatch: code was generated with a %ds step, "
                "verifier expects %ds" % (period, baseline.period),
                expected="%ds" % baseline.period,
                actual="%ds" % period,
            )
        )
    return tuple(deviations)


def _secret_deviation(variant: base32.KeyVariant) -> Deviation:
    return Deviation(
        kind="secret",
        summary="secret decoded differently: %s" % variant.note,
        expected="base32",
        actual=variant.label,
    )


def _offsets_for(deviation_count: int, max_skew_steps: int) -> Iterable[int]:
    """Window discipline: more deviations, narrower time window."""
    if deviation_count == 0:
        return range(-max_skew_steps, max_skew_steps + 1)
    if deviation_count == 1:
        return range(-2, 3)
    if deviation_count == 2:
        return range(-1, 2)
    return ()


def _axis(first, rest) -> List:
    """Baseline-first axis with de-duplication, preserving order."""
    values = [first]
    for value in rest:
        if value not in values:
            values.append(value)
    return values


def diagnose(
    secret: str,
    observed: str,
    at: int,
    baseline: Optional[Baseline] = None,
    max_skew_steps: int = DEFAULT_MAX_SKEW_STEPS,
    hotp_scan: int = DEFAULT_HOTP_SCAN,
    look_behind: int = DEFAULT_LOOK_BEHIND,
    look_ahead: int = DEFAULT_LOOK_AHEAD,
) -> Diagnosis:
    """Explain why ``observed`` does not verify under ``baseline`` at ``at``.

    Returns a :class:`Diagnosis` whose ``matches`` are ranked simplest-first.
    An empty ``matches`` list means no tested hypothesis reproduces the code.
    """
    baseline = baseline or Baseline()
    validate_period(baseline.period)
    observed = normalize_code(observed)
    variants = base32.key_variants(secret)
    if not variants:
        raise SecretError(
            "secret cannot be interpreted as base32, hex, or raw bytes"
        )
    report = base32.lint(secret)
    search = _Search(observed, baseline, at)

    algorithms = _axis(baseline.algorithm, ALGORITHMS)
    # Code equality requires equal length, so the only digits value that can
    # match the observed string is its own length.
    digits = len(observed)

    if baseline.mode == "totp":
        periods = _axis(baseline.period, PERIOD_AXIS)
        for variant in variants:
            for algorithm in algorithms:
                for period in periods:
                    extra = _param_deviations(
                        variant, algorithm, digits, period, baseline, len(observed)
                    )
                    for offset in _offsets_for(len(extra), max_skew_steps):
                        search.try_totp(variant, algorithm, digits, period, offset, extra)
        anchor = _anchor_variant(variants)
        _scan_stripped_zero(search, anchor, baseline, observed)
        _scan_hotp_enrollment(search, anchor, baseline, observed, hotp_scan)
    else:
        for variant in variants:
            for algorithm in algorithms:
                extra = _param_deviations(
                    variant, algorithm, digits, baseline.period, baseline, len(observed)
                )
                if len(extra) == 0:
                    deltas: Iterable[int] = range(-look_behind, look_ahead + 1)
                elif len(extra) == 1:
                    deltas = range(-1, 3)
                else:
                    deltas = (0,)
                for delta in deltas:
                    search.try_hotp(
                        variant, algorithm, digits, baseline.counter + delta, extra
                    )
        _scan_totp_enrollment(search, _anchor_variant(variants), baseline, observed)

    search.matches.sort(key=Match.sort_key)
    return Diagnosis(
        observed=observed,
        at=at,
        baseline=baseline,
        matches=search.matches,
        candidates_tested=search.tested,
        secret_report=report,
    )


def _anchor_variant(variants: List[base32.KeyVariant]) -> base32.KeyVariant:
    """The variant the auxiliary hypothesis scans anchor on.

    Prefer the true base32 decode; when the secret does not decode at all,
    fall back to the first interpretation so the scans still run.
    """
    for variant in variants:
        if variant.is_baseline:
            return variant
    return variants[0]


def _scan_stripped_zero(
    search: _Search,
    variant: base32.KeyVariant,
    baseline: Baseline,
    observed: str,
) -> None:
    """Hypothesis: the code was rendered as an integer, losing leading zeros."""
    if len(observed) >= baseline.digits:
        return
    deviations: List[Deviation] = [] if variant.is_baseline else [_secret_deviation(variant)]
    deviations.append(
        Deviation(
            kind="format",
            summary="leading zero(s) stripped: a %d-digit code was formatted as an "
            "integer and lost %d leading zero(s)"
            % (baseline.digits, baseline.digits - len(observed)),
            expected="%d digits, zero-padded" % baseline.digits,
            actual="%d digits" % len(observed),
        )
    )
    for offset in range(-2, 3):  # one deviation -> narrow window, like _offsets_for(1)
        search.try_totp(
            variant,
            baseline.algorithm,
            baseline.digits,
            baseline.period,
            offset,
            tuple(deviations),
            compare_stripped=True,
        )


def _scan_hotp_enrollment(
    search: _Search,
    variant: base32.KeyVariant,
    baseline: Baseline,
    observed: str,
    hotp_scan: int,
) -> None:
    """Hypothesis: the token is enrolled as HOTP although TOTP was expected."""
    prefix = () if variant.is_baseline else (_secret_deviation(variant),)
    for counter in range(hotp_scan + 1):
        deviation = Deviation(
            kind="mode",
            summary="mode mismatch: the code is an HOTP value at counter %d, "
            "but the verifier expects TOTP" % counter,
            expected="totp",
            actual="hotp",
            magnitude=counter,
        )
        search.try_hotp(
            variant, baseline.algorithm, len(observed), counter, prefix + (deviation,)
        )


def _scan_totp_enrollment(
    search: _Search,
    variant: base32.KeyVariant,
    baseline: Baseline,
    observed: str,
) -> None:
    """Hypothesis: the token is enrolled as TOTP although HOTP was expected."""
    prefix = () if variant.is_baseline else (_secret_deviation(variant),)
    for offset in (-1, 0, 1):
        deviation = Deviation(
            kind="mode",
            summary="mode mismatch: the code is a TOTP value at the reference "
            "time, but the verifier expects HOTP",
            expected="hotp",
            actual="totp",
            magnitude=abs(offset),
        )
        search.try_totp(
            variant,
            baseline.algorithm,
            len(observed),
            baseline.period,
            offset,
            prefix + (deviation,),
        )
