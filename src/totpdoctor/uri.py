"""otpauth:// URI parsing and interoperability audit.

The `Key Uri Format <https://github.com/google/google-authenticator/wiki/Key-Uri-Format>`_
is the de-facto enrollment standard, but real authenticator apps honor only a
subset of it. Parsing here is strict about structure and loud about the
parameters that popular clients silently ignore — which is itself a top cause
of "the code never matches" tickets.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import parse_qsl, unquote, urlparse

from . import base32
from .errors import ParameterError, UriError
from .otp import normalize_algorithm, validate_digits, validate_period


@dataclass
class OtpUri:
    """A parsed otpauth:// URI plus interoperability warnings."""

    mode: str  # "totp" or "hotp"
    secret: str
    label: str = ""
    account: str = ""
    issuer: str = ""
    label_issuer: str = ""
    algorithm: str = "SHA1"
    digits: int = 6
    period: int = 30
    counter: Optional[int] = None
    warnings: List[str] = field(default_factory=list)


def _split_label(raw_path: str) -> tuple:
    label = unquote(raw_path.lstrip("/"))
    if ":" in label:
        issuer, account = label.split(":", 1)
        return label, issuer.strip(), account.strip()
    return label, "", label.strip()


def parse(uri: str) -> OtpUri:
    """Parse an otpauth:// URI, validating structure and flagging pitfalls."""
    parsed = urlparse(uri.strip())
    if parsed.scheme != "otpauth":
        raise UriError("expected an otpauth:// URI, got scheme %r" % parsed.scheme)
    mode = parsed.netloc.lower()
    if mode not in ("totp", "hotp"):
        raise UriError("URI type must be 'totp' or 'hotp', got %r" % parsed.netloc)

    params = {}
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        lowered = key.lower()
        if lowered in params:
            raise UriError("duplicate parameter %r in URI" % key)
        params[lowered] = value

    if "secret" not in params or not params["secret"]:
        raise UriError("URI is missing the required 'secret' parameter")

    label, label_issuer, account = _split_label(parsed.path)
    result = OtpUri(
        mode=mode,
        secret=params["secret"],
        label=label,
        account=account,
        issuer=params.get("issuer", "").strip(),
        label_issuer=label_issuer,
    )

    try:
        if "algorithm" in params:
            result.algorithm = normalize_algorithm(params["algorithm"])
        if "digits" in params:
            result.digits = validate_digits(int(params["digits"]))
        if "period" in params:
            result.period = validate_period(int(params["period"]))
        if "counter" in params:
            result.counter = int(params["counter"])
            if result.counter < 0:
                raise UriError("counter must be non-negative")
    except ValueError:
        raise UriError("digits, period, and counter must be integers") from None
    except ParameterError as exc:
        raise UriError(str(exc)) from None

    if mode == "hotp" and result.counter is None:
        raise UriError("hotp URIs require a 'counter' parameter")

    _audit(result, params)
    return result


def _audit(result: OtpUri, params: dict) -> None:
    """Attach interoperability warnings that explain future mismatches."""
    if result.issuer and result.label_issuer and result.issuer != result.label_issuer:
        result.warnings.append(
            "issuer parameter (%r) disagrees with the label prefix (%r); "
            "apps display one or the other inconsistently"
            % (result.issuer, result.label_issuer)
        )
    if not result.issuer and not result.label_issuer:
        result.warnings.append(
            "no issuer set; the entry will be hard to identify in authenticator apps"
        )
    if result.algorithm != "SHA1":
        result.warnings.append(
            "algorithm=%s: several popular authenticator apps ignore this parameter "
            "and generate SHA1 codes anyway — a classic silent-mismatch source"
            % result.algorithm
        )
    if result.digits != 6:
        result.warnings.append(
            "digits=%d: some authenticator apps only render 6 digits and will "
            "produce codes the server rejects" % result.digits
        )
    if result.mode == "totp" and result.period != 30:
        result.warnings.append(
            "period=%ds: some authenticator apps hard-code 30s and will drift "
            "immediately" % result.period
        )
    if params.get("secret", "").endswith("="):
        result.warnings.append(
            "secret carries '=' padding; some enrollment scanners reject padded secrets"
        )
    secret_report = base32.lint(result.secret)
    if not secret_report.decodes:
        for issue in secret_report.issues:
            if issue.code in ("non-alphabet", "truncated", "empty", "undecodable"):
                result.warnings.append("secret: %s" % issue.message)
