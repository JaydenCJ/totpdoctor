"""totpdoctor — explain why a TOTP or HOTP code mismatches.

Public API: RFC 4226/6238 primitives (:func:`hotp`, :func:`totp`), lenient
base32 handling (:func:`decode_secret`, :func:`lint_secret`), otpauth URI
parsing (:func:`parse_uri`), and the diagnosis engine (:func:`diagnose`).
Everything is offline and standard-library only.
"""

from __future__ import annotations

__version__ = "0.1.0"

from .base32 import KeyVariant, SecretReport, decode as decode_secret, lint as lint_secret
from .diagnose import Baseline, Deviation, Diagnosis, Match, diagnose
from .errors import (
    CodeError,
    ParameterError,
    SecretError,
    TotpDoctorError,
    UriError,
)
from .explain import Explanation, explain_match
from .otp import hotp, seconds_remaining, time_step, totp
from .report import render_json, render_text, to_dict
from .uri import OtpUri, parse as parse_uri

__all__ = [
    "__version__",
    "Baseline",
    "CodeError",
    "Deviation",
    "Diagnosis",
    "Explanation",
    "KeyVariant",
    "Match",
    "OtpUri",
    "ParameterError",
    "SecretError",
    "SecretReport",
    "TotpDoctorError",
    "UriError",
    "decode_secret",
    "diagnose",
    "explain_match",
    "hotp",
    "lint_secret",
    "parse_uri",
    "render_json",
    "render_text",
    "seconds_remaining",
    "time_step",
    "to_dict",
    "totp",
]
