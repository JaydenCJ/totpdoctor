"""Exception hierarchy for totpdoctor.

Every error raised by the public API derives from :class:`TotpDoctorError`,
so callers can catch one type at the CLI boundary and map it to exit code 2.
"""

from __future__ import annotations


class TotpDoctorError(Exception):
    """Base class for all totpdoctor errors."""


class SecretError(TotpDoctorError):
    """The shared secret cannot be decoded into key bytes."""


class CodeError(TotpDoctorError):
    """The observed code is not a plausible OTP (empty, non-digit, absurd length)."""


class ParameterError(TotpDoctorError):
    """An OTP parameter (digits, period, algorithm, counter) is out of range."""


class UriError(TotpDoctorError):
    """An otpauth:// URI is malformed or missing required fields."""
