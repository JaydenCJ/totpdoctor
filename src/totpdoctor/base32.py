"""Base32 secret decoding, linting, and mis-encoding candidates.

Provisioning secrets are copied by humans: they arrive lower-cased, chunked
with spaces or dashes, stripped of padding, OCR-mangled (``0`` for ``O``), or
pasted as hex because the backend exported raw key bytes. This module decodes
leniently, explains every repair it performs, and — for the diagnosis engine —
enumerates the key-byte interpretations a *broken* client might have used.
"""

from __future__ import annotations

import base64
import binascii
import itertools
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .errors import SecretError

#: RFC 4648 §6 base32 alphabet.
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

#: RFC 4648 §7 "extended hex" base32 alphabet, used by some broken exporters.
HEX_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUV"

#: Characters that are invalid in base32 but visually mistaken for valid ones.
#: Ordered by likelihood; the first entry is the primary suggestion.
CONFUSABLES: Dict[str, Tuple[str, ...]] = {
    "0": ("O",),
    "1": ("I", "L"),
    "8": ("B",),
    "9": ("G", "Q"),
}

#: Base32 string lengths (mod 8) that can never occur, even without padding.
_IMPOSSIBLE_TAILS = frozenset({1, 3, 6})

#: Cap on generated confusable-repair combinations, to keep search bounded.
_MAX_REPAIRS = 16

#: RFC 4226 R6: shared secrets SHALL be at least 128 bits (16 bytes).
MIN_SECRET_BYTES = 16


@dataclass(frozen=True)
class Issue:
    """One observation about the secret, with an actionable suggestion."""

    code: str
    message: str
    suggestion: str = ""


@dataclass(frozen=True)
class KeyVariant:
    """One plausible interpretation of the secret as raw key bytes."""

    label: str
    note: str
    key: bytes
    is_baseline: bool = False


@dataclass
class SecretReport:
    """Everything ``totpdoctor secret`` knows about one secret string."""

    original: str
    normalized: str
    issues: List[Issue] = field(default_factory=list)
    key: Optional[bytes] = None
    repairs: List[str] = field(default_factory=list)

    @property
    def decodes(self) -> bool:
        return self.key is not None

    @property
    def key_bits(self) -> int:
        return len(self.key) * 8 if self.key is not None else 0


def normalize(secret: str) -> str:
    """Upper-case and strip separators/padding without judging validity."""
    cleaned = "".join(ch for ch in secret if ch not in " \t\r\n-_")
    return cleaned.upper().rstrip("=")


def _b32decode_padded(normalized: str) -> bytes:
    pad = (-len(normalized)) % 8
    try:
        return base64.b32decode(normalized + "=" * pad)
    except (binascii.Error, ValueError) as exc:
        raise SecretError("invalid base32 secret: %s" % exc) from None


def decode(secret: str) -> bytes:
    """Decode a base32 secret leniently (case, separators, missing padding).

    Raises :class:`SecretError` with a human explanation when the string can
    not be base32 at all.
    """
    normalized = normalize(secret)
    if not normalized:
        raise SecretError("secret is empty after removing separators")
    bad = sorted({ch for ch in normalized if ch not in ALPHABET})
    if bad:
        raise SecretError(
            "secret contains non-base32 characters: %s "
            "(base32 uses A-Z and 2-7 only)" % ", ".join(repr(ch) for ch in bad)
        )
    if len(normalized) % 8 in _IMPOSSIBLE_TAILS:
        raise SecretError(
            "secret length %d is impossible for base32 "
            "(likely truncated during copy/paste)" % len(normalized)
        )
    return _b32decode_padded(normalized)


def looks_like_hex(normalized: str) -> bool:
    """True when the normalized secret is plausibly a hex-encoded key."""
    if len(normalized) < 16 or len(normalized) % 2 != 0:
        return False
    return all(ch in "0123456789ABCDEF" for ch in normalized)


def repair_candidates(normalized: str) -> List[str]:
    """Enumerate confusable-character repairs that decode as base32.

    Each invalid-but-confusable character position expands to its likely
    intended letters; the cartesian product is capped at ``_MAX_REPAIRS``.
    """
    options: List[Tuple[str, ...]] = []
    has_confusable = False
    for ch in normalized:
        if ch in ALPHABET:
            options.append((ch,))
        elif ch in CONFUSABLES:
            has_confusable = True
            options.append(CONFUSABLES[ch])
        else:
            return []  # an unrepairable character makes all combinations moot
    if not has_confusable:
        return []  # nothing to repair
    candidates: List[str] = []
    for combo in itertools.islice(itertools.product(*options), _MAX_REPAIRS):
        candidate = "".join(combo)
        try:
            decode(candidate)
        except SecretError:
            continue
        candidates.append(candidate)
    return candidates


def lint(secret: str) -> SecretReport:
    """Inspect a secret and report every deviation from a clean base32 key."""
    report = SecretReport(original=secret, normalized=normalize(secret))
    stripped = secret.strip()
    if any(ch in stripped for ch in " \t-_"):
        report.issues.append(
            Issue(
                code="separators",
                message="secret contains spaces or dashes (common when pasted in groups)",
                suggestion="totpdoctor removed them; store the secret without separators",
            )
        )
    if any(ch.islower() for ch in stripped):
        report.issues.append(
            Issue(
                code="lowercase",
                message="secret contains lowercase letters; the RFC 4648 alphabet is uppercase",
                suggestion="most decoders fold case, but strict ones reject it — store uppercase",
            )
        )
    if stripped.rstrip().endswith("="):
        report.issues.append(
            Issue(
                code="padding",
                message="secret carries '=' padding; otpauth secrets are conventionally unpadded",
                suggestion="strip the padding — several enrollment scanners reject padded secrets",
            )
        )
    normalized = report.normalized
    if not normalized:
        report.issues.append(Issue(code="empty", message="secret is empty"))
        return report
    bad = sorted({ch for ch in normalized if ch not in ALPHABET})
    for ch in bad:
        hint = CONFUSABLES.get(ch)
        report.issues.append(
            Issue(
                code="non-alphabet",
                message="character %r is not in the base32 alphabet (A-Z, 2-7)" % ch,
                suggestion=(
                    "did you mean %s?" % " or ".join(repr(c) for c in hint)
                    if hint
                    else "remove or fix this character"
                ),
            )
        )
    if looks_like_hex(normalized) and bad:
        report.issues.append(
            Issue(
                code="hex-like",
                message="secret looks like a hex-encoded key, not base32",
                suggestion="if the backend exported hex, decode it as hex (totpdoctor "
                "diagnose tries this automatically)",
            )
        )
    if len(normalized) % 8 in _IMPOSSIBLE_TAILS:
        report.issues.append(
            Issue(
                code="truncated",
                message="length %d is impossible for base32 data" % len(normalized),
                suggestion="the secret was likely cut short during copy/paste — re-copy it",
            )
        )
    if bad:
        report.repairs = repair_candidates(normalized)
        return report
    try:
        report.key = decode(normalized)
    except SecretError as exc:
        report.issues.append(Issue(code="undecodable", message=str(exc)))
        return report
    if len(report.key) < MIN_SECRET_BYTES:
        report.issues.append(
            Issue(
                code="short-secret",
                message="decoded key is %d bytes (%d bits); RFC 4226 requires at least "
                "128 bits" % (len(report.key), report.key_bits),
                suggestion="fine for debugging, but ask the issuer for a longer secret",
            )
        )
    return report


def key_variants(secret: str) -> List[KeyVariant]:
    """Enumerate key-byte interpretations a mis-implemented client may use.

    The first successfully decoded variant is the baseline (correct base32).
    All variants are de-duplicated by key bytes so the diagnosis engine never
    tests the same HMAC key twice under two labels.
    """
    variants: List[KeyVariant] = []
    normalized = normalize(secret)
    try:
        variants.append(
            KeyVariant(
                label="base32",
                note="secret base32-decoded as specified",
                key=decode(secret),
                is_baseline=True,
            )
        )
    except SecretError:
        pass
    stripped = secret.strip()
    if stripped:
        variants.append(
            KeyVariant(
                label="raw-ascii",
                note="secret used verbatim as ASCII bytes — the client never "
                "base32-decoded it",
                key=stripped.encode("utf-8", errors="replace"),
            )
        )
    if looks_like_hex(normalized):
        variants.append(
            KeyVariant(
                label="hex",
                note="secret hex-decoded — the backend exported raw key bytes as hex",
                key=bytes.fromhex(normalized),
            )
        )
    if normalized and all(ch in HEX_ALPHABET for ch in normalized):
        translated = normalized.translate(str.maketrans(HEX_ALPHABET, ALPHABET))
        try:
            variants.append(
                KeyVariant(
                    label="base32hex",
                    note="secret decoded with the RFC 4648 §7 base32hex alphabet "
                    "instead of the standard one",
                    key=_b32decode_padded(translated),
                )
            )
        except SecretError:
            pass
    for repaired in repair_candidates(normalized):
        variants.append(
            KeyVariant(
                label="base32-repaired",
                note="secret decodes after fixing look-alike characters: %s" % repaired,
                key=decode(repaired),
            )
        )
    unique: List[KeyVariant] = []
    seen = set()
    for variant in variants:
        if variant.key in seen:
            continue
        seen.add(variant.key)
        unique.append(variant)
    return unique
