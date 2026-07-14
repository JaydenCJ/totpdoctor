# Changelog

All notable changes to this project are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-07-12

### Added

- Diagnosis engine (`totpdoctor diagnose`): explains why an observed TOTP or
  HOTP code mismatches by searching single-fault hypotheses — clock skew
  (±40 steps by default), wrong algorithm (SHA1/SHA256/SHA512), wrong digit
  count, wrong period (15/30/60 s), mis-decoded secret (raw ASCII, hex,
  base32hex, look-alike-character repairs), HOTP/TOTP mode confusion, HOTP
  counter desync, and integer-stripped leading zeros.
- Ranked explanations: matches sorted by deviation count, deviation weight,
  and magnitude, each rendered with a headline, a detail paragraph, and a
  concrete fix; exact matches redirect to validation-policy causes.
- Search receipts in every report: candidates tested and the resulting
  chance-collision probability, with window discipline that narrows the time
  scan as candidates deviate further from the baseline.
- RFC 4226 / RFC 6238 primitives (`hotp`, `totp`) verified against the
  published appendix test vectors for SHA1, SHA256, and SHA512.
- Secret linting (`totpdoctor secret`): separators, case, padding, truncated
  lengths, hex-like secrets, RFC 4226 minimum-length check, and decodable
  repair candidates for look-alike characters (0→O, 1→I/L, 8→B, 9→G/Q).
- otpauth:// URI parsing and interoperability audit (`totpdoctor uri`):
  issuer/label disagreement, parameters popular authenticator apps silently
  ignore (non-SHA1 algorithms, non-6 digits, non-30 s periods), padded
  secrets, and undecodable secrets.
- Code generation with context (`totpdoctor gen`): previous/current/next
  codes with validity windows and seconds remaining; HOTP mode via
  `--counter`; `--at` accepts Unix seconds or ISO 8601.
- `--json` output for every subcommand and a stable exit-code contract
  (0 match, 1 no-match, 2 input error).
- Zero runtime dependencies; 92 deterministic offline tests and
  `scripts/smoke.sh` (prints `SMOKE OK`).

### Notes

- The repository ships no CI workflow; verification is local —
  `pip install -e '.[dev]' && pytest && bash scripts/smoke.sh`.

[0.1.0]: https://github.com/JaydenCJ/totpdoctor/releases/tag/v0.1.0
