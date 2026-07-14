# How diagnosis works

`totpdoctor diagnose` answers one question: *which single deviation from the
expected verification setup would have produced the code you observed?* This
document specifies the hypothesis space, the search bounds, the ranking, and
the false-positive math behind the "chance-collision risk" figure printed in
every report.

## The hypothesis space

The engine starts from a **baseline** — what the verifier believes: mode
(`totp`/`hotp`), algorithm (`SHA1` by default), digits (6), period (30 s),
and, for HOTP, the expected counter. It then enumerates candidates along
these axes:

| Axis | Values tried | Deviation kind |
|---|---|---|
| Time step (TOTP) | ±`--max-skew` steps (default ±40 = ±20 min at 30 s) | `skew` |
| Counter (HOTP) | −3 … +`--look-ahead` (default 64) around the baseline | `counter` |
| Algorithm | SHA1, SHA256, SHA512 | `algorithm` |
| Digits | the observed code's own length | `digits` |
| Period | 30 s, 60 s, 15 s | `period` |
| Key bytes | base32, raw ASCII string, hex, base32hex, confusable repairs | `secret` |
| Mode | HOTP counters 0…`--hotp-scan` when TOTP expected, and vice versa | `mode` |
| Formatting | code compared after integer truncation (lost leading zeros) | `format` |

Two axes deserve a note:

- **Digits.** String equality already requires equal length, so the only
  digit count that can match a 8-character observation is 8. The engine
  therefore derives the digits axis from the observed code instead of testing
  6/7/8 blindly — except for the `format` hypothesis, which checks whether a
  full-length code with its leading zeros stripped equals the observation.
- **Key bytes.** `key_variants()` enumerates what a *broken* client might
  have HMAC'd: the base32-decoded key (correct), the secret string's raw
  ASCII bytes (the classic bug), a hex decode when the secret looks like hex,
  an RFC 4648 §7 base32hex decode, and every decodable repair of look-alike
  characters (`0→O`, `1→I/L`, `8→B`, `9→G/Q`, capped at 16 combinations).
  Variants are de-duplicated by key bytes before searching.

## Window discipline

Testing every combination of every axis over a wide time window would make
chance collisions likely — a 6-digit code space has only 10⁶ values. The
engine therefore narrows the time window as candidates get more exotic:

| Parameter deviations in the candidate | Time window scanned |
|---|---|
| 0 (everything matches the baseline) | ±`--max-skew` steps |
| 1 (e.g. wrong algorithm only) | ±2 steps |
| 2 (e.g. wrong algorithm *and* wrong period) | ±1 step |
| 3 or more | not tested |

A default TOTP run tests ≈150 candidates. Every candidate is fingerprinted
(key bytes, algorithm, digits, period, step/counter) and never tested twice.

## Ranking

Matches are sorted by a three-part key, simplest explanation first:

1. **Number of deviations** — a pure clock-skew match always outranks a
   "wrong algorithm plus one step of skew" coincidence.
2. **Total deviation weight** — ordinary failures rank above exotic ones:
   `skew`/`counter` (1) < `format` (2) < `digits`/`algorithm` (3) <
   `period` (4) < `secret` (5) < `mode` (6).
3. **Magnitude** — smaller skews and counter distances first.

An empty deviation list means the code is simply *correct*; the verdict
becomes `exact` and the report redirects you to validation policy (replay
protection, a zero-width acceptance window, rate limiting).

## False-positive math

Every tested candidate is an independent 1-in-10^digits lottery ticket. With
`N` candidates and a `d`-digit code, the probability that *at least one*
matches by chance is:

```text
P(collision) = 1 − (1 − 10⁻ᵈ)ᴺ
```

For the default search (N ≈ 150, d = 6) that is ≈ 0.015 % — low enough that
a reported match is evidence. The report prints both `N` and this probability
so you can judge for yourself; widening `--max-skew` to hours raises it, and
the top-5 cap on reported matches keeps lucky stragglers out of sight.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | A hypothesis (or an exact match) explains the observed code |
| 1 | No tested hypothesis reproduces the code |
| 2 | Input error: undecodable secret, malformed URI, implausible code |
