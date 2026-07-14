"""Command-line interface: gen, diagnose, secret, uri.

Exit codes are part of the contract so the tool can drive scripts:

* 0 — success (for ``diagnose``: an explanation was found)
* 1 — ``diagnose`` found no hypothesis that reproduces the code
* 2 — usage or input error (bad secret, bad URI, bad parameters)
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from typing import List, Optional

from . import __version__, base32, uri as urimod
from .diagnose import (
    Baseline,
    DEFAULT_HOTP_SCAN,
    DEFAULT_LOOK_AHEAD,
    DEFAULT_MAX_SKEW_STEPS,
    diagnose,
)
from .errors import TotpDoctorError
from .otp import (
    ALGORITHMS,
    format_utc,
    hotp,
    seconds_remaining,
    time_step,
    totp,
    validate_digits,
    validate_period,
)
from .report import render_json, render_text

PROG = "totpdoctor"


def parse_when(value: str) -> int:
    """Accept a Unix timestamp or an ISO 8601 instant (Z or offset)."""
    text = value.strip()
    if text.lstrip("-").isdigit():
        return int(text)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        raise TotpDoctorError(
            "cannot parse time %r (use Unix seconds or ISO 8601, e.g. "
            "2026-07-12T12:00:00Z)" % value
        ) from None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return int(parsed.timestamp())


def _add_otp_options(parser: argparse.ArgumentParser) -> None:
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--secret", help="base32 shared secret")
    source.add_argument("--uri", help="otpauth:// URI carrying secret and parameters")
    parser.add_argument(
        "--algorithm",
        choices=ALGORITHMS,
        help="HMAC algorithm (default SHA1, or the URI's value)",
    )
    parser.add_argument("--digits", type=int, help="code length (default 6)")
    parser.add_argument("--period", type=int, help="TOTP step seconds (default 30)")
    parser.add_argument("--counter", type=int, help="HOTP counter (switches to HOTP mode)")
    parser.add_argument(
        "--at",
        metavar="WHEN",
        help="reference time: Unix seconds or ISO 8601 (default: now)",
    )
    parser.add_argument("--json", action="store_true", help="machine-readable output")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="Explain why a TOTP or HOTP code mismatches: clock skew, "
        "digits, algorithm, base32.",
    )
    parser.add_argument(
        "--version", action="version", version="%s %s" % (PROG, __version__)
    )
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    gen = sub.add_parser("gen", help="generate codes with context (previous/current/next)")
    _add_otp_options(gen)
    gen.add_argument(
        "--window",
        type=int,
        default=1,
        help="extra codes to show: each side of the current step (TOTP) or "
        "after the counter (HOTP) (default 1)",
    )

    diag = sub.add_parser("diagnose", help="explain why an observed code mismatches")
    _add_otp_options(diag)
    diag.add_argument("--code", required=True, help="the code that failed to verify")
    diag.add_argument(
        "--max-skew",
        type=int,
        default=DEFAULT_MAX_SKEW_STEPS,
        help="clock-skew scan width in steps each way (default %d)"
        % DEFAULT_MAX_SKEW_STEPS,
    )
    diag.add_argument(
        "--hotp-scan",
        type=int,
        default=DEFAULT_HOTP_SCAN,
        help="counters tried for the HOTP-enrollment hypothesis (default %d)"
        % DEFAULT_HOTP_SCAN,
    )
    diag.add_argument(
        "--look-ahead",
        type=int,
        default=DEFAULT_LOOK_AHEAD,
        help="HOTP mode: counters scanned ahead of the expected one (default %d)"
        % DEFAULT_LOOK_AHEAD,
    )

    sec = sub.add_parser("secret", help="lint a base32 secret and suggest repairs")
    sec.add_argument("value", metavar="SECRET", help="the secret to inspect")
    sec.add_argument("--json", action="store_true", help="machine-readable output")

    uri = sub.add_parser("uri", help="parse and audit an otpauth:// URI")
    uri.add_argument("value", metavar="URI", help="the otpauth:// URI to inspect")
    uri.add_argument("--json", action="store_true", help="machine-readable output")

    return parser


def _resolve_params(args: argparse.Namespace) -> tuple:
    """Merge --uri values with explicit flags (flags win) into (secret, Baseline)."""
    secret = args.secret
    mode = "totp"
    algorithm, digits, period, counter = "SHA1", 6, 30, 0
    if args.uri:
        parsed = urimod.parse(args.uri)
        secret = parsed.secret
        mode = parsed.mode
        algorithm, digits, period = parsed.algorithm, parsed.digits, parsed.period
        counter = parsed.counter or 0
    if args.algorithm:
        algorithm = args.algorithm
    if args.digits is not None:
        digits = validate_digits(args.digits)
    if args.period is not None:
        period = validate_period(args.period)
    if args.counter is not None:
        if args.counter < 0:
            raise TotpDoctorError("counter must be non-negative")
        mode, counter = "hotp", args.counter
    baseline = Baseline(
        mode=mode, algorithm=algorithm, digits=digits, period=period, counter=counter
    )
    return secret, baseline


def _resolve_at(args: argparse.Namespace) -> int:
    return parse_when(args.at) if args.at else int(time.time())


def _require_non_negative(**flags: int) -> None:
    """Reject negative scan widths early; they would silently empty the search."""
    for name, value in flags.items():
        if value < 0:
            raise TotpDoctorError(
                "--%s must be non-negative, got %d" % (name.replace("_", "-"), value)
            )


def cmd_gen(args: argparse.Namespace, out) -> int:
    _require_non_negative(window=args.window)
    secret, baseline = _resolve_params(args)
    key = base32.decode(secret)
    at = _resolve_at(args)
    if baseline.mode == "hotp":
        rows = [
            {"counter": c, "code": hotp(key, c, baseline.digits, baseline.algorithm)}
            for c in range(baseline.counter, baseline.counter + 1 + args.window)
        ]
        if args.json:
            payload = {
                "mode": "hotp",
                "algorithm": baseline.algorithm,
                "digits": baseline.digits,
                "codes": rows,
            }
            out.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
            return 0
        out.write(
            "mode hotp | algorithm %s | digits %d\n" % (baseline.algorithm, baseline.digits)
        )
        for row in rows:
            marker = ">" if row["counter"] == baseline.counter else " "
            out.write("%s counter %-6d %s\n" % (marker, row["counter"], row["code"]))
        return 0
    step = time_step(at, baseline.period)
    remaining = seconds_remaining(at, baseline.period)
    rows = []
    for offset in range(-args.window, args.window + 1):
        if step + offset < 0:
            continue
        offset_at = at + offset * baseline.period
        rows.append(
            {
                "offset": offset,
                "code": totp(key, offset_at, baseline.period, baseline.digits, baseline.algorithm),
                "valid_from": (step + offset) * baseline.period,
                "valid_until": (step + offset + 1) * baseline.period,
            }
        )
    if args.json:
        payload = {
            "mode": "totp",
            "algorithm": baseline.algorithm,
            "digits": baseline.digits,
            "period": baseline.period,
            "at": at,
            "step": step,
            "seconds_remaining": remaining,
            "codes": rows,
        }
        out.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        return 0
    out.write(
        "mode totp | algorithm %s | digits %d | period %ds\n"
        % (baseline.algorithm, baseline.digits, baseline.period)
    )
    out.write("time %s | step %d | %ds remaining\n" % (format_utc(at), step, remaining))
    for row in rows:
        marker = ">" if row["offset"] == 0 else " "
        out.write(
            "%s %+d  %s  valid %s - %s\n"
            % (
                marker,
                row["offset"],
                row["code"],
                format_utc(row["valid_from"]),
                format_utc(row["valid_until"]),
            )
        )
    return 0


def cmd_diagnose(args: argparse.Namespace, out) -> int:
    _require_non_negative(
        max_skew=args.max_skew, hotp_scan=args.hotp_scan, look_ahead=args.look_ahead
    )
    secret, baseline = _resolve_params(args)
    at = _resolve_at(args)
    result = diagnose(
        secret,
        args.code,
        at,
        baseline=baseline,
        max_skew_steps=args.max_skew,
        hotp_scan=args.hotp_scan,
        look_ahead=args.look_ahead,
    )
    out.write((render_json(result) if args.json else render_text(result)) + "\n")
    return 0 if result.matches else 1


def cmd_secret(args: argparse.Namespace, out) -> int:
    report = base32.lint(args.value)
    if args.json:
        payload = {
            "normalized": report.normalized,
            "decodes": report.decodes,
            "key_bits": report.key_bits,
            "issues": [
                {"code": i.code, "message": i.message, "suggestion": i.suggestion}
                for i in report.issues
            ],
            "repairs": report.repairs,
        }
        out.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    else:
        out.write("normalized: %s\n" % (report.normalized or "(empty)"))
        if report.decodes:
            out.write("decodes: yes (%d-byte key, %d bits)\n" % (len(report.key or b""), report.key_bits))
        else:
            out.write("decodes: no\n")
        if not report.issues:
            out.write("issues: none — this is a clean base32 secret\n")
        for issue in report.issues:
            out.write("issue [%s]: %s\n" % (issue.code, issue.message))
            if issue.suggestion:
                out.write("  hint: %s\n" % issue.suggestion)
        for repair in report.repairs:
            out.write("repair candidate: %s\n" % repair)
    return 0 if report.decodes else 1


def cmd_uri(args: argparse.Namespace, out) -> int:
    parsed = urimod.parse(args.value)
    if args.json:
        payload = {
            "mode": parsed.mode,
            "label": parsed.label,
            "account": parsed.account,
            "issuer": parsed.issuer or parsed.label_issuer,
            "algorithm": parsed.algorithm,
            "digits": parsed.digits,
            "period": parsed.period,
            "counter": parsed.counter,
            "secret": parsed.secret,
            "warnings": parsed.warnings,
        }
        out.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        return 0
    out.write("type: %s\n" % parsed.mode)
    out.write("account: %s\n" % (parsed.account or "(none)"))
    out.write("issuer: %s\n" % (parsed.issuer or parsed.label_issuer or "(none)"))
    out.write(
        "parameters: algorithm %s, digits %d%s\n"
        % (
            parsed.algorithm,
            parsed.digits,
            ", period %ds" % parsed.period
            if parsed.mode == "totp"
            else ", counter %d" % (parsed.counter or 0),
        )
    )
    if parsed.warnings:
        for warning in parsed.warnings:
            out.write("warning: %s\n" % warning)
    else:
        out.write("warnings: none\n")
    return 0


_COMMANDS = {
    "gen": cmd_gen,
    "diagnose": cmd_diagnose,
    "secret": cmd_secret,
    "uri": cmd_uri,
}


def main(argv: Optional[List[str]] = None, out=None, err=None) -> int:
    """CLI entry point; returns the process exit code."""
    out = out if out is not None else sys.stdout
    err = err if err is not None else sys.stderr
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help(err)
        return 2
    try:
        return _COMMANDS[args.command](args, out)
    except TotpDoctorError as exc:
        err.write("%s: error: %s\n" % (PROG, exc))
        return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
