"""End-to-end CLI behavior through the in-process runner.

Covers all four subcommands, the exit-code contract (0 match / 1 no-match /
2 input error), --json output, --uri parameter merging, and time parsing.
"""

from __future__ import annotations

import json

import pytest

from totpdoctor import __version__, decode_secret, totp
from totpdoctor.cli import parse_when
from totpdoctor.errors import TotpDoctorError

from conftest import FIXED_AT, RFC_SECRET_B32

KEY = decode_secret(RFC_SECRET_B32)
AT = str(FIXED_AT)


def test_version_flag_matches_package(run_cli, capsys):
    # argparse's version action prints to the real stdout and exits 0.
    with pytest.raises(SystemExit) as excinfo:
        run_cli("--version")
    assert excinfo.value.code == 0
    assert capsys.readouterr().out.strip() == "totpdoctor %s" % __version__


def test_no_command_prints_help_and_exits_2(run_cli):
    code, out, err = run_cli()
    assert code == 2
    assert "diagnose" in err


def test_gen_shows_current_and_neighbor_codes(run_cli):
    code, out, _ = run_cli("gen", "--secret", RFC_SECRET_B32, "--at", AT)
    assert code == 0
    assert totp(KEY, FIXED_AT) in out
    assert totp(KEY, FIXED_AT - 30) in out  # previous step, for skew eyeballing
    assert "30s remaining" in out


def test_gen_json_is_parseable_and_complete(run_cli):
    code, out, _ = run_cli("gen", "--secret", RFC_SECRET_B32, "--at", AT, "--json")
    payload = json.loads(out)
    assert payload["mode"] == "totp"
    assert len(payload["codes"]) == 3
    assert payload["codes"][1]["code"] == totp(KEY, FIXED_AT)


def test_gen_hotp_mode_via_counter_flag(run_cli):
    code, out, _ = run_cli(
        "gen", "--secret", RFC_SECRET_B32, "--counter", "0", "--window", "2"
    )
    assert code == 0
    assert "mode hotp" in out
    assert out.count("counter") >= 3


def test_diagnose_skew_exits_zero_and_explains(run_cli):
    observed = totp(KEY, FIXED_AT - 60)
    code, out, _ = run_cli(
        "diagnose", "--secret", RFC_SECRET_B32, "--code", observed, "--at", AT
    )
    assert code == 0
    assert "clock skew: -60 s" in out


def test_diagnose_no_match_exits_one(run_cli):
    code, out, _ = run_cli(
        "diagnose", "--secret", RFC_SECRET_B32, "--code", "000001", "--at", AT
    )
    assert code == 1
    assert "NO MATCH" in out


def test_diagnose_json_verdict(run_cli):
    observed = totp(KEY, FIXED_AT, algorithm="SHA256")
    code, out, _ = run_cli(
        "diagnose", "--secret", RFC_SECRET_B32, "--code", observed, "--at", AT, "--json"
    )
    payload = json.loads(out)
    assert code == 0
    assert payload["matches"][0]["algorithm"] == "SHA256"


def test_diagnose_with_uri_inherits_parameters(run_cli):
    uri = (
        "otpauth://totp/Example:alice@example.test?secret=%s&issuer=Example"
        "&algorithm=SHA256&digits=8" % RFC_SECRET_B32
    )
    observed = totp(KEY, FIXED_AT, digits=8, algorithm="SHA256")
    code, out, _ = run_cli("diagnose", "--uri", uri, "--code", observed, "--at", AT)
    assert code == 0
    assert "verdict: EXACT" in out  # URI parameters made it an exact match


def test_diagnose_flags_override_uri(run_cli):
    uri = "otpauth://totp/E:a?secret=%s&issuer=E&digits=8" % RFC_SECRET_B32
    observed = totp(KEY, FIXED_AT)  # 6 digits
    code, out, _ = run_cli(
        "diagnose", "--uri", uri, "--code", observed, "--at", AT, "--digits", "6"
    )
    assert code == 0 and "verdict: EXACT" in out


def test_diagnose_negative_scan_width_exits_two_with_flag_name(run_cli):
    # A negative width would silently empty the search (even the zero-deviation
    # candidate would never be tested), so it must be rejected loudly instead.
    code, _, err = run_cli(
        "diagnose", "--secret", RFC_SECRET_B32, "--code", "123456",
        "--at", AT, "--max-skew", "-5",
    )
    assert code == 2
    assert "--max-skew must be non-negative" in err


def test_gen_negative_window_exits_two_with_flag_name(run_cli):
    code, _, err = run_cli(
        "gen", "--secret", RFC_SECRET_B32, "--at", AT, "--window", "-1"
    )
    assert code == 2
    assert "--window must be non-negative" in err


def test_gen_json_includes_generation_parameters(run_cli):
    # The JSON contract must carry the parameters the text header shows, so a
    # script consuming it never has to guess what produced the codes.
    _, out, _ = run_cli("gen", "--secret", RFC_SECRET_B32, "--at", AT, "--json")
    payload = json.loads(out)
    assert (payload["algorithm"], payload["digits"], payload["period"]) == ("SHA1", 6, 30)
    _, out, _ = run_cli("gen", "--secret", RFC_SECRET_B32, "--counter", "3", "--json")
    payload = json.loads(out)
    assert payload["mode"] == "hotp" and payload["algorithm"] == "SHA1"


def test_diagnose_bad_code_exits_two_with_message(run_cli):
    code, out, err = run_cli(
        "diagnose", "--secret", RFC_SECRET_B32, "--code", "not-a-code", "--at", AT
    )
    assert code == 2
    assert "error" in err


def test_diagnose_undecodable_secret_exits_two(run_cli):
    code, _, err = run_cli("diagnose", "--secret", "  ", "--code", "123456", "--at", AT)
    assert code == 2 and "secret" in err


def test_secret_lint_clean_exits_zero(run_cli):
    code, out, _ = run_cli("secret", RFC_SECRET_B32)
    assert code == 0
    assert "decodes: yes" in out


def test_secret_lint_undecodable_exits_one_with_repairs(run_cli):
    code, out, _ = run_cli("secret", "JBSW0EHK")
    assert code == 1
    assert "repair candidate: JBSWOEHK" in out


def test_secret_json_lists_issue_codes(run_cli):
    code, out, _ = run_cli("secret", "mzxw 6ytb", "--json")
    payload = json.loads(out)
    codes = {issue["code"] for issue in payload["issues"]}
    assert "separators" in codes and "lowercase" in codes


def test_uri_command_reports_warnings(run_cli):
    code, out, _ = run_cli(
        "uri",
        "otpauth://totp/Alpha:alice@example.test?secret=%s&issuer=Beta" % RFC_SECRET_B32,
    )
    assert code == 0
    assert "warning:" in out and "disagrees" in out


def test_uri_command_json(run_cli):
    code, out, _ = run_cli(
        "uri",
        "otpauth://hotp/E:alice?secret=%s&issuer=E&counter=9" % RFC_SECRET_B32,
        "--json",
    )
    payload = json.loads(out)
    assert payload["mode"] == "hotp" and payload["counter"] == 9


def test_uri_command_malformed_exits_two(run_cli):
    code, _, err = run_cli("uri", "otpauth://totp/alice")
    assert code == 2 and "secret" in err


def test_parse_when_accepts_unix_and_iso_rejects_garbage():
    assert parse_when(AT) == FIXED_AT
    assert parse_when("2026-07-12T12:00:00Z") == FIXED_AT
    assert parse_when("2026-07-12T14:00:00+02:00") == FIXED_AT
    with pytest.raises(TotpDoctorError):
        parse_when("half past noon")


def test_gen_accepts_iso8601_at_flag(run_cli):
    code, out, _ = run_cli(
        "gen", "--secret", RFC_SECRET_B32, "--at", "2026-07-12T12:00:00Z"
    )
    assert code == 0 and totp(KEY, FIXED_AT) in out
