# Contributing to totpdoctor

Thanks for your interest in contributing. Issues, discussions, and pull
requests are all welcome.

## Development setup

```bash
git clone https://github.com/JaydenCJ/totpdoctor
cd totpdoctor
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Running the checks

```bash
pytest                 # 92 deterministic tests, fully offline
bash scripts/smoke.sh  # end-to-end CLI smoke; must print SMOKE OK
```

Both must pass before a pull request is reviewed. The suite pins every
reference time with `--at`, so nothing depends on the wall clock or the
network.

## Ground rules

- **No new runtime dependencies.** The package is standard-library only;
  that is a feature. Test-only dependencies belong in the `dev` extra.
- **Every hypothesis needs receipts.** A new deviation kind must come with a
  test that manufactures the fault and asserts the top-ranked match names it,
  plus an entry in `docs/diagnosis.md` (including its ranking weight and its
  effect on the candidate count / collision-risk math).
- **Codes are strings, never integers.** Leading zeros are significant
  everywhere — in the engine, the CLI, and the JSON output.
- **Keep the three READMEs aligned.** `README.md`, `README.zh.md`, and
  `README.ja.md` are line-for-line translations; update all three when you
  change one (English is the authoritative version).

## Reporting bugs

Please include `totpdoctor --version`, the full command line (with the secret
replaced by a fresh test secret that reproduces the issue), the `--at` value,
and the complete report output. Never post a production secret in an issue.

## Security

Do not report security issues in public issues. Use GitHub's private
vulnerability reporting on the repository instead.
