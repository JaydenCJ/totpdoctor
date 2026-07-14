# totpdoctor examples

Both examples are fully offline and deterministic — they pin the reference
time with `--at`, so they produce the same output on every run.

| File | What it shows |
|---|---|
| [`diagnose_walkthrough.sh`](diagnose_walkthrough.sh) | Every fault class the engine detects, staged one at a time from the CLI |
| [`library_usage.py`](library_usage.py) | The Python API: build a diagnosis programmatically and inspect ranked matches |

Run them from the repository root:

```bash
bash examples/diagnose_walkthrough.sh
python3 examples/library_usage.py
```

Neither example needs an install: the walkthrough script sets `PYTHONPATH=src`
itself, and `library_usage.py` inserts `src/` when totpdoctor is not installed.
