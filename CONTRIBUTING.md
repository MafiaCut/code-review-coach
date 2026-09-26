# Contributing

Contributions are welcome through pull requests.

## Development setup

```bash
python -m venv .venv
python -m pip install -e ".[dev,web]"
python -m pytest
ruff check analyzer app.py cli.py code_review_coach
```

Add tests for behavior changes and keep submitted diffs as inert text fixtures;
tests and analysis rules must never execute code from a diff.

For new rules, include positive and negative examples, register the rule in
`ALL_RULES`, and add English and Spanish output where human-readable text is
introduced.
