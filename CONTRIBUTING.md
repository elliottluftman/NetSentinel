# Contributing

## Development Setup

1. Clone repo.
2. Create env and install deps:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

3. Run tests before opening a PR:

```bash
pytest -q
```

## Pull Request Rules

- Keep PRs scoped and focused.
- Add or update tests for behavior changes.
- Ensure CI passes.
- Document any config or API behavior changes in `README.md`.
