# Contributing to IPIntel

Thanks for your interest in contributing! Here's how to get involved.

---

## Reporting Bugs

Open an issue and include:
- Your OS and Python version
- The command you ran
- The full error output

---

## Suggesting Features

Open an issue with the `enhancement` label. Describe the use case, not just the feature — it helps evaluate fit.

---

## Adding a New API

IPIntel is designed to make adding new APIs straightforward:

1. Create a new file in `apis/` (e.g. `apis/virustotal.py`)
2. Inherit from `BaseAPI` in `apis/base.py`
3. Implement `query(self, ip)` and `headers(self)`
4. Add the new key to `DEFAULT_CONFIG` in `config.py`
5. Wire it up in `ipintel.py` with a new `--flag`

---

## Pull Requests

- Keep PRs focused — one feature or fix per PR
- Match the existing code style
- Test your changes before submitting
- Update `CHANGELOG.md` with a summary of your changes

---

## Code Style

- Use `black` for formatting if possible
- Keep functions small and single-purpose
- Add comments for anything non-obvious
