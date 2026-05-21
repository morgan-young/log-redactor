# log-redactor

[![CI](https://github.com/ORG/REPO/actions/workflows/ci.yml/badge.svg)](https://github.com/ORG/REPO/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/log-redactor.svg)](https://pypi.org/project/log-redactor/)
[![Python](https://img.shields.io/pypi/pyversions/log-redactor.svg)](https://pypi.org/project/log-redactor/)
[![License](https://img.shields.io/pypi/l/log-redactor.svg)](https://github.com/ORG/REPO/blob/main/LICENSE)

Small, dependency-free redaction helpers for Python logs and payloads.  
`log-redactor` helps prevent accidental exposure of secrets in log messages, strings, and nested dictionaries.

> Replace `ORG/REPO` in badge URLs once the repository is published.

## Why use it?

- Redacts by **key name** and **regex pattern value matching**
- Supports nested `dict` / `list` / `tuple` structures
- Works with standard library `logging` and `%s`-style args
- Keeps runtime dependencies at zero (stdlib only)

## Installation

```bash
pip install log-redactor
```

## Quick start

```python
import logging
from log_redactor import RedactingFilter, redact, redact_dict

logger = logging.getLogger("app")
logger.setLevel(logging.INFO)
logger.addFilter(RedactingFilter(patterns=["email", "jwt", "api_key"]))

logger.info("User %s used key %s", "alice@example.com", "sk-live-abc123")

print(redact("Contact: dev@example.com"))

payload = {
    "username": "alice",
    "password": "super-secret",
    "profile": {"email": "alice@example.com"},
}
print(redact_dict(payload))
```

## API

```python
from log_redactor import RedactingFilter, redact, redact_dict
```

- `redact(text: str, patterns=None, custom_patterns=None, replacement="[REDACTED]") -> str`
- `redact_dict(data: dict, keys=None, patterns=None, custom_patterns=None, replacement="[REDACTED]") -> dict`
- `RedactingFilter(logging.Filter)`

## Built-in patterns

- `email`
- `ipv4`
- `jwt`
- `bearer_token`
- `api_key`
- `url_token`
- `credit_card_basic`

## Built-in sensitive keys

- `password`
- `passwd`
- `secret`
- `token`
- `access_token`
- `refresh_token`
- `api_key`
- `authorization`

## Development

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e . pytest ruff
pytest
ruff check .
```

## Security note

This package is intended to reduce accidental leakage, not guarantee perfect anonymization.
Always validate your own threat model and pattern coverage for production systems.

## License

MIT
