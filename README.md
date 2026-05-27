# Log Redactor

[![CI](https://github.com/morgan-young/log-redactor/actions/workflows/ci.yml/badge.svg)](https://github.com/morgan-young/log-redactor/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/python-log-redactor.svg)](https://pypi.org/project/python-log-redactor/)
[![Python](https://img.shields.io/pypi/pyversions/python-log-redactor.svg)](https://pypi.org/project/python-log-redactor/)
[![License](https://img.shields.io/pypi/l/python-log-redactor.svg)](https://github.com/morgan-young/log-redactor/blob/main/LICENSE)

This is a small, dependency-free redaction helper for Python logs and payloads that helps prevent accidental exposure of secrets and other things you wouldn't want to persist on a server somewhere (email addresses, etc.) in log messages and anything else that gets printed out. Of course, you may be thinking we should never log this stuff anyway, but there are some instances where things are okay when working locally but not okay when working with real infra, which means things that shouldn't get logged, do get logged, by mistake. This aims to stop that.

It works with both the official python logger and with print statements.

## Why use it?

- Redacts by key name and regex for common secrets/sensitive information.
- Supports nested `dict` / `list` / `tuple` structures
- Works with standard library `logging` and `%s`-style args
- Keeps runtime dependencies at zero (stdlib only)

## Installation

```bash
pip install python-log-redactor
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

## Built-in patterns
These all have regex patterns that try to identify these values and redact them.

- `email`
- `ipv4`
- `jwt`
- `bearer_token`
- `api_key`
- `url_token`
- `credit_card_basic`

## Built-in sensitive keys
The value of these keys will be redacted automatically if the presence of these keys are detected.

- `password`
- `passwd`
- `secret`
- `token`
- `access_token`
- `refresh_token`
- `api_key`
- `authorization`

## Development
tbc here as well as a contributing section.

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e . pytest ruff
pytest
ruff check .
```

## Security note

This package is intended to reduce accidental leakage, not guarantee perfect anonymisation. You should not be printing secrets to logs on real infrastructure *regardless*. If you do, this is just a failsafe to try and ensure that it is captured and redacted, but it may not always be successful. The primary use case is combatting forgetfulness when moving from local to real infra.

Don't be stupid. Do not log secrets on real infra.

## License

This package is distributed under an MIT license.
