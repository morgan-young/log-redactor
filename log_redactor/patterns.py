"""Built-in patterns and key configuration for redaction."""

from __future__ import annotations

import re

BUILTIN_PATTERN_SOURCES: dict[str, str] = {
    "email": r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
    "ipv4": r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
    "jwt": r"\b[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
    "bearer_token": r"\bBearer\s+[A-Za-z0-9\-._~+/]+=*\b",
    "api_key": r"\b(?:sk-(?:live|test)-[A-Za-z0-9]+|AKIA[0-9A-Z]{16}|AIza[A-Za-z0-9_-]{35})\b",
    "url_token": r"([?&](?:token|access_token|refresh_token|api_key|key)=)[^&\s]+",
    "credit_card_basic": r"\b(?:\d[ -]*?){13,19}\b",
}

BUILTIN_PATTERNS: dict[str, re.Pattern[str]] = {
    name: re.compile(source) for name, source in BUILTIN_PATTERN_SOURCES.items()
}

BUILTIN_SENSITIVE_KEYS: set[str] = {
    "password",
    "passwd",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "authorization",
}
