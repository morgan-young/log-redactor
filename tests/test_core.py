from __future__ import annotations

from log_redactor import redact, redact_dict


def test_redact_uses_selected_builtin_patterns() -> None:
    text = "Email alice@example.com from 127.0.0.1"
    redacted = redact(text, patterns=["email"])
    assert "alice@example.com" not in redacted
    assert "[REDACTED]" in redacted
    assert "127.0.0.1" in redacted


def test_redact_supports_custom_patterns() -> None:
    text = "order id: internal-12345"
    redacted = redact(text, patterns=[], custom_patterns=[r"internal-\d+"])
    assert redacted == "order id: [REDACTED]"


def test_redact_dict_is_recursive_and_non_mutating() -> None:
    original = {
        "user": "alice@example.com",
        "password": "p@ssw0rd",
        "nested": {
            "token": "Bearer super-secret",
            "list": ["hello", "bob@example.com"],
            "tuple": ("api_key=abc123", 7),
        },
    }

    redacted = redact_dict(original)

    assert original["password"] == "p@ssw0rd"
    assert redacted["password"] == "[REDACTED]"
    assert redacted["user"] == "[REDACTED]"
    assert redacted["nested"]["token"] == "[REDACTED]"
    assert redacted["nested"]["list"][1] == "[REDACTED]"
    assert redacted["nested"]["tuple"][1] == 7
    assert redacted["nested"]["tuple"][0].startswith("api_key=")


def test_redact_dict_preserves_non_string_values_unless_key_sensitive() -> None:
    data = {"count": 3, "active": True, "api_key": 9999}
    redacted = redact_dict(data)
    assert redacted["count"] == 3
    assert redacted["active"] is True
    assert redacted["api_key"] == "[REDACTED]"
