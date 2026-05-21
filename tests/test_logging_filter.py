from __future__ import annotations

import io
import logging

from log_redactor import RedactingFilter


def _build_test_logger() -> tuple[logging.Logger, io.StringIO, logging.Handler]:
    logger = logging.getLogger("log_redactor_test_logger")
    logger.handlers.clear()
    logger.filters.clear()
    logger.setLevel(logging.INFO)
    logger.propagate = False

    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    return logger, stream, handler


def test_filter_redacts_percent_style_args() -> None:
    logger, stream, handler = _build_test_logger()
    logger.addFilter(RedactingFilter(patterns=["email", "api_key"]))

    logger.info("User %s used key %s", "alice@example.com", "sk-live-abc123")

    output = stream.getvalue()
    logger.removeHandler(handler)
    logger.handlers.clear()
    logger.filters.clear()

    assert "alice@example.com" not in output
    assert "sk-live-abc123" not in output
    assert output.count("[REDACTED]") >= 2


def test_filter_redacts_mapping_and_nested_values() -> None:
    logger, stream, handler = _build_test_logger()
    logger.addFilter(RedactingFilter(patterns=["email"]))

    logger.info(
        "payload=%s",
        {"password": "letmein", "meta": {"email": "bob@example.com"}, "count": 2},
    )

    output = stream.getvalue()
    logger.removeHandler(handler)
    logger.handlers.clear()
    logger.filters.clear()

    assert "letmein" not in output
    assert "bob@example.com" not in output
    assert output.count("[REDACTED]") >= 2
    assert "2" in output
