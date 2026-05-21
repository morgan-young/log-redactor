"""Logging filter that redacts sensitive values in log records."""

from __future__ import annotations

import logging
from collections.abc import Iterable
from typing import Any

from .core import RegexLike, _build_patterns, _normalize_sensitive_keys, _redact_value


class RedactingFilter(logging.Filter):
    """A logging filter that redacts sensitive values before emission.

    :param name:
        Filter name passed to :class:`logging.Filter`.
    :param keys:
        Optional sensitive key names. If ``None``, built-in sensitive keys are
        used.
    :param patterns:
        Optional built-in pattern names to apply. If ``None``, all built-in
        patterns are used.
    :param custom_patterns:
        Optional custom regex patterns as strings or compiled regex objects.
    :param replacement:
        Text used to replace redacted values.
    :raises ValueError:
        If ``patterns`` contains an unknown built-in pattern name.
    """

    def __init__(
        self,
        name: str = "",
        *,
        keys: Iterable[str] | None = None,
        patterns: Iterable[str] | None = None,
        custom_patterns: Iterable[RegexLike] | None = None,
        replacement: str = "[REDACTED]",
    ) -> None:
        """Initialize filter configuration for key and pattern redaction.

        :param name:
            Filter name passed to :class:`logging.Filter`.
        :param keys:
            Optional sensitive key names.
        :param patterns:
            Optional built-in pattern names to apply.
        :param custom_patterns:
            Optional custom regex patterns as strings or compiled regex objects.
        :param replacement:
            Text used to replace redacted values.
        :raises ValueError:
            If ``patterns`` contains an unknown built-in pattern name.
        """
        super().__init__(name)
        self._replacement = replacement
        self._compiled_patterns = _build_patterns(patterns, custom_patterns)
        self._sensitive_keys = _normalize_sensitive_keys(keys)

    def _redact_any(self, value: Any) -> Any:
        """Redact an arbitrary object using configured keys and patterns.

        :param value:
            Value to redact.
        :returns:
            Redacted value with container structure preserved.
        """
        return _redact_value(
            value,
            compiled_patterns=self._compiled_patterns,
            sensitive_keys=self._sensitive_keys,
            replacement=self._replacement,
        )

    def filter(self, record: logging.LogRecord) -> bool:
        """Redact message content on a log record.

        This method updates ``record.msg`` and ``record.args`` in place so that
        standard ``%s`` logging formatting emits redacted values.

        :param record:
            Log record to redact.
        :returns:
            Always ``True`` so logging continues after redaction.
        """
        record.msg = self._redact_any(record.msg)
        if isinstance(record.args, tuple):
            record.args = tuple(self._redact_any(item) for item in record.args)
        elif isinstance(record.args, dict):
            record.args = self._redact_any(record.args)
        elif record.args:
            record.args = self._redact_any(record.args)
        return True
