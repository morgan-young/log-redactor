"""Core string and dictionary redaction helpers."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

from .patterns import BUILTIN_PATTERNS, BUILTIN_SENSITIVE_KEYS

RegexLike = str | re.Pattern[str]


def _build_patterns(
    patterns: Iterable[str] | None = None,
    custom_patterns: Iterable[RegexLike] | None = None,
) -> tuple[re.Pattern[str], ...]:
    """Resolve built-in and custom patterns into compiled regex objects.

    :param patterns:
        Iterable of built-in pattern names to enable. If ``None``, all built-ins
        are used.
    :param custom_patterns:
        Additional regex patterns provided as pattern strings or pre-compiled
        :class:`re.Pattern` instances.
    :returns:
        Tuple of compiled regex patterns in application order.
    :raises ValueError:
        If ``patterns`` contains an unknown built-in pattern name.
    """
    if patterns is None:
        compiled = list(BUILTIN_PATTERNS.values())
    else:
        compiled = []
        for name in patterns:
            try:
                compiled.append(BUILTIN_PATTERNS[name])
            except KeyError as error:
                message = f"Unknown built-in pattern: {name!r}"
                raise ValueError(message) from error

    if custom_patterns:
        for pattern in custom_patterns:
            if isinstance(pattern, re.Pattern):
                compiled.append(pattern)
            else:
                compiled.append(re.compile(pattern))

    return tuple(compiled)


def _normalize_sensitive_keys(keys: Iterable[str] | None = None) -> set[str]:
    """Normalize sensitive key names for case-insensitive comparison.

    :param keys:
        Optional iterable of key names to treat as sensitive. If ``None``, the
        default built-in key set is used.
    :returns:
        Lower-cased key names used during dictionary redaction.
    """
    if keys is None:
        return set(BUILTIN_SENSITIVE_KEYS)
    return {key.lower() for key in keys}


def _redact_text_with_patterns(
    text: str,
    compiled_patterns: tuple[re.Pattern[str], ...],
    replacement: str,
) -> str:
    """Apply compiled redaction patterns to a string.

    :param text:
        Input text to scan for sensitive values.
    :param compiled_patterns:
        Compiled regex objects used for substitutions.
    :param replacement:
        Replacement text inserted for matched sensitive values.
    :returns:
        Redacted string with all configured patterns applied.
    """
    redacted = text
    for pattern in compiled_patterns:
        if pattern.pattern == BUILTIN_PATTERNS["url_token"].pattern:
            redacted = pattern.sub(rf"\1{replacement}", redacted)
        else:
            redacted = pattern.sub(replacement, redacted)
    return redacted


def _redact_value(
    value: Any,
    *,
    compiled_patterns: tuple[re.Pattern[str], ...],
    sensitive_keys: set[str],
    replacement: str,
    key_context: str | None = None,
) -> Any:
    """Recursively redact a value based on key sensitivity and regex matches.

    :param value:
        Value to process. Supports nested mappings, lists, tuples, and strings.
    :param compiled_patterns:
        Compiled regex objects used to redact string values.
    :param sensitive_keys:
        Lower-cased key names that force full-value redaction.
    :param replacement:
        Replacement text inserted when data is redacted.
    :param key_context:
        Current key name for ``value`` when traversing mappings.
    :returns:
        A redacted copy of ``value`` while preserving container types.
    """
    if key_context and key_context.lower() in sensitive_keys:
        return replacement

    if isinstance(value, str):
        return _redact_text_with_patterns(value, compiled_patterns, replacement)

    if isinstance(value, Mapping):
        return {
            key: _redact_value(
                nested_value,
                compiled_patterns=compiled_patterns,
                sensitive_keys=sensitive_keys,
                replacement=replacement,
                key_context=key if isinstance(key, str) else None,
            )
            for key, nested_value in value.items()
        }

    if isinstance(value, list):
        return [
            _redact_value(
                item,
                compiled_patterns=compiled_patterns,
                sensitive_keys=sensitive_keys,
                replacement=replacement,
            )
            for item in value
        ]

    if isinstance(value, tuple):
        return tuple(
            _redact_value(
                item,
                compiled_patterns=compiled_patterns,
                sensitive_keys=sensitive_keys,
                replacement=replacement,
            )
            for item in value
        )

    return value


def redact(
    text: str,
    patterns: Iterable[str] | None = None,
    custom_patterns: Iterable[RegexLike] | None = None,
    replacement: str = "[REDACTED]",
) -> str:
    """Redact sensitive values from a string.

    :param text:
        Text to redact.
    :param patterns:
        Optional built-in pattern names to apply. If ``None``, all built-in
        patterns are used.
    :param custom_patterns:
        Optional custom regex patterns as strings or compiled
        :class:`re.Pattern` objects.
    :param replacement:
        Text used to replace matched sensitive values.
    :returns:
        Redacted text.
    :raises TypeError:
        If ``text`` is not a string.
    :raises ValueError:
        If ``patterns`` contains an unknown built-in pattern name.
    """
    if not isinstance(text, str):
        message = "text must be a string"
        raise TypeError(message)

    compiled_patterns = _build_patterns(patterns, custom_patterns)
    return _redact_text_with_patterns(text, compiled_patterns, replacement)


def redact_dict(
    data: dict[Any, Any],
    keys: Iterable[str] | None = None,
    patterns: Iterable[str] | None = None,
    custom_patterns: Iterable[RegexLike] | None = None,
    replacement: str = "[REDACTED]",
) -> dict[Any, Any]:
    """Return a recursively redacted copy of a dictionary.

    Redaction is applied by sensitive key name and by configured regex patterns
    for string values. Input data is never mutated.

    :param data:
        Dictionary to redact.
    :param keys:
        Optional sensitive key names. If ``None``, built-in sensitive keys are
        used.
    :param patterns:
        Optional built-in pattern names to apply. If ``None``, all built-in
        patterns are used.
    :param custom_patterns:
        Optional custom regex patterns as strings or compiled
        :class:`re.Pattern` objects.
    :param replacement:
        Text used to replace redacted values.
    :returns:
        New dictionary with redacted values.
    :raises TypeError:
        If ``data`` is not a dictionary.
    :raises ValueError:
        If ``patterns`` contains an unknown built-in pattern name.
    """
    if not isinstance(data, dict):
        message = "data must be a dictionary"
        raise TypeError(message)

    compiled_patterns = _build_patterns(patterns, custom_patterns)
    sensitive_keys = _normalize_sensitive_keys(keys)

    return {
        key: _redact_value(
            value,
            compiled_patterns=compiled_patterns,
            sensitive_keys=sensitive_keys,
            replacement=replacement,
            key_context=key if isinstance(key, str) else None,
        )
        for key, value in data.items()
    }
