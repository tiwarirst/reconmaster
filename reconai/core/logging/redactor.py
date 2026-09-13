"""Secret redactor — prevents sensitive data from appearing in logs.

Never log: passwords, session cookies, access tokens, API secrets, private keys.
"""
from __future__ import annotations

import re

# Patterns that indicate sensitive data
_SENSITIVE_PATTERNS = [
    (re.compile(r'(api[_-]?key\s*[=:]\s*)["\']?[\w\-]{16,}["\']?', re.I), r'\1[REDACTED]'),
    (re.compile(r'(token\s*[=:]\s*)["\']?[\w\-\.]{16,}["\']?', re.I), r'\1[REDACTED]'),
    (re.compile(r'(password\s*[=:]\s*)["\']?[^\s"\']{4,}["\']?', re.I), r'\1[REDACTED]'),
    (re.compile(r'(secret\s*[=:]\s*)["\']?[\w\-]{16,}["\']?', re.I), r'\1[REDACTED]'),
    (re.compile(r'(authorization\s*[=:]\s*)(Bearer\s+)?[\w\-\.]{16,}', re.I), r'\1[REDACTED]'),
    (re.compile(r'(cookie\s*[=:]\s*)[^\s;]{16,}', re.I), r'\1[REDACTED]'),
    (re.compile(r'(session[_-]?id\s*[=:]\s*)[^\s;]{8,}', re.I), r'\1[REDACTED]'),
    (re.compile(r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----.*?-----END', re.S), '[REDACTED PRIVATE KEY]'),
    (re.compile(r'(aws_secret_access_key\s*[=:]\s*)[\w/\+]{20,}', re.I), r'\1[REDACTED]'),
]


def redact(text: str) -> str:
    """Redact sensitive information from text."""
    result = text
    for pattern, replacement in _SENSITIVE_PATTERNS:
        result = pattern.sub(replacement, result)
    return result


def is_sensitive(text: str) -> bool:
    """Check if text appears to contain sensitive information."""
    for pattern, _ in _SENSITIVE_PATTERNS:
        if pattern.search(text):
            return True
    return False
