"""Shared regex patterns for URL, token, and secret detection across analyzers."""

from __future__ import annotations

import re

URL_PATTERN = re.compile(r"https?://[\w\-._~:/?#\[\]@!$&'()*+,;=%]+", re.IGNORECASE)

SECRET_PATTERN = re.compile(
    r"(?i)(api[_-]?key|client[_-]?secret|secret|token|passwd|password)\s*[:=]\s*[\"']?([A-Za-z0-9_\-+/=]{8,})"
)

JWT_PATTERN = re.compile(
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
)

BEARER_PATTERN = re.compile(r"(?i)bearer\s+([A-Za-z0-9\-._~+/=]{12,})")

PRIVATE_KEY_PATTERN = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
