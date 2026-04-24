"""Shared regex patterns for URL and secret detection across all analyzers."""

from __future__ import annotations

import re

URL_PATTERN = re.compile(r"https?://[\w\-._~:/?#\[\]@!$&'()*+,;=%]+", re.IGNORECASE)

SECRET_PATTERN = re.compile(
    r"(?i)(api[_-]?key|client[_-]?secret|secret|token|passwd|password)\s*[:=]\s*[\"']?([A-Za-z0-9_\-+/=]{8,})"
)
