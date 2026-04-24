from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

SignalKind = Literal["readable_source", "hardcoded_url", "candidate_secret", "naming_pattern"]


@dataclass(frozen=True)
class AndroidExternalToolSignal:
    kind: SignalKind
    value: str
    location: str


@dataclass(frozen=True)
class AndroidExternalToolResult:
    tool_name: str
    available: bool
    executed: bool
    signals: tuple[AndroidExternalToolSignal, ...] = ()
    source_files_scanned: int = 0
    error: str | None = None
