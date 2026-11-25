"""ct-5545: account for every item a sync push did not store.

A push answers HTTP 200 even when it stores only part of the batch. This module
keeps one tally per (item kind, reason, retryable) so the handler can return an
explicit `rejections[]` summary and log one warning line per partially rejected
push. Nothing here sees entry content: categories carry counts and a bounded,
server-written detail string.
"""

import re
from dataclasses import dataclass, field
from typing import Literal

from contextify_cloud.schemas import SyncRejectionCategory

ItemKind = Literal[
    "entry", "transcript", "summary", "usage", "tool_invocation", "transcript_metadata"
]

# Mirrors the tenant schema CHECK on `{schema}.transcripts.provider`
# (services/tenant.py). A transcript outside this set cannot be stored, and
# neither can any entry or record that depends on it.
ACCEPTED_PROVIDERS: tuple[str, ...] = ("claude.code", "codex.cli", "other")

UNSUPPORTED_PROVIDER = "UNSUPPORTED_PROVIDER"

# Reasons that describe tenant configuration rather than a client or server
# fault. They are reported in `rejections[]` but alone do not warrant a warning.
POLICY_REASONS: frozenset[str] = frozenset({"ENTRY_POLICY_BLOCKED"})

_PROVIDER_SAFE = re.compile(r"[^A-Za-z0-9._-]")
_MAX_PROVIDER_LEN = 40
_MAX_PROVIDERS_SHOWN = 5


def sanitize_provider(value: object) -> str:
    """Return a log- and response-safe rendering of a client provider string."""
    text = _PROVIDER_SAFE.sub("?", str(value))
    if len(text) > _MAX_PROVIDER_LEN:
        text = text[:_MAX_PROVIDER_LEN] + "..."
    return text or "<empty>"


def unsupported_provider_detail(providers: set[str]) -> str:
    shown = sorted(sanitize_provider(p) for p in providers)
    extra = len(shown) - _MAX_PROVIDERS_SHOWN
    listed = ", ".join(repr(p) for p in shown[:_MAX_PROVIDERS_SHOWN])
    if extra > 0:
        listed += f" (+{extra} more)"
    return (
        f"provider not supported: {listed}; accepted: {', '.join(ACCEPTED_PROVIDERS)}"
    )


@dataclass
class RejectionTally:
    _counts: dict[tuple[ItemKind, str, bool], int] = field(default_factory=dict)
    _details: dict[tuple[ItemKind, str, bool], str] = field(default_factory=dict)

    def add(
        self,
        item_kind: ItemKind,
        reason_code: str,
        *,
        retryable: bool,
        count: int = 1,
        detail: str | None = None,
    ) -> None:
        if count <= 0:
            return
        key = (item_kind, reason_code, retryable)
        self._counts[key] = self._counts.get(key, 0) + count
        if detail and key not in self._details:
            self._details[key] = detail[:500]

    def categories(self) -> list[SyncRejectionCategory]:
        return [
            SyncRejectionCategory(
                item_kind=kind,
                reason_code=reason,
                count=count,
                retryable=retryable,
                detail=self._details.get((kind, reason, retryable)),
            )
            for (kind, reason, retryable), count in sorted(self._counts.items())
        ]

    def needs_warning(self) -> bool:
        return any(reason not in POLICY_REASONS for (_, reason, _) in self._counts)

    def log_summary(self) -> str:
        """One-line, content-free rendering for the server log."""
        parts = []
        for category in self.categories():
            kind = "retryable" if category.retryable else "permanent"
            # Counts and fixed reason codes only: client-supplied values such
            # as the provider string never reach the server log.
            parts.append(f"{category.item_kind}:{category.reason_code}={category.count} {kind}")
        return "; ".join(parts)
