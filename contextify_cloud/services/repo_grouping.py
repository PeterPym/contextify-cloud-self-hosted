"""Helpers for deriving stable cloud repo grouping identifiers."""

from __future__ import annotations

import hashlib


def normalize_repo_origin(repo_origin_normalized: str | None) -> str | None:
    """Canonicalize normalized origin strings before hashing or storage."""
    if repo_origin_normalized is None:
        return None

    trimmed = repo_origin_normalized.strip()
    if not trimmed:
        return None

    host, separator, raw_path = trimmed.partition("/")
    if not separator:
        return trimmed.lower()

    path = raw_path.strip()
    while path.startswith("/"):
        path = path[1:]
    while path.endswith("/"):
        path = path[:-1]
    if path.endswith(".git"):
        path = path[:-4]

    if not path:
        return host.lower() or None

    return f"{host.lower()}/{path}"


def derive_repo_group_key(
    repo_origin_normalized: str | None,
    repo_identity: str | None,
) -> str | None:
    """Derive the canonical grouping key used by cloud grouping queries."""
    normalized_origin = normalize_repo_origin(repo_origin_normalized)
    if normalized_origin:
        digest = hashlib.sha256(normalized_origin.encode("utf-8")).hexdigest()
        return f"repo-origin-sha256:{digest}"
    if repo_identity:
        return repo_identity
    return None


def canonical_repo_group_key(
    repo_group_key: str | None,
    repo_identity: str | None,
    repo_origin_normalized: str | None,
) -> str | None:
    """Prefer a server-derived key over a client-provided key when origin is known."""
    derived = derive_repo_group_key(repo_origin_normalized, repo_identity)
    if derived:
        return derived
    return repo_group_key or None
