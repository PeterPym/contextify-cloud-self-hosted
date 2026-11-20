"""ct-5459 (Slice 3): versioned, source-qualified repository evidence.

Each push records, per lane (the client's project id as pushed), pushing
device and uploader, the repository keys the client attested under a
versioned normalizer. Pushes without usable evidence (1.8.x clients,
synthetic or folder lanes) record a *legacy* tuple.

Provenance is per entry and immutable: an entry records its source lane only
when the push that inserted it carried usable versioned evidence for that
lane. Pull reports each referenced lane's state, so a client verifies pulled
history only when every entry was pushed under a matching versioned key and
the lane's evidence is consistent.

Wire contract: /tmp/slice3-4/wire-contract.md (rev 1). Key version 1 is the
client's ``LocalRepoIdentity`` (forge-only origin folding; device- and
incarnation-qualified common-dir keys). The server never re-normalizes a
versioned key; it validates the format and stores it.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from contextify_cloud.schemas import LaneRepoEvidence

SUPPORTED_KEY_VERSIONS = frozenset({1})

ORIGIN_KEY_RE = re.compile(r"^repo-origin-sha256:[0-9a-f]{64}$")
# Device segment: printable ASCII without ':' (0x21-0x39, 0x3B-0x7E).
COMMON_DIR_KEY_RE = re.compile(r"^git-common-dir:[!-9;-~]{1,128}:[0-9a-f]{64}:[0-9a-f]{64}$")

_MAX_ROOT_LEN = 4096


@dataclass(frozen=True)
class ValidEvidence:
    key_version: int
    origin_key: str | None
    common_dir_key: str | None
    checkout_root: str | None

    @property
    def merge_key(self) -> str:
        """Origin key when present, else the device-qualified common-dir key."""
        key = self.origin_key or self.common_dir_key
        assert key is not None  # guaranteed by validate_evidence
        return key


def validate_evidence(raw: Any) -> ValidEvidence | None:
    """Return usable versioned evidence, or None (legacy semantics apply).

    ``raw`` is the untyped wire value, so every field is type-checked here.
    """
    if not isinstance(raw, dict):
        return None
    version = raw.get("key_version")
    if isinstance(version, bool) or not isinstance(version, int):
        return None
    if version not in SUPPORTED_KEY_VERSIONS:
        return None
    origin = raw.get("origin_key")
    common = raw.get("common_dir_key")
    root = raw.get("checkout_root")
    for value in (origin, common, root):
        if value is not None and not isinstance(value, str):
            return None
    origin = origin or None
    common = common or None
    root = root or None
    if origin is not None and not ORIGIN_KEY_RE.fullmatch(origin):
        return None
    if common is not None and not COMMON_DIR_KEY_RE.fullmatch(common):
        return None
    if origin is None and common is None:
        return None
    if root is not None and (len(root) > _MAX_ROOT_LEN or "\x00" in root):
        return None
    return ValidEvidence(version, origin, common, root)


@dataclass(frozen=True)
class EvidenceRecord:
    """One evidence observation from one project in one push."""

    project_id: str  # canonical server row the lane's data landed in
    source_project_id: str  # client lane id as pushed (before remap)
    source_machine_id: str
    device_id: str | None
    user_id: str
    evidence: ValidEvidence | None
    legacy_repo_group_key: str | None
    lane_root: str | None

    def fields(self) -> dict[str, Any]:
        ev = self.evidence
        return {
            "key_version": ev.key_version if ev else None,
            "origin_key": ev.origin_key if ev else None,
            "common_dir_key": ev.common_dir_key if ev else None,
            # A versioned tuple's identity is its keys; the legacy key is only
            # recorded (and hashed) for legacy tuples.
            "legacy_repo_group_key": None if ev else self.legacy_repo_group_key,
            "checkout_root": ev.checkout_root if ev else None,
            "lane_root": self.lane_root,
        }

    def evidence_hash(self) -> str:
        payload = json.dumps(self.fields(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


async def record_evidence(
    db: AsyncSession, schema: str, records: list[EvidenceRecord], now_epoch: int
) -> None:
    """Upsert evidence tuples. ``schema`` must already be validated."""
    for rec in records:
        fields = rec.fields()
        # Separate nextval so first_seq and last_seq share one value without
        # relying on expression evaluation order.
        seq = (await db.execute(text(f"SELECT nextval('{schema}.repo_evidence_seq')"))).scalar()
        await db.execute(
            text(f"""
            INSERT INTO {schema}.repo_evidence (
                source_project_id, source_machine_id, evidence_hash, project_id,
                device_id, uploaded_by_user_id, key_version, origin_key,
                common_dir_key, legacy_repo_group_key, lane_root, checkout_root,
                first_seq, last_seq, first_seen_at, last_seen_at
            )
            VALUES (
                :source_project_id, :source_machine_id, :evidence_hash, :project_id,
                :device_id, :user_id, :key_version, :origin_key, :common_dir_key,
                :legacy_repo_group_key, :lane_root, :checkout_root,
                :seq, :seq, :now, :now
            )
            ON CONFLICT (source_project_id, source_machine_id, uploaded_by_user_id, evidence_hash)
            DO UPDATE SET
                project_id = EXCLUDED.project_id,
                device_id = COALESCE(EXCLUDED.device_id, {schema}.repo_evidence.device_id),
                last_seq = EXCLUDED.last_seq,
                last_seen_at = EXCLUDED.last_seen_at
            """),
            {
                **fields,
                "source_project_id": rec.source_project_id,
                "source_machine_id": rec.source_machine_id,
                "evidence_hash": rec.evidence_hash(),
                "project_id": rec.project_id,
                "device_id": rec.device_id,
                "user_id": rec.user_id,
                "seq": seq,
                "now": now_epoch,
            },
        )


def lane_subpath(lane_root: str | None, checkout_root: str | None) -> str | None:
    """Lane root relative to the checkout root, when it is at or below it."""
    if not lane_root or not checkout_root:
        return None
    root = checkout_root.rstrip("/\\")
    if lane_root.rstrip("/\\") == root:
        return ""
    for sep in ("/", "\\"):
        prefix = root + sep
        if lane_root.startswith(prefix):
            return lane_root[len(prefix) :].rstrip("/\\")
    return None


LaneKey = tuple[str, str, str]  # (source lane id, source machine id, uploader user id)


def evaluate_lane(rows: list[Any], lane: LaneKey) -> LaneRepoEvidence:
    """Compute the evidence state of one (lane, device, uploader).

    - no tuples -> unattested
    - only legacy tuples -> legacy
    - >1 distinct versioned key tuple, or any legacy tuple seen after the
      lane's first versioned tuple -> conflict
    - otherwise -> verified with the single versioned key tuple
    Entries pushed without versioned evidence never carry a source lane, so a
    legacy tuple from before the lane's first versioned push cannot make any
    attributed entry verifiable; it is reported but does not block.
    """
    base: dict[str, Any] = {
        "source_lane_id": lane[0],
        "source_device_id": lane[1],
        "uploaded_by_user_id": lane[2],
    }
    if not rows:
        return LaneRepoEvidence(state="unattested", **base)
    latest = max(rows, key=lambda r: r.last_seq)
    legacy = [r for r in rows if r.key_version is None]
    versioned = [r for r in rows if r.key_version is not None]
    latest_legacy = max(legacy, key=lambda r: r.last_seq) if legacy else None
    latest_versioned = max(versioned, key=lambda r: r.last_seq) if versioned else None
    base.update(
        lane_root=latest.lane_root,
        checkout_root=latest_versioned.checkout_root if latest_versioned else None,
        legacy_repo_group_key=latest_legacy.legacy_repo_group_key if latest_legacy else None,
    )
    base["lane_subpath"] = lane_subpath(base["lane_root"], base["checkout_root"])
    if not versioned:
        return LaneRepoEvidence(state="legacy", **base)
    first_versioned = min(r.first_seq for r in versioned)
    if any(r.last_seq > first_versioned for r in legacy):
        return LaneRepoEvidence(state="conflict", **base)
    keys = {(r.key_version, r.origin_key, r.common_dir_key) for r in versioned}
    if len(keys) != 1:
        return LaneRepoEvidence(state="conflict", **base)
    key_version, origin_key, common_dir_key = next(iter(keys))
    return LaneRepoEvidence(
        state="verified",
        key_version=key_version,
        origin_key=origin_key,
        common_dir_key=common_dir_key,
        **base,
    )


async def lane_evidence(
    db: AsyncSession, schema: str, lanes: list[LaneKey]
) -> list[LaneRepoEvidence]:
    """Evidence for each (lane, machine, uploader), in input order, deduplicated.

    Callers must pass only lanes the caller may see (user scope).
    """
    unique = list(dict.fromkeys(lanes))
    if not unique:
        return []
    ev_result = await db.execute(
        text(f"""
        SELECT ev.source_project_id, ev.source_machine_id, ev.uploaded_by_user_id,
               ev.key_version, ev.origin_key, ev.common_dir_key,
               ev.legacy_repo_group_key, ev.lane_root, ev.checkout_root,
               ev.first_seq, ev.last_seq
        FROM {schema}.repo_evidence ev
        WHERE ev.source_project_id = ANY(:lanes)
        """),
        {"lanes": sorted({lane[0] for lane in unique})},
    )
    grouped: dict[LaneKey, list[Any]] = {}
    for ev in ev_result.fetchall():
        key = (ev.source_project_id, ev.source_machine_id, str(ev.uploaded_by_user_id))
        grouped.setdefault(key, []).append(ev)
    return [evaluate_lane(grouped.get(lane, []), lane) for lane in unique]


async def project_repo_info(
    db: AsyncSession,
    schema: str,
    project_ids: list[str],
    scope_clause: str,
    scope_params: dict[str, str],
    caller_user_id: str,
) -> dict[str, dict[str, Any]]:
    """repo_group_key, canonical_project_id and visible versioned keys per row.

    ``scope_clause`` comes from ``build_user_scope_clause(auth, column=
    "ev.uploaded_by_user_id")`` so members only aggregate their own evidence.
    """
    if not project_ids:
        return {}
    info: dict[str, dict[str, Any]] = {}
    proj_result = await db.execute(
        text(f"""
        SELECT p.id, p.repo_group_key,
               COALESCE((
                   SELECT c.id FROM {schema}.projects c
                   WHERE p.repo_group_key IS NOT NULL
                     AND c.repo_group_key = p.repo_group_key
                   ORDER BY c.created_at ASC, c.id ASC
                   LIMIT 1
               ), p.id) AS canonical_id
        FROM {schema}.projects p
        WHERE p.id = ANY(:ids)
        """),
        {"ids": project_ids},
    )
    for row in proj_result.fetchall():
        info[row.id] = {
            "repo_group_key": row.repo_group_key,
            "canonical_project_id": row.canonical_id,
            "repo_keys": [],
            "shared_by_caller": False,
        }
    if info:
        # ct-5461: only the caller's own share rows; never another user's.
        shares = await db.execute(
            text(f"""
            SELECT project_id FROM {schema}.project_team_shares
            WHERE user_id = :caller AND project_id = ANY(:ids)
            """),
            {"caller": caller_user_id, "ids": list(info)},
        )
        for row in shares.fetchall():
            if row.project_id in info:
                info[row.project_id]["shared_by_caller"] = True
    keys_result = await db.execute(
        text(f"""
        SELECT DISTINCT ev.project_id, ev.key_version, ev.origin_key, ev.common_dir_key
        FROM {schema}.repo_evidence ev
        WHERE ev.project_id = ANY(:ids)
          AND ev.key_version IS NOT NULL
          {scope_clause}
        ORDER BY ev.project_id, ev.key_version, ev.origin_key, ev.common_dir_key
        """),
        {"ids": project_ids, **scope_params},
    )
    key_rows = [r for r in keys_result.fetchall() if r.project_id in info]
    merge_keys = sorted({r.origin_key or r.common_dir_key for r in key_rows})
    canonical_by_key: dict[str, str] = {}
    if merge_keys:
        canon_result = await db.execute(
            text(f"""
            SELECT DISTINCT ON (repo_group_key) repo_group_key, id
            FROM {schema}.projects
            WHERE repo_group_key = ANY(:keys)
            ORDER BY repo_group_key, created_at ASC, id ASC
            """),
            {"keys": merge_keys},
        )
        canonical_by_key = {r.repo_group_key: r.id for r in canon_result.fetchall()}
    for row in key_rows:
        info[row.project_id]["repo_keys"].append(
            {
                "key_version": row.key_version,
                "origin_key": row.origin_key,
                "common_dir_key": row.common_dir_key,
                "canonical_project_id": canonical_by_key.get(
                    row.origin_key or row.common_dir_key
                ),
            }
        )
    return info
