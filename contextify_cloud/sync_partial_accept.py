"""Per-item partial-accept helper for FastAPI list-of-typed-items endpoints.

ct-1841 extracted this from `routers/sync.py` so the mechanics of per-item
validation are reusable beyond `entries`. The locked design plan (unit-6
external review) phases generalization in three steps:

    PR 1 (this module): entries-only, with helper extraction. <- here.
    PR 2: projects + transcripts (with dependency handling).
    PR 3: summaries + tool_invocations + transcript_metadata.
    PR 4 or separate: usage (or move to best-effort telemetry ingest).

The helper owns the "boring" mechanics that every item kind needs:

    - Pydantic `model_validate` with a try/except boundary
    - First-error extraction with safe `loc` and `pydantic_type` capping
    - SyncItemError construction (bounded `detail`, no raw `input` leak)
    - Item-id resolution from the raw dict
    - Routing the failure to a caller-provided Sentry capture

Each item kind keeps its own:

    - Stable error-code classifier (entry-specific codes today, e.g.
      `string_too_long -> ENTRY_TOO_LARGE`).
    - Counters, completion-state semantics, quarantine policy.
    - Materialization / sha checks (entries do this; others may not).
    - Insert / conflict-handling logic.

This is the boundary the unit-6 reviewer recommended: FastAPI keeps
protocol-level validation; Contextify owns item-level partial-accept
semantics, expressed as code that the sync handler calls explicitly
(rather than hidden in a decorator or middleware).
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, ValidationError
from starlette.requests import Request

from contextify_cloud.schemas import SyncItemError


@dataclass(frozen=True)
class PartialAcceptSpec[T: BaseModel]:
    """Description of how to validate one kind of payload item.

    `item_kind` is the literal that ends up in `SyncItemError.item_kind`.
    The current SyncItemError literal restricts this to the seven kinds in
    the schema; new kinds added in future phases must also be added to
    the Literal definition.

    `array_key` is the field name in the request body. Defaults to
    `f"{item_kind}s"` (the convention for projects/transcripts/summaries
    etc.) but must be overridden when the field is irregular -
    `item_kind="entry"` ships in the body as `"entries"`. Errors use this
    in `loc` so client tooling can resolve back to the request array.

    `classifier` maps a Pydantic `type` string ("string_too_long",
    "missing", etc.) to a stable client-facing error_code. Each item kind
    can have its own taxonomy; entries use the ENTRY_* codes today.

    `extract_item_id` plucks a stable id from the raw dict. Implementations
    should be defensive (return None for missing or non-string ids). The
    id is what the client uses to route into local quarantine state, so
    a precise extractor matters more than a precise type.

    `capture_validation_error` is the Sentry hook. Optional; tests pass
    None to suppress capture.
    """

    item_kind: str
    item_model: type[T]
    classifier: Callable[[str], str]
    extract_item_id: Callable[[Any], str | None]
    capture_validation_error: Callable[..., None] | None = None
    array_key: str | None = None  # defaults to item_kind + "s"


@dataclass
class PartialAcceptResult[T: BaseModel]:
    """Return value of `validate_items`.

    `valid_items` keeps the original list order (skipping rejected items).
    `item_errors` is in insertion order, one per rejected item, suitable
    for appending directly to `SyncPushResponse.item_errors`.
    `permanent_failed` mirrors the entry-counter convention so callers
    can fold it into `entries_permanent_failed` / equivalent counters.
    `raw_index_by_item_id` lets a caller cross-reference a server-side
    item-error back to the raw position when only the id is known.
    """

    valid_items: list[T] = field(default_factory=list)
    item_errors: list[SyncItemError] = field(default_factory=list)
    permanent_failed: int = 0
    raw_index_by_item_id: dict[str, int] = field(default_factory=dict)


def _first_pydantic_error(exc: ValidationError) -> dict[str, Any]:
    """Return the first Pydantic error as a plain dict, or {} when empty."""
    errs = exc.errors()
    if not errs:
        return {}
    # Pydantic v2 returns a list of ErrorDetails (TypedDict). Coerce to a
    # regular dict so downstream `.get(...)` works without type ignores.
    return dict(errs[0])


def _summarize_loc(loc: Any) -> str:
    if not loc:
        return ""
    try:
        return ".".join(str(part) for part in loc)
    except TypeError:
        return str(loc)


def validate_items[T: BaseModel](
    *,
    raw_items: Sequence[Any],
    spec: PartialAcceptSpec[T],
    request: Request | None = None,
) -> PartialAcceptResult[T]:
    """Validate `raw_items` against `spec.item_model`, isolating failures.

    Walks `raw_items` in order. Each one that's a dict is fed through
    `spec.item_model.model_validate`; on failure, the helper records a
    `SyncItemError` with the first Pydantic error's type/loc and a
    classifier-mapped `error_code`. On success the typed item lands in
    `valid_items`. Both lists keep their relative order.

    Non-dict raw items (None, lists, strings, ints) become an immediate
    `ENTRY_INVALID_FIELD`-style error with `pydantic_type='dict_type'`.

    Sentry capture is delegated to `spec.capture_validation_error`. The
    helper calls it once per rejected item, never with the raw `input`
    field. Caller-side privacy review of the capture body is therefore
    out of scope here.
    """
    result: PartialAcceptResult[T] = PartialAcceptResult()
    item_kind = spec.item_kind
    array_key = spec.array_key or f"{item_kind}s"

    for index, raw in enumerate(raw_items):
        if not isinstance(raw, dict):
            err = SyncItemError(
                item_kind=item_kind,  # type: ignore[arg-type]
                index=index,
                item_id=None,
                error_code=spec.classifier("dict_type"),
                retryable=False,
                detail=f"{item_kind} at index {index} is not a JSON object",
                pydantic_type="dict_type",
                loc=["body", array_key, index],
            )
            result.item_errors.append(err)
            result.permanent_failed += 1
            if spec.capture_validation_error and request is not None:
                spec.capture_validation_error(
                    request=request,
                    item_kind=item_kind,
                    item_id=None,
                    loc=_summarize_loc(err.loc),
                    pydantic_type="dict_type",
                    error_code=err.error_code,
                )
            continue

        candidate_id = spec.extract_item_id(raw)

        try:
            item = spec.item_model.model_validate(raw)
        except ValidationError as exc:
            first = _first_pydantic_error(exc)
            ptype = str(first.get("type", "validation_error"))
            loc_tuple = first.get("loc", ()) or ()
            err = SyncItemError(
                item_kind=item_kind,  # type: ignore[arg-type]
                index=index,
                item_id=candidate_id,
                error_code=spec.classifier(ptype),
                retryable=False,
                detail=(f"{ptype} at {_summarize_loc(loc_tuple)}")[:500],
                pydantic_type=ptype[:128],
                loc=["body", array_key, index, *list(loc_tuple)],
            )
            result.item_errors.append(err)
            result.permanent_failed += 1
            if spec.capture_validation_error and request is not None:
                spec.capture_validation_error(
                    request=request,
                    item_kind=item_kind,
                    item_id=candidate_id,
                    loc=_summarize_loc(err.loc),
                    pydantic_type=ptype,
                    error_code=err.error_code,
                )
            continue

        result.valid_items.append(item)
        # Best-effort id->index map. If two items share an id only the
        # first is recorded; that matches the server's de-dup-by-id
        # semantics for entries.
        item_id = candidate_id
        if isinstance(item_id, str) and item_id and item_id not in result.raw_index_by_item_id:
            result.raw_index_by_item_id[item_id] = index

    return result
