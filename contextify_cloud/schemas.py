"""Pydantic request/response models for the API."""

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, EmailStr, Field, model_validator

# --- Auth ---

class RegisterRequest(BaseModel):
    email: str
    name: str
    team_name: str


class RegisterResponse(BaseModel):
    tenant_id: uuid.UUID
    user_id: uuid.UUID
    api_key: str  # Full key, shown only once
    api_key_prefix: str


class ApiKeyCreate(BaseModel):
    name: str = "Default"
    scopes: list[str] = Field(default_factory=lambda: ["sync", "search"])


class ApiKeyResponse(BaseModel):
    id: uuid.UUID
    key_prefix: str
    name: str
    scopes: list[str]
    created_at: datetime
    last_used_at: datetime | None = None


class BrowserHandoffRequest(BaseModel):
    target_path: str = Field(default="/cloud/sync", max_length=512)
    device_id: str | None = Field(default=None, max_length=128)
    device_name: str | None = Field(default=None, max_length=255)


class BrowserHandoffResponse(BaseModel):
    handoff_url: str
    expires_at: datetime
    email: EmailStr
    tenant_name: str
    target_path: str


# --- Sync ---

class DeviceInfo(BaseModel):
    machine_id: str
    machine_name: str
    os: str | None = None
    app_version: str | None = None


class SyncProject(BaseModel):
    id: str
    name: str | None = None
    root_path: str
    repo_group_key: str | None = None
    repo_identity: str | None = None
    repo_origin_normalized: str | None = None
    git_common_dir: str | None = None
    is_worktree: bool = False
    default_branch: str | None = None
    vcs_provider: str | None = None
    worktree_name: str | None = None
    repo_name: str | None = None


class SyncTranscript(BaseModel):
    id: str
    project_id: str
    file_path: str
    provider: str
    provider_session_id: str | None = None
    line_count: int = 0
    created_at: int
    updated_at: int


_PER_CHUNK_BYTE_CAP = 1_000_000  # 1 MB UTF-8 bytes per chunk
_MAX_CHUNKS_PER_ENTRY = 40        # 40 * 900 KB ~= 36 MB, below 50 MB body cap


class SyncEntry(BaseModel):
    id: str
    transcript_id: str
    project_id: str
    session_id: str | None = None
    provider: str
    kind: str = Field(..., pattern=r"^(user|assistant|system|summary)$")
    timestamp: int
    # ct-1841: content may be sent inline (`content`) or split into
    # `content_chunks` for entries that exceed the per-chunk byte cap. Exactly
    # one of the two fields must be set. The handler materializes chunks into
    # a single TEXT row before INSERT and verifies content_sha256 against the
    # materialized bytes. All limits are enforced as UTF-8 byte counts, not
    # character counts.
    content: str | None = Field(default=None)
    content_chunks: list[str] | None = Field(default=None, max_length=_MAX_CHUNKS_PER_ENTRY)
    content_sha256: str = Field(
        ..., min_length=64, max_length=64,
    )  # SHA-256 = 64 hex chars
    display_in_timeline: bool = True
    git_branch: str | None = None
    git_commit: str | None = None
    cwd: str | None = None
    # Per-entry device provenance from the originating machine.
    # Preferred over request-level device info (which is the *uploader*, not
    # necessarily the *originator* -- they differ after DB copy/restore).
    source_device_id: str | None = None
    source_device_name: str | None = None
    created_at: int
    updated_at: int

    @model_validator(mode="after")
    def _content_xor_chunks(self) -> "SyncEntry":
        # Exactly one of content / content_chunks must be set. This keeps the
        # wire format unambiguous and lets the handler decide how to materialize.
        # Per-chunk byte caps live here (defensive); per-entry materialized
        # ceiling lives in the push handler so it can be enforced after
        # reassembly and surfaced as ENTRY_TOO_LARGE in item_errors.
        has_content = self.content is not None
        has_chunks = self.content_chunks is not None
        if has_content == has_chunks:
            raise ValueError(
                "exactly one of `content` or `content_chunks` must be set"
            )
        if has_chunks:
            assert self.content_chunks is not None  # narrowing
            for i, chunk in enumerate(self.content_chunks):
                if len(chunk.encode("utf-8")) > _PER_CHUNK_BYTE_CAP:
                    raise ValueError(
                        f"`content_chunks[{i}]` exceeds 1 MB UTF-8 bytes"
                    )
        return self

    def materialized_content(self) -> str:
        """Return the single logical content string, joining chunks if needed."""
        if self.content is not None:
            return self.content
        return "".join(self.content_chunks or [])


class SyncSummary(BaseModel):
    entry_id: str
    content_sha256: str
    window_sha256: str
    present_form: str
    past_form: str
    disposition: str | None = None
    generated_at: int


class SyncUsage(BaseModel):
    entry_id: str
    request_id: str
    model: str
    input_tokens: int
    output_tokens: int
    cache_creation_tokens: int = 0
    cache_read_tokens: int = 0


class SyncToolInvocation(BaseModel):
    id: str
    entry_id: str
    transcript_id: str
    tool_name: str
    tool_key: str | None = None
    status: str = "unknown"
    started_at: int | None = None
    completed_at: int | None = None
    metadata_json: dict[str, object] | None = None
    created_at: int
    updated_at: int


class SyncTranscriptMetadata(BaseModel):
    transcript_id: str
    project_id: str
    title: str
    description: str | None = None
    topics: list[str] = Field(default_factory=list)
    confidence: float
    generated_at: int
    model: str
    created_at: int
    updated_at: int


class SyncPushRequest(BaseModel):
    """Push request for syncing local data to cloud.

    idempotency_key: Optional client-generated key to prevent duplicate processing.
    If provided, the server will return the cached response for a previously
    processed request with the same key, rather than re-processing the batch.
    This is critical for robustness with intermittent connectivity.

    batch_seq: Optional sequence number for ordered multi-batch uploads.
    The client should increment this for each batch in a sync session.

    sync_session_id: Optional session ID for resuming a multi-batch upload.
    On the first push of a session, omit this field and the server will create
    a new session and return its ID. On subsequent pushes, include the returned
    session ID to track batch progress within the same session.
    """

    idempotency_key: str | None = Field(
        None,
        max_length=128,
        description="Client-generated UUID to prevent duplicate batch processing",
    )
    batch_seq: int | None = Field(
        None, ge=0,
        description="Sequence number within a multi-batch sync session",
    )
    sync_session_id: str | None = Field(
        None,
        description="Server-generated session ID for multi-batch resume",
    )
    entries_sent: int | None = Field(
        None, ge=0,
        description="Optional client-declared entries count for sanity checks",
    )
    total_batches: int | None = Field(
        None, ge=0,
        description="Client-estimated total batches for the push session",
    )
    device: DeviceInfo
    projects: list[SyncProject] = Field(default_factory=list)
    transcripts: list[SyncTranscript] = Field(default_factory=list)
    # ct-1841: entries arrive as raw dicts at the envelope so a single bad
    # entry never 422s the whole batch. The push handler validates each entry
    # with SyncEntry.model_validate inside a per-entry try/except, routing
    # failures into structured item_errors with stable error_codes. Other
    # arrays remain typed because downstream handler code reads typed
    # attributes (summary.entry_id, usage.request_id, etc.).
    entries: list[dict[str, Any]] = Field(default_factory=list)
    summaries: list[SyncSummary] = Field(default_factory=list)
    usage: list[SyncUsage] = Field(default_factory=list)
    tool_invocations: list[SyncToolInvocation] = Field(default_factory=list)
    transcript_metadata: list[SyncTranscriptMetadata] = Field(default_factory=list)


class SyncItemError(BaseModel):
    """Per-item error for ct-1841 partial-accept.

    The push handler emits one entry per failed item (entry, summary, usage,
    tool_invocation, transcript_metadata) instead of poisoning the whole batch.
    Clients route on `retryable` regardless of whether they recognize the
    `error_code`, so the contract stays forward-compatible.

    Detail and pydantic_type are bounded so a pathological validation message
    cannot create a large response or leak content-like values. The server
    must construct `detail` from type + loc + sanitized constraint summary -
    never raw user content from Pydantic `input`.
    """

    item_kind: Literal[
        "entry", "summary", "usage", "tool_invocation", "transcript_metadata"
    ]
    index: int | None = None
    item_id: str | None = None
    error_code: str
    retryable: bool
    detail: str | None = Field(default=None, max_length=500)
    pydantic_type: str | None = Field(default=None, max_length=128)
    loc: list[str | int] = Field(default_factory=list)


class SyncPushResponse(BaseModel):
    accepted: int
    duplicates_skipped: int
    errors: list[str] = Field(default_factory=list)
    sync_token: str | None = None
    idempotency_key: str | None = None  # Echoed back for client correlation
    sync_session_id: str | None = None  # Server-managed session ID for multi-batch tracking
    batch_seq: int | None = None
    entries_sent: int = 0
    entries_accepted: int = 0
    entries_duplicates: int = 0
    entries_conflicted: int = 0
    entries_blocked_policy: int = 0
    entries_permanent_failed: int = 0  # ct-1841: split from retriable
    entries_retriable_failed: int = 0
    entries_resolved: int = 0
    checkpoint_safe: bool = False
    completion_state: Literal[
        "in_progress", "success", "completed_with_issues", "blocked"
    ] = "in_progress"
    needs_attention_count: int = 0
    error_codes: list[str] = Field(default_factory=list)
    # ct-1841: structured per-item errors. Uncapped by count so clients can
    # quarantine every failed entry. `errors[]` above remains the legacy
    # human-readable summary, still capped at 10.
    item_errors: list[SyncItemError] = Field(default_factory=list)
    server_sequence: int = 0
    project_id_remapped: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Map of client project IDs that were remapped to canonical server IDs "
            "via repo_group_key deduplication. Key = client ID, value = canonical ID."
        ),
    )


class ActivePushSessionStatus(BaseModel):
    sync_session_id: str
    phase: str = "initial_upload"
    entries_resolved: int | None = None
    entries_total: int | None = None
    progress_percent: float | None = None
    throughput_entries_per_min: float | None = None
    eta_seconds: int | None = None
    checkpoint_safe: bool | None = None
    completion_state: Literal[
        "in_progress", "success", "completed_with_issues", "blocked"
    ] = "in_progress"
    needs_attention_count: int = 0
    last_batch_at: datetime | None = None


class SyncStatusResponse(BaseModel):
    last_sync: datetime | None = None
    entries_synced: int = 0
    devices: list[DeviceInfo] = Field(default_factory=list)
    server_sequence: int = 0
    pending_batches: int = 0  # Count of in-progress sync sessions
    active_push_session: ActivePushSessionStatus | None = None


# --- Sync Pull ---

class PullEntry(BaseModel):
    """An entry returned from the pull endpoint."""
    id: str
    transcript_id: str
    project_id: str
    session_id: str | None = None
    provider: str
    kind: str = Field(..., pattern=r"^(user|assistant|system|summary)$")
    timestamp: int
    # ct-1841: cap removed so reassembled large content can round-trip back to
    # clients. The push handler already enforces a materialized byte ceiling
    # before insert, so unbounded values cannot reach the DB.
    content: str
    content_sha256: str = Field(..., min_length=64, max_length=64)
    display_in_timeline: bool = True
    git_branch: str | None = None
    git_commit: str | None = None
    cwd: str | None = None
    uploaded_by_user_id: str
    uploaded_by_device_id: str | None = None
    uploaded_by_device_name: str | None = None
    server_sequence: int = Field(..., ge=1)
    created_at: int
    updated_at: int


class PullProject(BaseModel):
    id: str
    name: str | None = None
    root_path: str


class PullTranscript(BaseModel):
    id: str
    project_id: str
    file_path: str
    provider: str


class PullSummary(BaseModel):
    entry_id: str
    present_form: str
    past_form: str
    disposition: str | None = None


class SyncPullResponse(BaseModel):
    entries: list[PullEntry]
    projects: list[PullProject] = Field(default_factory=list)
    transcripts: list[PullTranscript] = Field(default_factory=list)
    summaries: list[PullSummary] = Field(default_factory=list)
    has_more: bool = False
    next_cursor: int = 0
    server_sequence: int = 0


# --- Search ---

class SearchResult(BaseModel):
    """Individual search result with relevance scoring and highlighted snippet."""

    entry_id: str
    kind: str
    timestamp: int
    project_id: str
    transcript_id: str | None = None
    snippet: str  # ts_headline highlighted excerpt
    score: float  # ts_rank_cd relevance score
    content: str | None = None  # Full content (truncated), for clients that need it
    project_name: str | None = None
    user_name: str | None = None
    user_email: str | None = None
    transcript_title: str | None = None
    # ct-2250: True when the caller uploaded this entry. The server is authoritative on
    # own-vs-teammate (the client cannot derive "self" from its transport-only config), so
    # clients label provenance off this flag rather than guessing from the presence of a
    # user_name (the team-widened response carries the caller's OWN rows too).
    is_own: bool = False


class SearchResponse(BaseModel):
    """Paginated search response with total count and timing."""

    results: list[SearchResult]
    total_count: int
    limit: int
    offset: int
    has_more: bool
    query_ms: float


# --- Projects ---


class ProjectSummary(BaseModel):
    """Project with aggregate stats for the list endpoint."""

    id: str
    name: str | None = None
    root_path: str
    transcript_count: int = 0
    entry_count: int = 0
    last_activity: int | None = None  # epoch timestamp of most recent entry


class ProjectDetail(BaseModel):
    """Project with detailed stats for the detail endpoint."""

    id: str
    name: str | None = None
    root_path: str
    transcript_count: int = 0
    entry_count: int = 0
    last_activity: int | None = None
    providers: list[str] = Field(default_factory=list)


class ProjectActivityEntry(BaseModel):
    """A single activity entry within a project."""

    id: str
    kind: str
    timestamp: int
    content_snippet: str  # First 200 chars of content
    transcript_id: str


class ProjectActivityResponse(BaseModel):
    """Paginated response for project activity."""

    entries: list[ProjectActivityEntry]
    total_count: int
    has_more: bool = False


class ProjectShareRequest(BaseModel):
    """Toggle a project's team-read share state (ct-2250)."""

    shared: bool


class ProjectShareResponse(BaseModel):
    """Result of a share toggle: the project's authoritative new share state."""

    project_id: str
    shared_with_team: bool


# --- Billing ---


class CheckoutRequest(BaseModel):
    """Request to create a Stripe Checkout session."""

    price_id: str = Field(..., description="Stripe price ID for the plan")
    success_url: str = Field(..., description="URL to redirect after successful payment")
    cancel_url: str = Field(..., description="URL to redirect if checkout is cancelled")


class CheckoutResponse(BaseModel):
    """Response with the Stripe Checkout session URL."""

    checkout_url: str


class LocalCommercialCheckoutRequest(BaseModel):
    """Request for the account-optional Local Commercial checkout (ct-1966)."""

    price_id: str = Field(..., description="Stripe price ID for a Local Commercial plan")
    success_url: str = Field(..., description="URL to redirect after successful payment")
    cancel_url: str = Field(..., description="URL to redirect if checkout is cancelled")
    customer_email: str | None = Field(
        None,
        description="Buyer email for an anonymous purchase (ignored when logged in)",
    )


class PortalResponse(BaseModel):
    """Response with the Stripe Customer Portal URL."""

    portal_url: str


SubscriptionStatus = Literal[
    "trialing",
    "active",
    "past_due",
    "unpaid",
    "canceled",
    "archived",
    "incomplete",
    "incomplete_expired",
    "paused",
]
BillingInterval = Literal["month", "year"]


class SubscriptionResponse(BaseModel):
    """Current subscription details for a tenant."""

    plan: str
    billing_interval: BillingInterval = "month"
    subscription_status: SubscriptionStatus
    max_seats: int
    current_seat_count: int
    stripe_subscription_id: str | None = None
    current_period_start: datetime | None = None
    current_period_end: datetime | None = None
    cancel_at_period_end: bool = False


class ModifySubscriptionRequest(BaseModel):
    """Request to modify a subscription's plan or quantity."""

    price_id: str | None = None
    quantity: int | None = Field(default=None, ge=1)


class ModifySubscriptionResponse(BaseModel):
    """Response after a successful subscription modification."""

    status: Literal["updated"] = "updated"
    plan: str
    billing_interval: BillingInterval = "month"
    subscription_status: SubscriptionStatus
    max_seats: int
    cancel_at_period_end: bool = False
    current_period_start: datetime | None = None
    current_period_end: datetime | None = None


class CancelSubscriptionResponse(BaseModel):
    """Cancellation/reactivation response."""

    status: Literal["cancel_scheduled", "reactivated"]
    cancel_at_period_end: bool
    current_period_end: datetime | None = None


# --- Invitations ---


class CreateInvitationRequest(BaseModel):
    """Request to invite a user to the tenant."""

    email: EmailStr = Field(..., description="Email address of the person to invite")
    role: str = Field(
        default="member",
        pattern=r"^(admin|member|viewer)$",
        description="Role to assign (admin, member, or viewer)",
    )


class InvitationResponse(BaseModel):
    """Public representation of an invitation."""

    id: uuid.UUID
    email: str
    role: str
    status: str
    created_at: datetime
    expires_at: datetime
    seat_warning: str | None = None


class AcceptInvitationRequest(BaseModel):
    """Request body for accepting an invitation."""

    password: str = Field(..., min_length=10)
    name: str | None = Field(default=None, max_length=255)


class AcceptInvitationResponse(BaseModel):
    """Response when accepting an invitation and creating a browser session."""

    user_id: uuid.UUID
    tenant_id: uuid.UUID
    email: str
    role: str
    redirect_url: str = "/cloud/"


class InvitationListResponse(BaseModel):
    """List of invitations for a tenant."""

    items: list[InvitationResponse]


# --- Audit Log ---


class AuditLogEntry(BaseModel):
    """A single audit log entry."""

    id: int
    tenant_id: uuid.UUID
    user_id: uuid.UUID | None = None
    action: str
    resource_type: str
    resource_id: str | None = None
    detail: dict[str, object] | None = None
    ip_address: str | None = None
    created_at: datetime


class AuditLogResponse(BaseModel):
    """Paginated audit log response."""

    items: list[AuditLogEntry]
    total_count: int
    page: int
    per_page: int
    has_more: bool


class AdminEmailTestRequest(BaseModel):
    """Request to fire a transactional email template to a chosen address."""

    template: Literal[
        "welcome",
        "email_verification",
        "password_reset",
        "email_change",
        "invitation",
    ] = Field(..., description="Production template to fire.")
    to_email: EmailStr = Field(
        ...,
        description="Recipient (does not have to be a real Contextify user).",
    )
    name: str | None = Field(
        default=None,
        max_length=200,
        description="Display name for templates that personalize (welcome, invitation).",
    )


class AdminEmailTestResponse(BaseModel):
    """Result of a fire-test-template send."""

    sent: bool
    template: str
    to: str
    auth_token_id: uuid.UUID | None = None
    invitation_id: uuid.UUID | None = None


# --- Team API ---


class TeamMember(BaseModel):
    """A team member returned from the team API."""

    id: uuid.UUID
    email: str
    name: str | None = None
    role: str
    created_at: datetime
    removed_at: datetime | None = None


class TeamMembersResponse(BaseModel):
    """List of team members."""

    items: list[TeamMember]


class RoleUpdateRequest(BaseModel):
    """Request to change a team member's role."""

    role: str = Field(
        ...,
        pattern=r"^(owner|admin|member|viewer)$",
        description="New role (owner, admin, member, or viewer)",
    )


class InviteRequest(BaseModel):
    """Request to invite a user to the team via API."""

    email: EmailStr = Field(..., description="Email address of the person to invite")
    role: str = Field(
        default="member",
        pattern=r"^(admin|member|viewer)$",
        description="Role to assign (admin, member, or viewer)",
    )


class TeamUsageEntry(BaseModel):
    """Per-user sync usage statistics."""

    user_id: str | None = None
    email: str | None = None
    name: str | None = None
    entry_count: int
    last_sync_at: int | None = None


class TeamUsageResponse(BaseModel):
    """List of per-user usage stats."""

    items: list[TeamUsageEntry]


class TeamActivityEntry(BaseModel):
    """A single activity feed entry."""

    id: str
    user_id: str | None = None
    user_email: str | None = None
    user_name: str | None = None
    action: str
    project_name: str | None = None
    detail: str | None = None
    created_at: int


class TeamActivityResponse(BaseModel):
    """Paginated team activity response."""

    items: list[TeamActivityEntry]
    total_count: int
    page: int
    per_page: int
    has_more: bool


# --- Health ---

class HealthResponse(BaseModel):
    status: str = "ok"
    self_hosted: bool = False


# --- Auth (Login / Key Management) ---


class LoginRequest(BaseModel):
    email: EmailStr
    api_key: str = Field(..., description="Full API key (ctx_keyid_secret)")


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: uuid.UUID
    tenant_id: uuid.UUID
    role: str


class ApiKeyUpdateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)


class ApiKeyRotateResponse(BaseModel):
    api_key: str  # Full key, shown only once
    api_key_prefix: str
    id: uuid.UUID
    name: str
    scopes: list[str]
    created_at: datetime


# --- Account ---


class AccountResponse(BaseModel):
    user_id: uuid.UUID
    email: str
    name: str | None = None
    role: str
    tenant_id: uuid.UUID
    tenant_name: str
    tenant_plan: str
    effective_history_retention_days: int = 0
    effective_history_retention_minimum_timestamp: int | None = None
    created_at: datetime


class AccountUpdateRequest(BaseModel):
    name: str | None = Field(None, max_length=200)


class AccountExportResponse(BaseModel):
    user: dict[str, Any]  # user profile
    api_keys: list[dict[str, Any]]  # keys without secrets
    entry_count: int
    audit_events: list[dict[str, Any]]


# --- Projects (Contributors) ---


class ProjectContributor(BaseModel):
    user_id: str
    email: str | None = None
    name: str | None = None
    role: str | None = None
    entry_count: int
    last_contribution: int | None = None


class ProjectContributorsResponse(BaseModel):
    items: list[ProjectContributor]


# --- Admin (Tenant Stats) ---


class TenantStatsResponse(BaseModel):
    tenant_id: uuid.UUID
    name: str
    plan: str
    subscription_status: str | None = None
    is_internal: bool = False
    member_count: int
    project_count: int
    entry_count: int
    created_at: datetime


# --- Analytics REST ---


class AnalyticsSummaryResponse(BaseModel):
    """Summary statistics for the analytics endpoint."""

    total_entries: int
    total_projects: int
    total_transcripts: int
    active_users_30d: int


class DailyVolumeEntry(BaseModel):
    """A single day's entry count."""

    date: str  # YYYY-MM-DD
    count: int


class DailyVolumeResponse(BaseModel):
    """Daily volume entries over a time period."""

    items: list[DailyVolumeEntry]
    days: int


# --- Admin Settings REST ---


class AdminSettingsResponse(BaseModel):
    """Admin settings for the REST API."""

    retention_days: int
    project_allowlist: list[str] | None
    plan: str


class AdminSettingsUpdateRequest(BaseModel):
    """Request to update admin settings.

    Both fields are optional. Only fields present in the request body
    will be updated. Use ``model_fields_set`` to check which fields
    were actually sent by the client.
    """

    retention_days: int | None = None
    project_allowlist: list[str] | None = None


# --- Device Flow Auth (RFC 8628) ---


class DeviceCodeRequest(BaseModel):
    """Request to initiate device flow authorization."""

    client_name: str | None = Field(None, max_length=100)


class DeviceCodeResponse(BaseModel):
    """Response with codes for device flow authorization."""

    device_code: str  # Opaque, CLI uses this to poll
    user_code: str  # Human-readable, user types this in browser
    verification_uri: str  # Bare URL — for "type the code manually" UX
    # Per RFC 8628 §3.2: URL with user_code embedded as a query parameter
    # so a client (e.g., the macOS app's "Open in Browser" button) can
    # navigate the user to a page that auto-fills the code, removing the
    # copy-paste step. /cloud/device State A renders the pill prefilled
    # when this URL is followed.
    verification_uri_complete: str
    expires_in: int  # Seconds until codes expire
    interval: int  # Minimum polling interval in seconds


class DeviceTokenRequest(BaseModel):
    """Request to exchange device code for API key."""

    device_code: str
    grant_type: str = "urn:ietf:params:oauth:grant-type:device_code"


class DeviceTokenResponse(BaseModel):
    """Response when device authorization is completed."""

    api_key: str  # Full ctx_... key, shown only once
    api_key_prefix: str
    user_id: uuid.UUID
    tenant_id: uuid.UUID
    email: str
    name: str | None = None
    role: str
    plan: str
    tenant_name: str


# --- Magic-link / OTP device flow (cloud-magic-link spec §5.3) ---


class DeviceEmailInitRequest(BaseModel):
    """Request body for ``POST /api/v1/auth/device/email-init`` (spec §5.3).

    Either ``device_code`` (sent automatically by the State A page from the
    URL hidden field) or ``setup_code`` (typed manually by the user on State
    A') must be provided. Both may be present (the device_code wins).
    """

    email: str = Field(..., max_length=320)
    device_code: str | None = Field(default=None, max_length=128)
    setup_code: str | None = Field(default=None, max_length=32)


class DeviceEmailInitResponse(BaseModel):
    """Generic 200 response shape for ``email-init`` (spec §5.3).

    Returned in BOTH the ``email actually sent`` branch (existing-active /
    new-signup) and the ``silent skip`` branch (disabled accounts) so
    attackers cannot enumerate registered emails by observing the response.

    ct-1512 Shard C — C2 fix: ``token_id`` is REQUIRED in every 200 branch.
    On real-issuance branches it is the freshly-minted AuthToken id; on
    silent-skip branches (``account_status`` ∈ {``disabled``, ``unknown``})
    it is a deterministic-but-opaque dummy id derived from the input email
    + the server secret. The dummy id is shaped like a real UUID so the
    response is structurally indistinguishable, but it is not registered
    in the auth_tokens table — so any subsequent ``verify-otp`` call using
    it will be rejected with the same generic ``token_unknown`` error a
    real-but-expired probe would receive. Defends against State A → State
    B response-shape enumeration (a probe seeing ``token_id`` present can
    no longer infer ``email is registered AND active``).
    """

    status: Literal["sent"] = "sent"
    email_masked: str
    expires_in: int
    otp_attempts_remaining: int
    resend_available_in: int
    token_id: uuid.UUID


class DeviceVerifyOtpRequest(BaseModel):
    """Request body for ``POST /api/v1/auth/device/verify-otp`` (spec §5.3).

    The ``token_id`` is returned alongside the State A → State B transition
    response so the client can post back the OTP without re-deriving the
    underlying token from the email body. The OTP is the 6-digit code from
    the email body.
    """

    token_id: uuid.UUID
    otp: str = Field(..., min_length=6, max_length=6)


class DeviceVerifyOtpSuccess(BaseModel):
    """200 response shape for a successful ``verify-otp`` call."""

    ok: Literal[True] = True
    redirect: str


class DeviceVerifyOtpFailure(BaseModel):
    """200 response shape for a failed ``verify-otp`` call.

    Returns 200 (not 400) so the front-end can surface the inline error
    state without triggering retry logic that assumes server-side faults.
    The ``error_code`` matches §6 State E codes (``otp_wrong``,
    ``otp_locked``, ``token_expired``, ``token_consumed``,
    ``token_unknown``); ``attempts_remaining`` is set when applicable.
    """

    ok: Literal[False] = False
    error_code: str
    attempts_remaining: int | None = None


# --- Magic-link sign-in on /cloud/login (cloud-magic-link spec §13b) ---


class LoginEmailLinkRequest(BaseModel):
    """Request body for ``POST /api/v1/auth/login/email-link`` (spec §13b).

    Sister of ``DeviceEmailInitRequest`` for the no-device login-magic-link
    flow. Only the email field is required; there is no device_code /
    setup_code because /cloud/login is for existing users signing in to the
    dashboard, not for completing a CLI device authorization.

    ct-1512 Shard C C4: ``return_to`` is an optional caller-supplied
    relative path (must start with ``/cloud/``) preserved into the
    magic-link callback URL so a recent-reauth challenge from
    ``/cloud/settings#password`` lands the user back on the password form.
    Validated server-side via ``_safe_return_to``.
    """

    email: str = Field(..., max_length=320)
    return_to: str | None = Field(default=None, max_length=512)


class LoginEmailLinkResponse(BaseModel):
    """Generic 200 response for ``/api/v1/auth/login/email-link`` (spec §13b).

    Returned regardless of account existence (existing-active / disabled /
    unknown) so attackers cannot enumerate registered emails by observing
    the response. Mirrors ``DeviceEmailInitResponse`` minus the device-flow
    fields (no ``otp_attempts_remaining`` field at this stage; the State B
    OTP UI will receive ``otp_attempts_remaining`` from a fresh server
    payload via the State A → B transition once the user submits the OTP).

    ct-1512 Shard C — C2 fix: ``token_id`` is REQUIRED in every 200 branch
    (real-issuance and silent-skip alike). See ``DeviceEmailInitResponse``
    for the dummy-id strategy used by silent-skip branches.
    """

    status: Literal["sent"] = "sent"
    email_masked: str
    expires_in: int
    otp_attempts_remaining: int
    resend_available_in: int
    token_id: uuid.UUID


class LoginVerifyOtpRequest(BaseModel):
    """Request body for ``POST /api/v1/auth/login/verify-otp`` (spec §13b).

    Sister of ``DeviceVerifyOtpRequest``. The ``token_id`` is returned by
    the State A → State B transition response on the login page so the
    State B OTP form can post the typed code without re-deriving the
    underlying token from the email body.

    ct-1512 Shard C C4: optional ``return_to`` carried from the original
    /cloud/login render so a successful verify-otp lands the user on the
    pre-reauth page (e.g. ``/cloud/settings#password``). Validated
    server-side via ``_safe_return_to`` before use.
    """

    token_id: uuid.UUID
    otp: str = Field(..., min_length=6, max_length=6)
    return_to: str | None = Field(default=None, max_length=512)


# --- Account password endpoints (cloud-magic-link spec §13a) ---


class AccountPasswordRequest(BaseModel):
    """Request body for ``POST /api/v1/account/password`` (spec §13a).

    For passwordless accounts (``account.password_hash IS NULL``) the
    ``current_password`` field is ignored — the recent-reauth check on the
    session is the security gate per the iter-02 reviewer feedback. For
    accounts that already have a password, ``current_password`` is required
    and validated against the stored hash.
    """

    new_password: str = Field(..., min_length=10, max_length=128)
    current_password: str | None = Field(default=None, max_length=128)


class AccountPasswordResponse(BaseModel):
    """Successful response for ``POST /api/v1/account/password``."""

    status: Literal["saved"] = "saved"


class AccountPasswordReauthRequired(BaseModel):
    """403 challenge response for ``POST /api/v1/account/password``.

    The frontend redirects the user to ``challenge_url`` (a fresh
    /cloud/login magic-link sign-in flow with a ``return_to`` query string),
    after which the user lands back at the password-set form with a fresh
    ``last_reauthenticated_at`` timestamp.
    """

    error: Literal["reauth_required"] = "reauth_required"
    challenge_url: str


class AccountPasswordPromptDismissResponse(BaseModel):
    """Successful response for ``POST /api/v1/account/password-prompt/dismiss``.

    Idempotent — a second dismiss for the same account returns the same
    payload with no observable side effect.
    """

    status: Literal["dismissed"] = "dismissed"


# --- Tenant Admin ---


class TenantDeleteRequest(BaseModel):
    """Confirmation payload for tenant deletion."""

    confirm_slug: str = Field(
        ...,
        description="Must match the tenant slug exactly to confirm deletion.",
    )


class TenantDeleteResponse(BaseModel):
    """Response after scheduling tenant deletion."""

    status: Literal["deletion_scheduled"]
    purge_due_at: datetime
    message: str


class TenantDeleteCancelResponse(BaseModel):
    """Response after cancelling a scheduled tenant deletion."""

    status: Literal["deletion_cancelled"]
    message: str


# --- Local Commercial license retrieval (ct-2015) ---


class LicenseSummary(BaseModel):
    """A Local Commercial license returned to its owner for re-retrieval.

    Only fields the owner needs are exposed; internal columns (customer email,
    Stripe ids, delivery state) are never included.
    """

    license_id: str
    product: str
    token: str
    seats: int
    status: str
    expires_at: datetime


class LicensesResponse(BaseModel):
    licenses: list[LicenseSummary]


class LicenseRetrievalRequest(BaseModel):
    """Request an anonymous license-retrieval link by purchase email."""

    email: EmailStr


class LicenseRetrievalRequestResponse(BaseModel):
    """Always the same shape whether or not a license exists (no enumeration)."""

    status: Literal["ok"]
    message: str
