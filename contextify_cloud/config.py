"""Application configuration via environment variables."""

from urllib.parse import urlsplit

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings

DEFAULT_API_SECRET_KEY = "dev-secret-change-me"
DEFAULT_EMAIL_FROM = "noreply@contextify.sh"
MIN_SUPPORT_ADMIN_TOKEN_LENGTH = 32


def is_dev_email_url(value: str) -> bool:
    """Return True for local/test URLs where fake email delivery is safe."""
    try:
        host = urlsplit(value.strip()).hostname
    except ValueError:
        host = None
    if not host:
        return False
    host = host.rstrip(".").lower()
    return host in {"localhost", "127.0.0.1", "::1"} or host.endswith(".test")


def parse_dev_email_sink(value: str) -> tuple[str, int] | None:
    """Parse ``DEV_EMAIL_SINK_SMTP`` (``host:port``); None when malformed."""
    host, sep, port_text = value.strip().rpartition(":")
    host = host.strip().strip("[]").rstrip(".").lower()
    if not sep or not host or not port_text.isdigit():
        return None
    port = int(port_text)
    if not 1 <= port <= 65535:
        return None
    return host, port


DEV_EMAIL_SINK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "mailpit"})


def is_local_email_sink_host(host: str) -> bool:
    """Return True only for the controlled catcher: loopback or the compose ``mailpit``.

    Any other name or literal (including single-label names that could resolve
    publicly and numeric forms such as ``0x08080808``) is refused. The send path
    additionally resolves the host and requires loopback or private addresses.
    """
    return host.strip().rstrip(".").lower() in DEV_EMAIL_SINK_HOSTS


def dev_email_sink_refusal(settings_obj: "Settings") -> str | None:
    """Return why ``DEV_EMAIL_SINK_SMTP`` must not be used, or None when allowed.

    The sink is a local/dev-only transport (ct-5331). It is refused whenever
    the configuration could be production: a Resend key is present, or any
    link host is not localhost, loopback or ``.test``. Startup refuses to boot
    and the send path refuses to deliver on the same conditions.
    """
    if not settings_obj.dev_email_sink_smtp.strip():
        return None
    parsed = parse_dev_email_sink(settings_obj.dev_email_sink_smtp)
    if parsed is None:
        return "DEV_EMAIL_SINK_SMTP must be host:port"
    if not is_local_email_sink_host(parsed[0]):
        return "DEV_EMAIL_SINK_SMTP host must be localhost, loopback or mailpit"
    if settings_obj.cloud_profile.strip().lower() == "hosted_qa":
        return "DEV_EMAIL_SINK_SMTP is refused for CLOUD_PROFILE=hosted_qa"
    if settings_obj.resend_api_key:
        return "DEV_EMAIL_SINK_SMTP cannot be combined with RESEND_API_KEY"
    if settings_obj.dev_allow_fake_transactional_email:
        return (
            "DEV_EMAIL_SINK_SMTP cannot be combined with "
            "DEV_ALLOW_FAKE_TRANSACTIONAL_EMAIL"
        )
    if not (
        is_dev_email_url(settings_obj.email_base_url)
        and is_dev_email_url(settings_obj.invitation_base_url)
    ):
        return (
            "DEV_EMAIL_SINK_SMTP is only allowed with localhost, loopback, or "
            ".test EMAIL_BASE_URL and INVITATION_BASE_URL values"
        )
    return None


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Database
    database_url: str = "postgresql+asyncpg://contextify:contextify@localhost:5432/contextify"

    # API security
    api_secret_key: str = DEFAULT_API_SECRET_KEY

    # Stripe (optional for self-hosted)
    stripe_secret_key: str = ""
    stripe_publishable_key: str = ""
    stripe_webhook_secret: str = ""

    # SMTP (optional - invitations logged if not configured)
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = "noreply@contextify.sh"

    # Transactional auth email. When RESEND_API_KEY is empty, auth emails are
    # logged instead of sent so local/dev/CI workflows remain fully testable.
    resend_api_key: str = ""
    dev_allow_fake_transactional_email: bool = False
    # ct-5331: local/dev-only SMTP mail sink ("host:port", e.g. a Mailpit
    # service at "mailpit:1025"). When set, transactional email goes to the
    # sink instead of Resend so a local stack can read welcome and magic-link
    # mail. dev_email_sink_refusal() rejects it at startup and at send time
    # unless the configuration is unmistakably local.
    dev_email_sink_smtp: str = ""
    email_from: str = DEFAULT_EMAIL_FROM
    email_reply_to: str = "support@contextify.sh"
    # ct-2076: operator/ops notification recipient for signup + activation +
    # paid events. Empty disables all operator notifications (self-hosted has
    # no central operator). Managed prod sets this to the operator's address.
    operator_notification_email: str = "rob@contextify.sh"
    # Operator test accounts: comma-separated addresses whose tenants are created
    # internal (no funnel analytics, no operator signup/activation emails). A
    # plus-addressed variant of a listed address also matches, so every
    # rob+<tag>@banagale.com test signup is internal. Reserved test TLDs (.test,
    # .invalid, ...) are always internal; see services/internal_accounts.py.
    internal_account_emails: str = "rob@banagale.com,rob@contextify.sh"
    email_base_url: str = ""
    auth_email_delivery_max_attempts: int = 3
    auth_email_retry_delay_seconds: int = 300
    auth_email_outbox_interval_seconds: int = 60
    # Local Commercial license-delivery outbox (ct-2015): retry the initial
    # purchase-fulfillment email instead of best-effort send.
    license_delivery_max_attempts: int = 5
    license_delivery_retry_delay_seconds: int = 300
    license_delivery_outbox_interval_seconds: int = 60
    # Hosted paid-purchase reconciliation. Polling Stripe independently of the
    # webhook makes paid-but-unfulfilled purchases visible to the operator.
    commercial_reconciliation_interval_seconds: int = 7_200  # 2 hours
    commercial_reconciliation_bootstrap_seconds: int = 7_776_000  # 90 days
    commercial_reconciliation_overlap_seconds: int = 86_400  # 1 day
    commercial_fulfillment_grace_seconds: int = 1_800  # 30 minutes
    commercial_operator_alert_retry_seconds: int = 300
    commercial_operator_alert_max_attempts: int = 5
    # Purchases before this incident cutover already followed the legacy
    # webhook notification path. Suppress only their replacement ledger email
    # so bootstrap reconciliation does not notify the operator twice.
    commercial_operator_alert_cutover_epoch: int = 1_786_555_800
    # ct-3303: how long shutdown waits for in-flight funnel sends before giving up.
    # Defaults to the funnel backend's own HTTP timeout: a shorter bound would
    # guarantee dropping healthy sends, and a longer one only helps when the
    # backend is already timing out, which is exactly when a deploy should not
    # wait. On expiry the undelivered count is logged rather than lost silently.
    funnel_shutdown_drain_seconds: float = 5.0
    # Anonymous license retrieval (ct-2015): short-lived single-use magic link,
    # plus a per-email cooldown so the request endpoint cannot be used to email-bomb.
    license_retrieval_link_ttl_minutes: int = 30
    license_retrieval_request_cooldown_seconds: int = 120
    tos_version: str = "2026-04-24"

    # Invitation settings
    invitation_base_url: str = ""
    invitation_expiry_days: int = 7

    # Deployment mode
    cloud_profile: str = ""
    self_hosted: bool = False
    # Disposable-tenant QA profile. These values are ignored outside
    # CLOUD_PROFILE=hosted_qa and are validated together at startup.
    qa_public_origin: str = ""
    qa_database_name: str = ""
    qa_admin_token: str = ""
    qa_allowed_cidrs: str = ""
    qa_run_ttl_seconds: int = 3600
    qa_reaper_interval_seconds: int = 60
    qa_admin_max_failures: int = 5
    qa_admin_lockout_seconds: int = 300
    qa_source_commit: str = ""
    commercial_license_key: str = ""
    # Ed25519 private signing key (base64url, raw 32 bytes) for the Local
    # Commercial purchase webhook (ct-1966). Held ONLY by the cloud; mints
    # offline tokens with kid="lc1" whose public half is baked into the clients.
    # Empty in dev/CI (no real purchases). In production the purchase webhook
    # refuses to fulfill without it: it raises so Stripe retries and ops is
    # alerted, rather than minting unsigned tokens or dropping a paid purchase.
    commercial_license_signing_key: str = ""
    # Ed25519 private signing key (base64url, raw 32 bytes) for the Self-Hosted Pro
    # self-serve purchase webhook (ct-2313). A SEPARATE online key (kid="shp1") so
    # the offline "v1" Self-Hosted key never goes online; the matching public half
    # is COMMERCIAL_LICENSE_PUBLIC_KEYS["shp1"]. Empty in dev/CI; in production the
    # webhook refuses to fulfill without it (raises -> Stripe retries, ops alerted)
    # rather than dropping a paid purchase.
    commercial_license_signing_key_shp1: str = ""
    # Self-Hosted Pro auto-mint (ct-2313). When False (the launch default), a
    # completed purchase still mints + persists the license idempotently, but the
    # key email is HELD (delivery_status 'held') for operator approval; an operator
    # release flips it to 'pending' and the outbox sends. When True, delivery is
    # fully automatic. The license always exists either way (no silent-drop window);
    # the gate is purely a delivery release. Repo-access provisioning follows the
    # same flag (manual for first buyers while off). Keep this OFF until there is a
    # refund/chargeback answer: an offline token cannot be revoked once delivered,
    # so the held-delivery gate is the only take-back before the key is out, making
    # this flag load-bearing for fraud control, not just operational caution.
    self_hosted_pro_auto_mint: bool = False
    # GitHub token (repo scope) used to grant a Self-Hosted Pro licensee pull
    # access to the private commercial mirror (ct-2313). Unset in dev/CI. The
    # grant is operator-run during onboarding: checkout collects an email, not a
    # GitHub username, so a fully automatic grant-on-purchase is a follow-up.
    github_repo_access_token: str = ""
    enable_docs: bool = False  # Set True locally to enable /api/docs, /api/redoc, /openapi.json
    enable_registration: bool = False  # Public self-serve registration is off by default
    # Scripted-submission checks on the public forms that send email
    # (services/form_shield.py): signed render token, minimum human time,
    # JavaScript proof, honeypot. On everywhere; no external dependency.
    form_shield_enabled: bool = True
    form_shield_min_seconds: float = 2.0
    # Cloudflare Turnstile human check on POST /cloud/register (services/turnstile.py).
    # Off by default and for self-hosted installs; hosted sets all three.
    turnstile_enabled: bool = False
    turnstile_site_key: str = ""
    turnstile_secret_key: str = ""
    # Hosted browser analytics is enabled by default. CI/E2E disables it so a
    # localhost browser never contacts the production first-party event relay.
    browser_analytics_enabled: bool = True

    # JWT session auth (dashboard cookies)
    jwt_token_expire_hours: int = 24
    reauth_window_minutes: int = 15
    auth_email_resend_cooldown_seconds: int = 180
    # Production deployments must set this to True so session and CSRF cookies
    # are always emitted with Secure=True regardless of the request scheme
    # the ASGI app sees from upstream proxies. The request-scheme inference
    # in _is_secure_request only applies when this flag is False (dev/CI).
    force_secure_cookies: bool = False
    # Launch behavior: one browser session maps to one active tenant membership.
    # Keep disabled until explicit tenant switching exists.
    allow_multi_membership_accounts: bool = False

    # ct-2614 — dedicated hostname the first-party telemetry relay answers on.
    # nginx fronts one FastAPI app for both cloud.contextify.sh and this host; the
    # relay route enforces the separation app-side by responding only when the
    # request Host matches this value (any other host -> 404). Safe to ship in the
    # source-available mirror (just a hostname); the relay route itself lives under
    # contextify_cloud/hosted/ and is excluded from the mirror.
    telemetry_relay_host: str = "telemetry.contextify.sh"

    # CORS
    allowed_origins: str = "http://localhost:3000"
    # Comma-separated CIDRs whose X-Forwarded-Proto header is trusted. Loopback
    # clients are always trusted. Self-hosted compose sets Docker/OrbStack
    # gateway ranges for host-level Caddy -> container traffic.
    trusted_proxy_cidrs: str = ""

    # Logging
    log_level: str = "info"
    log_format: str = "text"  # "json" for structured output, "text" for plaintext

    # Error monitoring
    error_monitoring_enabled: bool = False
    error_monitoring_send_default_pii: bool = False
    error_monitoring_max_events_per_minute: int = 20
    ops_smoke_token: str = ""
    support_admin_token: str = ""
    sentry_dsn: str = ""
    sentry_environment: str = "production"
    sentry_release: str = ""
    sentry_error_sample_rate: float = 1.0
    sentry_traces_sample_rate: float | None = None
    sentry_profiles_sample_rate: float | None = None
    sentry_debug: bool = False

    # Sync limits
    # ct-1841: high backstop only. The real request-size guard is
    # max_request_body_bytes (50MB); entry inserts already sub-batch at 1000
    # rows (routers/sync.py). The previous 5000 wall rejected modest but
    # item-dense catch-up batches (e.g. a 3.4MB push of >5000 small
    # tool_invocation/usage rows) with an all-or-nothing 413 BEFORE the
    # handler's partial-accept path ran; clients that do not catch 413 then
    # retried the same batch forever and never drained. Raised so the byte cap
    # governs. Follow-up: sub-batch the per-row summary/usage/tool_invocation/
    # metadata inserts for latency at very high counts (currently O(N) round-trips).
    max_batch_size: int = 50_000
    max_entry_content_bytes: int = 1_000_000  # 1MB per entry content field
    max_request_body_bytes: int = 50_000_000  # 50MB overall request body limit
    idempotency_ttl_hours: int = 24  # How long idempotency keys are retained
    session_ttl_hours: int = 24  # How long before inactive sync sessions are marked abandoned

    # Rate limiting (per API key, requests per minute; 0 = disabled)
    rate_limit_sync_per_minute: int = 120
    rate_limit_search_per_minute: int = 60
    rate_limit_auth_per_minute: int = 10

    # Unauthenticated endpoint rate limits (per IP, requests per minute; 0 = disabled)
    rate_limit_unauth_register_per_minute: int = 5
    rate_limit_unauth_login_per_minute: int = 10
    rate_limit_unauth_device_code_per_minute: int = 10
    rate_limit_unauth_device_token_per_minute: int = 30
    rate_limit_unauth_invitation_accept_per_minute: int = 10
    rate_limit_unauth_email_init_per_minute: int = 10
    rate_limit_unauth_verify_otp_per_minute: int = 10
    # ct-1563 — sister rate limits for the no-device /cloud/login magic-link
    # flow (spec §13b). Same per-IP cap as the device-flow endpoints; the
    # per-token OTP lockout is enforced inside ``verify_device_otp_attempt``.
    rate_limit_unauth_login_email_link_per_minute: int = 10
    rate_limit_unauth_login_verify_otp_per_minute: int = 10
    # ct-2983 — sister rate limits for the email-first passwordless sign-up
    # flow. The register POST itself is covered by the existing per-IP
    # register cap (5/min); these bound the link-confirm + OTP-verify surfaces.
    rate_limit_unauth_register_email_link_confirm_per_minute: int = 10
    rate_limit_unauth_register_verify_otp_per_minute: int = 10
    rate_limit_unauth_forgot_password_per_minute: int = 5
    # ct-2340 — per-IP cap on the anonymous checkout endpoints (card-testing surface).
    rate_limit_unauth_checkout_per_minute: int = 5
    # ct-2614 — per-IP cap on the first-party client-telemetry relay (POST /capture/
    # on telemetry.contextify.sh). The relayed events are rare per client (first-*
    # milestones + a weekly heartbeat), so this bounds abuse without throttling the
    # NAT-shared legitimate traffic. 0 disables the check (CI/E2E).
    rate_limit_telemetry_per_minute: int = 120
    password_reset_request_cooldown_seconds: int = 120
    # ct-2983 — shared per-email send cooldown for the BROWSER magic-link INIT
    # paths (login email-link, register email-first). The device flow is out of
    # scope here and keeps its own per-device send cap (follow-up ct-3039).
    # Keyed on ``AuthToken.email_normalized`` (NOT account_id) so existing,
    # unknown-sentinel, and disabled emails are suppressed identically
    # (enumeration-safe). 60s matches the client resend countdown; 0 disables.
    magic_link_send_cooldown_seconds: int = 60
    # Caps on sign-up/sign-in email requests (services/auth_email_limits.py). The
    # per-email cooldown above cannot stop a client that rotates proxies and
    # addresses. Per IP: 429. Global: emails to new addresses pause, sign-in to
    # existing accounts continues. Legitimate volume is a few
    # a day. 0 disables.
    auth_email_send_cap_per_ip_per_hour: int = 5
    auth_email_send_cap_global_per_hour: int = 20
    auth_email_send_cap_global_per_day: int = 50
    # Operator alert (email + Sentry warning, at most hourly) once this many
    # email requests plus rejected scripted submissions arrive within an hour.
    # 0 disables.
    auth_email_spike_alert_per_hour: int = 10

    # Magic-link / OTP device flow (cloud-magic-link spec §5.3, §10).
    # AuthToken expiry for device-flow magic-link / OTP tokens is 10 minutes.
    auth_device_token_expiry_seconds: int = 600
    # Per-token OTP brute-force defense: how many wrong codes before a token
    # is invalidated (consumed_at set with the locked sentinel). Spec §10.
    auth_otp_attempts_per_token_max: int = 5
    # Per-device-code send cap: prevents email-bombing a single CLI session.
    # Counts non-consumed AuthTokens with the device_authorization_id metadata
    # plus any tokens already invalidated by resend semantics. Spec §10.
    auth_email_send_cap_per_device_code: int = 5

    # Device flow (RFC 8628)
    device_code_expiry_seconds: int = 900  # 15 minutes
    device_poll_interval: int = 5  # Minimum seconds between polls

    # Browser handoff lets native clients exchange a valid API key for a
    # short-lived one-time browser URL. Self-hosted operators can disable it.
    enable_browser_handoff: bool = True
    browser_handoff_token_ttl_seconds: int = 60

    # Data retention (days, 0 = no auto-deletion)
    default_data_retention_days: int = 0

    # Purge scheduling
    purge_grace_period_days: int = 30  # Days between deletion trigger and actual purge
    purge_check_interval_seconds: int = 3600  # 1 hour between purge sweeps
    purge_tombstone_retention_months: int = 12  # Months to retain tombstone records
    purge_batch_limit: int = 5  # Max tenants to purge per sweep

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}

    @model_validator(mode="before")
    @classmethod
    def ignore_removed_legacy_smoke_token(cls, data: object) -> object:
        """Tolerate stale dotenv files that still contain the retired alias."""
        if isinstance(data, dict):
            data.pop("error_monitoring_smoke_test_token", None)
            data.pop("ERROR_MONITORING_SMOKE_TEST_TOKEN", None)
        return data

    @field_validator("form_shield_min_seconds")
    @classmethod
    def validate_form_shield_min_seconds(cls, value: float) -> float:
        if value < 0:
            raise ValueError("FORM_SHIELD_MIN_SECONDS must be >= 0")
        return value

    @model_validator(mode="after")
    def turnstile_requires_keys(self) -> "Settings":
        """Refuse TURNSTILE_ENABLED without keys rather than silently skip the check."""
        if self.turnstile_enabled and not (self.turnstile_site_key and self.turnstile_secret_key):
            raise ValueError(
                "TURNSTILE_ENABLED=true requires TURNSTILE_SITE_KEY and TURNSTILE_SECRET_KEY"
            )
        return self

    @field_validator("sentry_traces_sample_rate", "sentry_profiles_sample_rate", mode="before")
    @classmethod
    def empty_string_to_none(cls, value: object) -> object:
        if value == "":
            return None
        return value

    @field_validator("purge_grace_period_days")
    @classmethod
    def validate_non_negative_purge_grace_period(cls, value: int) -> int:
        if value < 0:
            raise ValueError("purge_grace_period_days must be >= 0")
        return value

    @field_validator(
        "purge_check_interval_seconds",
        "purge_tombstone_retention_months",
        "purge_batch_limit",
        "auth_email_delivery_max_attempts",
        "auth_email_retry_delay_seconds",
        "auth_email_outbox_interval_seconds",
        "license_delivery_max_attempts",
        "license_delivery_retry_delay_seconds",
        "license_delivery_outbox_interval_seconds",
        "commercial_reconciliation_interval_seconds",
        "commercial_reconciliation_bootstrap_seconds",
        "commercial_reconciliation_overlap_seconds",
        "commercial_fulfillment_grace_seconds",
        "commercial_operator_alert_retry_seconds",
        "commercial_operator_alert_max_attempts",
    )
    @classmethod
    def validate_positive_integer_settings(cls, value: int) -> int:
        if value < 1:
            raise ValueError("integer settings must be >= 1")
        return value

    @field_validator(
        "rate_limit_sync_per_minute",
        "rate_limit_search_per_minute",
        "rate_limit_auth_per_minute",
        "rate_limit_unauth_register_per_minute",
        "rate_limit_unauth_login_per_minute",
        "rate_limit_unauth_device_code_per_minute",
        "rate_limit_unauth_device_token_per_minute",
        "rate_limit_unauth_invitation_accept_per_minute",
        "rate_limit_unauth_email_init_per_minute",
        "rate_limit_unauth_verify_otp_per_minute",
        "rate_limit_unauth_login_email_link_per_minute",
        "rate_limit_unauth_login_verify_otp_per_minute",
        "rate_limit_unauth_forgot_password_per_minute",
        "rate_limit_unauth_checkout_per_minute",
        "rate_limit_telemetry_per_minute",
        "auth_email_send_cap_per_ip_per_hour",
        "auth_email_send_cap_global_per_hour",
        "auth_email_send_cap_global_per_day",
        "auth_email_spike_alert_per_hour",
    )
    @classmethod
    def validate_non_negative_rate_limits(cls, value: int) -> int:
        if value < 0:
            raise ValueError("rate limits must be >= 0")
        return value

    @field_validator(
        "auth_device_token_expiry_seconds",
        "auth_otp_attempts_per_token_max",
        "auth_email_send_cap_per_device_code",
        "browser_handoff_token_ttl_seconds",
        "password_reset_request_cooldown_seconds",
    )
    @classmethod
    def validate_positive_auth_flow_settings(cls, value: int) -> int:
        if value < 1:
            raise ValueError("auth-flow integer settings must be >= 1")
        return value

    @field_validator(
        "sentry_error_sample_rate",
        "sentry_traces_sample_rate",
        "sentry_profiles_sample_rate",
    )
    @classmethod
    def validate_sample_rate(cls, value: float | None) -> float | None:
        if value is None or 0.0 <= value <= 1.0:
            return value
        raise ValueError("sample rate must be between 0 and 1")

    @property
    def cors_origins(self) -> list[str]:
        origins = [o.strip() for o in self.allowed_origins.split(",") if o.strip()]
        for origin in origins:
            parsed = urlsplit(origin)
            if (
                "*" in origin
                or parsed.scheme not in {"http", "https"}
                or not parsed.netloc
                or parsed.username
                or parsed.password
                or parsed.path not in {"", "/"}
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError(
                    "ALLOWED_ORIGINS must be comma-separated absolute http(s) "
                    "origins without paths/query/fragment/userinfo and must not "
                    "contain '*' when credentials are enabled."
                )
        return origins


settings = Settings()
