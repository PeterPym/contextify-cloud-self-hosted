"""Extend auth_tokens.purpose for magic-link device + login flows.

Adds three new purposes (`device_login_existing_user`, `device_signup_new_user`,
`login_magic_link`) for the cloud-side magic-link epic (ct-1512). Pairs with
the verify-then-create model: signup tokens carry no `account_id` until the
user proves email ownership, while the two new existing-user purposes always
do. A CHECK constraint pins down the new invariant at the DB layer:

    (purpose <> 'device_signup_new_user' OR account_id IS NULL)
    AND
    (purpose NOT IN ('device_login_existing_user', 'login_magic_link')
       OR account_id IS NOT NULL)

The constraint is deliberately scoped to the three NEW purposes only. The
older `password_reset` / `email_verify` / `email_change` purposes legitimately
issue tokens with `account_id=NULL` (e.g. the no-account branch of
`create_auth_token_record`, `admin_email_test` QA sends), so they are not
constrained here; tightening that discipline is left to a follow-up migration
once those flows are audited.

A partial unique index on `metadata_json->>'signup_email'` defends against
concurrent-signup-token issuance for the same email (the race-loser guard from
spec §13 done_when 9). The existing `uq_auth_tokens_active_email_purpose_no_account`
index covers the broader `(email_normalized, purpose)` slot and stays in place.

NOTE on the partial unique index predicate: `consumed_at IS NULL` is the
canonical "this signup slot is occupied" definition. There is no separate
`status` column on `auth_tokens` --- finalization stamps `consumed_at`, the
OTP-lockout path stamps `consumed_at`, and the resend invalidation path also
stamps `consumed_at`. Expired-but-unconsumed signup tokens cannot block new
signups for the same email indefinitely because `create_auth_token_record`
issuance ALWAYS runs an UPDATE invalidation (setting `consumed_at=now`) on
prior unconsumed `(purpose, email_normalized)` rows BEFORE INSERTing the new
token, so a fresh signup attempt naturally clears any stale slot.

Adds `accounts.password_prompt_dismissed_at` (nullable timestamptz) for the
post-signup discoverability toast (spec §13a). The `accounts.email_normalized`
column already carries a UNIQUE constraint (migration 020), and is the
post-`normalize_email` storage form, so no additional `lower(email)` index
is needed.

Revision ID: 031
Revises: 030
Create Date: 2026-04-27
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "031"
down_revision: str | None = "030"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_OLD_PURPOSES = "purpose IN ('email_verify', 'password_reset', 'email_change')"
_NEW_PURPOSES = (
    "purpose IN ("
    "'email_verify', 'password_reset', 'email_change', "
    "'device_login_existing_user', 'device_signup_new_user', 'login_magic_link'"
    ")"
)
_ACCOUNT_PAIRING = (
    "(purpose <> 'device_signup_new_user' OR account_id IS NULL)"
    " AND "
    "(purpose NOT IN ('device_login_existing_user', 'login_magic_link')"
    " OR account_id IS NOT NULL)"
)


def upgrade() -> None:
    # Replace the purpose CHECK with the expanded enum (3 -> 6 values).
    op.drop_constraint("ck_auth_token_purpose", "auth_tokens", type_="check")
    op.create_check_constraint(
        "ck_auth_token_purpose",
        "auth_tokens",
        _NEW_PURPOSES,
    )

    # Enforce account_id-purpose pairing: signup tokens have no account yet,
    # everything else (login, password reset, magic-link login, etc.) does.
    op.create_check_constraint(
        "ck_auth_token_account_id_purpose_pairing",
        "auth_tokens",
        _ACCOUNT_PAIRING,
    )

    # Race-loser guard: at most one pending signup token per normalized email.
    # The application normalizer is `s.strip().casefold()` (see
    # `contextify_cloud.utils.email.normalize_email`); the DB-side index uses
    # PostgreSQL `lower(btrim(...))` because PG has no `casefold()` equivalent.
    # For ASCII the two agree exactly; for the rare non-ASCII edge cases
    # (German `ß`, Greek final sigma, ...) the application-side casefold is
    # the source of truth (it is what gets stored in `accounts.email_normalized`
    # and `metadata_json->>'signup_email'`), so the index will at worst MISS
    # a duplicate insertion --- it cannot incorrectly REJECT one. Predicate is
    # `consumed_at IS NULL` (no separate `status` column exists on auth_tokens);
    # see module docstring for why expired-but-unconsumed signup tokens cannot
    # block new signups for the same email indefinitely.
    op.create_index(
        "uq_auth_tokens_active_signup_email",
        "auth_tokens",
        [sa.text("lower(btrim(metadata_json->>'signup_email'))")],
        unique=True,
        postgresql_where=sa.text(
            "purpose = 'device_signup_new_user' AND consumed_at IS NULL"
        ),
    )

    # Discoverability toast state (spec §13a). Nullable so existing rows
    # auto-show the toast for passwordless accounts; setting a password or
    # explicitly dismissing the toast stamps this column.
    op.add_column(
        "accounts",
        sa.Column(
            "password_prompt_dismissed_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("accounts", "password_prompt_dismissed_at")

    op.drop_index(
        "uq_auth_tokens_active_signup_email",
        table_name="auth_tokens",
    )

    op.drop_constraint(
        "ck_auth_token_account_id_purpose_pairing",
        "auth_tokens",
        type_="check",
    )

    # Drop any tokens issued under the new purposes before re-narrowing the
    # CHECK; otherwise the constraint addition fails on a populated DB.
    op.execute(
        sa.text(
            "DELETE FROM auth_tokens "
            "WHERE purpose IN ("
            "'device_login_existing_user', "
            "'device_signup_new_user', "
            "'login_magic_link'"
            ")"
        )
    )
    op.drop_constraint("ck_auth_token_purpose", "auth_tokens", type_="check")
    op.create_check_constraint(
        "ck_auth_token_purpose",
        "auth_tokens",
        _OLD_PURPOSES,
    )
