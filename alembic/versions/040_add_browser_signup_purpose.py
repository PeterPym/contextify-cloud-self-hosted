"""Add the ``browser_signup_new_user`` auth-token purpose (ct-2983).

The email-first passwordless sign-up flow (Option B+ / Decision-2a) issues a
signup token from ``POST /cloud/register`` that carries no ``account_id`` until
the user proves email ownership by consuming the emailed link (or OTP). It is
the browser analogue of the device flow's ``device_signup_new_user`` token, so
it lives on the NULL-account side of the pairing CHECK and shares the
per-email active-signup partial unique index.

Three constraint/index changes:

1. ``ck_auth_token_purpose`` gains ``browser_signup_new_user`` (6 -> 7 values).
2. ``ck_auth_token_account_id_purpose_pairing`` moves ``browser_signup_new_user``
   onto the ``account_id IS NULL`` side alongside ``device_signup_new_user``.
3. ``uq_auth_tokens_active_signup_email`` predicate widens to cover BOTH signup
   purposes so at most one active signup token exists per email across the
   device and browser flows.

Revision ID: 040
Revises: 039
Create Date: 2026-07-17
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "040"
down_revision: str | None = "039"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_OLD_PURPOSES = (
    "purpose IN ("
    "'email_verify', 'password_reset', 'email_change', "
    "'device_login_existing_user', 'device_signup_new_user', 'login_magic_link'"
    ")"
)
_NEW_PURPOSES = (
    "purpose IN ("
    "'email_verify', 'password_reset', 'email_change', "
    "'device_login_existing_user', 'device_signup_new_user', 'login_magic_link', "
    "'browser_signup_new_user'"
    ")"
)
_OLD_ACCOUNT_PAIRING = (
    "(purpose <> 'device_signup_new_user' OR account_id IS NULL)"
    " AND "
    "(purpose NOT IN ('device_login_existing_user', 'login_magic_link')"
    " OR account_id IS NOT NULL)"
)
_NEW_ACCOUNT_PAIRING = (
    "(purpose NOT IN ('device_signup_new_user', 'browser_signup_new_user')"
    " OR account_id IS NULL)"
    " AND "
    "(purpose NOT IN ('device_login_existing_user', 'login_magic_link')"
    " OR account_id IS NOT NULL)"
)
_OLD_SIGNUP_INDEX_WHERE = "purpose = 'device_signup_new_user' AND consumed_at IS NULL"
_NEW_SIGNUP_INDEX_WHERE = (
    "purpose IN ('device_signup_new_user', 'browser_signup_new_user') "
    "AND consumed_at IS NULL"
)


def upgrade() -> None:
    # Expand the purpose CHECK (6 -> 7 values).
    op.drop_constraint("ck_auth_token_purpose", "auth_tokens", type_="check")
    op.create_check_constraint(
        "ck_auth_token_purpose",
        "auth_tokens",
        _NEW_PURPOSES,
    )

    # Move browser_signup_new_user onto the account_id IS NULL side.
    op.drop_constraint(
        "ck_auth_token_account_id_purpose_pairing", "auth_tokens", type_="check"
    )
    op.create_check_constraint(
        "ck_auth_token_account_id_purpose_pairing",
        "auth_tokens",
        _NEW_ACCOUNT_PAIRING,
    )

    # Widen the active-signup partial unique index to both signup purposes so a
    # duplicate active signup token per email stays impossible across flows.
    op.drop_index("uq_auth_tokens_active_signup_email", table_name="auth_tokens")
    op.create_index(
        "uq_auth_tokens_active_signup_email",
        "auth_tokens",
        [sa.text("lower(btrim(metadata_json->>'signup_email'))")],
        unique=True,
        postgresql_where=sa.text(_NEW_SIGNUP_INDEX_WHERE),
    )


def downgrade() -> None:
    # Drop any tokens issued under the new purpose before re-narrowing.
    op.execute(
        "DELETE FROM auth_tokens WHERE purpose = 'browser_signup_new_user'"
    )

    op.drop_index("uq_auth_tokens_active_signup_email", table_name="auth_tokens")
    op.create_index(
        "uq_auth_tokens_active_signup_email",
        "auth_tokens",
        [sa.text("lower(btrim(metadata_json->>'signup_email'))")],
        unique=True,
        postgresql_where=sa.text(_OLD_SIGNUP_INDEX_WHERE),
    )

    op.drop_constraint(
        "ck_auth_token_account_id_purpose_pairing", "auth_tokens", type_="check"
    )
    op.create_check_constraint(
        "ck_auth_token_account_id_purpose_pairing",
        "auth_tokens",
        _OLD_ACCOUNT_PAIRING,
    )

    op.drop_constraint("ck_auth_token_purpose", "auth_tokens", type_="check")
    op.create_check_constraint(
        "ck_auth_token_purpose",
        "auth_tokens",
        _OLD_PURPOSES,
    )
