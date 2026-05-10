"""Backfill browser accounts for existing tenant users.

Revision ID: 022
Revises: 021
Create Date: 2026-04-25
"""

from collections.abc import Sequence

from alembic import op

revision: str = "022"
down_revision: str | None = "021"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


LEGACY_DUPLICATE_EMAIL_PREFLIGHT_SQL = """
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM users u
        WHERE u.account_id IS NULL
          AND u.removed_at IS NULL
          AND btrim(u.email) <> ''
          AND position('@' in btrim(u.email)) > 1
        GROUP BY u.tenant_id, lower(btrim(u.email))
        HAVING count(*) > 1
    ) THEN
        RAISE EXCEPTION
            'Duplicate active users with the same normalized email exist in one tenant. '
            'Resolve duplicates before account backfill.';
    END IF;
END $$;
"""


ACCOUNT_BACKFILL_SQL = """
INSERT INTO accounts (
    id,
    email_normalized,
    email_display,
    password_hash,
    email_verified_at,
    status,
    session_version,
    last_login_at,
    tos_accepted_at,
    tos_version,
    tos_ip,
    tos_user_agent,
    created_at,
    updated_at
)
SELECT
    gen_random_uuid(),
    candidates.email_normalized,
    candidates.email_display,
    NULL,
    NULL,
    'password_unset',
    1,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    now(),
    now()
FROM (
    SELECT DISTINCT ON (lower(btrim(u.email)))
        lower(btrim(u.email)) AS email_normalized,
        btrim(u.email) AS email_display
    FROM users u
    WHERE u.account_id IS NULL
      AND u.removed_at IS NULL
      AND btrim(u.email) <> ''
      AND position('@' in btrim(u.email)) > 1
    ORDER BY lower(btrim(u.email)), u.created_at ASC, u.id ASC
) AS candidates
WHERE NOT EXISTS (
    SELECT 1
    FROM accounts a
    WHERE a.email_normalized = candidates.email_normalized
);
"""

USER_ACCOUNT_LINK_SQL = """
UPDATE users u
SET account_id = a.id
FROM accounts a
WHERE u.account_id IS NULL
  AND u.removed_at IS NULL
  AND lower(btrim(u.email)) = a.email_normalized
  AND btrim(u.email) <> ''
  AND position('@' in btrim(u.email)) > 1;
"""


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")
    op.execute(LEGACY_DUPLICATE_EMAIL_PREFLIGHT_SQL)
    op.execute(ACCOUNT_BACKFILL_SQL)
    op.execute(USER_ACCOUNT_LINK_SQL)


def downgrade() -> None:
    # Data migration only. Rollback uses a database snapshot, or a targeted
    # operational unlink/delete query after inspecting affected rows.
    pass
