"""Add 'held' to the licenses delivery_status check (ct-2313).

Self-Hosted Pro hold-delivery: when SELF_HOSTED_PRO_AUTO_MINT is off (the default
launch posture), a purchase still mints + persists the license idempotently, but
the key email is HELD for operator approval. A held row sits in delivery_status
'held', which the scheduled outbox sweep ignores (it only sends 'pending'/'failed'
rows); an operator release flips it to 'pending'. Extend the check accordingly.

Revision ID: 038
Revises: 037
Create Date: 2026-06-22
"""

from collections.abc import Sequence

from alembic import op

revision: str = "038"
down_revision: str | None = "037"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_CONSTRAINT = "ck_licenses_delivery_status"
_OLD = "delivery_status IN ('pending', 'sent', 'failed', 'exhausted')"
_NEW = "delivery_status IN ('pending', 'sent', 'failed', 'exhausted', 'held')"


def upgrade() -> None:
    op.drop_constraint(_CONSTRAINT, "licenses", type_="check")
    op.create_check_constraint(_CONSTRAINT, "licenses", _NEW)


def downgrade() -> None:
    op.drop_constraint(_CONSTRAINT, "licenses", type_="check")
    op.create_check_constraint(_CONSTRAINT, "licenses", _OLD)
