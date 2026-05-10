"""User-scoping utilities for per-user data filtering.

Provides helpers to add uploaded_by_user_id filtering to SQL queries
based on the authenticated user's role:
  - owner/admin: no filtering (full tenant visibility)
  - member: filtered to uploaded_by_user_id = auth.user_id
  - viewer: filtered to uploaded_by_user_id = auth.user_id (future: aggregate only)

These functions work with raw SQL text queries (used for tenant-schema queries)
rather than SQLAlchemy ORM, since tenant tables use dynamic schema names.
"""

import logging

from contextify_cloud.middleware.auth import AuthContext

logger = logging.getLogger(__name__)


def build_user_scope_clause(
    auth: AuthContext,
    *,
    column: str = "uploaded_by_user_id",
    param_name: str = "scope_user_id",
) -> tuple[str, dict[str, str]]:
    """Build a SQL WHERE clause fragment for user-scoped filtering.

    Returns a tuple of (sql_fragment, params_dict):
      - For full-access roles: ("", {}) -- no filtering
      - For member/viewer: ("AND <column> = :<param_name>", {param_name: str(user_id)})

    The caller should append the sql_fragment to their WHERE clause and merge
    the params_dict into their query parameters.

    Args:
        auth: The authenticated user context.
        column: The column name to filter on (default: uploaded_by_user_id).
        param_name: The parameter name to use in the SQL fragment (default: scope_user_id).

    Returns:
        Tuple of (sql_clause, params_dict).
    """
    if auth.has_full_access:
        return "", {}

    logger.debug(
        "Applying user scope: user_id=%s role=%s column=%s",
        auth.user_id, auth.role, column,
    )
    return f"AND {column} = :{param_name}", {param_name: str(auth.user_id)}


def build_user_scope_where(
    auth: AuthContext,
    *,
    column: str = "uploaded_by_user_id",
    param_name: str = "scope_user_id",
) -> tuple[str, dict[str, str]]:
    """Build a standalone WHERE clause for user-scoped filtering.

    Like build_user_scope_clause but returns a WHERE clause (not AND fragment).
    Useful when user scoping is the only filter condition.

    Returns:
      - For full-access roles: ("", {}) -- no filtering
      - For member/viewer: ("WHERE <column> = :<param_name>", {param_name: str(user_id)})
    """
    if auth.has_full_access:
        return "", {}

    logger.debug(
        "Applying user scope (WHERE): user_id=%s role=%s column=%s",
        auth.user_id, auth.role, column,
    )
    return f"WHERE {column} = :{param_name}", {param_name: str(auth.user_id)}
