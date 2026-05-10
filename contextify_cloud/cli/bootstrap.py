"""Management CLI for self-hosted first-admin bootstrap."""

import argparse
import asyncio
import getpass
import sys
from typing import Any

from contextify_cloud.database import async_session_factory
from contextify_cloud.services.bootstrap import (
    BootstrapUnavailableError,
    create_first_admin,
)
from contextify_cloud.services.browser_auth import BrowserAuthError


async def _run_create_admin(args: argparse.Namespace) -> int:
    password = args.password
    if not password:
        password = getpass.getpass("Password: ")
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("Passwords do not match.", file=sys.stderr)
            return 2

    async with async_session_factory() as db:
        try:
            result = await create_first_admin(
                db,
                email=args.email,
                password=password,
                name=args.name or "",
                team_name=args.team_name,
                request_ip=None,
                user_agent="contextify-cloud-cli",
            )
            email_display = result.account.email_display
            tenant_name = result.tenant.name
            await db.commit()
        except (BrowserAuthError, BootstrapUnavailableError) as exc:
            await db.rollback()
            print(str(exc), file=sys.stderr)
            return 2
        except Exception:
            await db.rollback()
            raise

    print("First admin created.")
    print(f"Email: {email_display}")
    print(f"Team:  {tenant_name}")
    print("Open /cloud/login to sign in.")
    return 0


def add_create_admin_parser(subparsers: Any) -> None:
    parser = subparsers.add_parser(
        "create-admin",
        help="Create the first self-hosted owner account",
        description="Create the first self-hosted owner account",
    )
    parser.add_argument("--email", required=True, help="Owner email address")
    parser.add_argument("--password", help="Owner password; prompts when omitted")
    parser.add_argument("--name", default="", help="Owner display name")
    parser.add_argument(
        "--team-name",
        default="Contextify Self-Hosted",
        help="Initial workspace/team name",
    )
    parser.set_defaults(func=lambda args: asyncio.run(_run_create_admin(args)))
