"""Management entry point for ``python -m contextify_cloud``."""

import argparse
from collections.abc import Sequence

from contextify_cloud.cli.bootstrap import add_create_admin_parser
from contextify_cloud.cli.self_hosted_ops import add_self_hosted_ops_parsers


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="python -m contextify_cloud")
    subparsers = parser.add_subparsers(dest="command", required=True)
    add_create_admin_parser(subparsers)
    add_self_hosted_ops_parsers(subparsers)
    args = parser.parse_args(argv)
    raise SystemExit(args.func(args))


if __name__ == "__main__":
    main()
