"""Self-hosted backup, restore, and launchd helper commands."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO
from xml.sax.saxutils import escape as xml_escape

ARCHIVE_PREFIX = "contextify-selfhosted"
ARCHIVE_SUFFIX = ".tar"
MANIFEST_NAME = "manifest.json"
DUMP_NAME = "contextify.dump"
MAX_HEALTH_RESPONSE_BYTES = 1024 * 1024
MIN_DUMP_BYTES_DEFAULT = 1024


class SelfHostedOpsError(RuntimeError):
    """Raised for recoverable operator-facing self-hosted CLI failures."""


@dataclass(frozen=True)
class IncludedFile:
    source_path: Path
    archive_path: str
    size: int
    sha256: str
    mode: int


@dataclass(frozen=True)
class HealthCheck:
    name: str
    status: str
    message: str
    detail: dict[str, Any] | None = None


def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)  # noqa: UP017 - fallback supports macOS system Python.


def _timestamp(now: dt.datetime | None = None) -> str:
    value = now or _utc_now()
    return value.strftime("%Y%m%dT%H%M%SZ")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _compose_cmd(compose_file: Path) -> list[str]:
    return ["docker", "compose", "-f", str(compose_file)]


def _resolve_repo_path(value: str, repo_dir: Path) -> Path:
    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        candidate = repo_dir / candidate
    return candidate.resolve()


def _run_checked(
    command: list[str],
    *,
    stdin: BinaryIO | None = None,
    stdout: BinaryIO | None = None,
) -> None:
    try:
        subprocess.run(command, stdin=stdin, stdout=stdout, check=True)
    except FileNotFoundError as exc:
        raise SelfHostedOpsError(f"Required command not found: {command[0]}") from exc
    except subprocess.CalledProcessError as exc:
        rendered = " ".join(command)
        raise SelfHostedOpsError(f"Command failed with exit {exc.returncode}: {rendered}") from exc


def _run_capture(command: list[str]) -> str:
    try:
        completed = subprocess.run(command, capture_output=True, text=True, check=True)
    except FileNotFoundError as exc:
        raise SelfHostedOpsError(f"Required command not found: {command[0]}") from exc
    except subprocess.CalledProcessError as exc:
        rendered = " ".join(command)
        stderr = exc.stderr.strip()
        detail = f": {stderr}" if stderr else ""
        message = f"Command failed with exit {exc.returncode}: {rendered}{detail}"
        raise SelfHostedOpsError(message) from exc
    return completed.stdout.strip()


def _run_quiet(command: list[str]) -> bool:
    try:
        subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False


def _run_success(command: list[str]) -> tuple[bool, str | None]:
    try:
        subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        )
        return True, None
    except FileNotFoundError:
        return False, f"Required command not found: {command[0]}"
    except subprocess.CalledProcessError as exc:
        return False, exc.stderr.strip() or f"Command exited {exc.returncode}"


def _archive_path_for(source_path: Path, root: Path) -> str:
    resolved = source_path.resolve()
    try:
        relative = resolved.relative_to(root.resolve())
        parts = ["config", *relative.parts]
    except ValueError:
        parts = ["config", "absolute", *resolved.parts[1:]]
    return "/".join(part for part in parts if part not in {"", ".", ".."})


def _default_include_files(compose_file: Path) -> list[Path]:
    root = compose_file.parent
    candidates = [
        root / ".env",
        compose_file,
        root / "Caddyfile",
        Path("/opt/homebrew/etc/Caddyfile"),
        Path("/etc/caddy/Caddyfile"),
    ]
    return candidates


def _collect_include_files(paths: Iterable[Path], root: Path) -> list[IncludedFile]:
    included: list[IncludedFile] = []
    seen: set[Path] = set()
    for path in paths:
        resolved = path.expanduser().resolve()
        if resolved in seen or not resolved.is_file():
            continue
        seen.add(resolved)
        stat = resolved.stat()
        included.append(
            IncludedFile(
                source_path=resolved,
                archive_path=_archive_path_for(resolved, root),
                size=stat.st_size,
                sha256=_sha256_file(resolved),
                mode=stat.st_mode & 0o777,
            )
        )
    return included


def _add_file_to_tar(tar: tarfile.TarFile, source: Path, archive_path: str, mode: int) -> None:
    stat = source.stat()
    info = tarfile.TarInfo(archive_path)
    info.size = stat.st_size
    info.mode = mode
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    with source.open("rb") as handle:
        tar.addfile(info, handle)


def _write_bytes_member(tar: tarfile.TarFile, archive_path: str, data: bytes, mode: int) -> None:
    import io

    info = tarfile.TarInfo(archive_path)
    info.size = len(data)
    info.mode = mode
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    tar.addfile(info, io.BytesIO(data))


@contextmanager
def _open_private_tar(path: Path) -> Iterator[tarfile.TarFile]:
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise SelfHostedOpsError(f"Backup partial already exists: {path}") from exc
    except OSError as exc:
        raise SelfHostedOpsError(f"Could not create private backup archive: {path}") from exc

    fileobj: BinaryIO | None = None
    try:
        fileobj = os.fdopen(fd, "wb")
    except Exception:
        os.close(fd)
        raise
    try:
        with tarfile.open(fileobj=fileobj, mode="w") as archive:
            yield archive
    except Exception:
        path.unlink(missing_ok=True)
        raise
    finally:
        if fileobj is not None and not fileobj.closed:
            fileobj.close()


def _rotate_archives(backup_dir: Path, retention_days: int, min_keep: int) -> None:
    if retention_days < 0:
        return
    archives = sorted(
        backup_dir.glob(f"{ARCHIVE_PREFIX}-*{ARCHIVE_SUFFIX}"),
        key=lambda path: path.stat().st_mtime,
    )
    if len(archives) <= min_keep:
        return
    cutoff = _utc_now().timestamp() - (retention_days * 86400)
    max_delete = len(archives) - min_keep
    deleted = 0
    for archive in archives:
        if deleted >= max_delete:
            break
        if archive.stat().st_mtime <= cutoff:
            archive.unlink()
            deleted += 1


def _require_compose_file(path: Path) -> Path:
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        raise SelfHostedOpsError(f"Compose file not found: {resolved}")
    return resolved


def _allocate_archive_paths(backup_dir: Path) -> tuple[Path, Path]:
    timestamp = _timestamp()
    for suffix in ["", *[f"-{index}" for index in range(1, 1000)]]:
        archive_name = f"{ARCHIVE_PREFIX}-{timestamp}{suffix}{ARCHIVE_SUFFIX}"
        archive_path = backup_dir / archive_name
        partial_path = backup_dir / f"{archive_name}.partial"
        if not archive_path.exists() and not partial_path.exists():
            return archive_path, partial_path
    raise SelfHostedOpsError("Could not allocate a unique backup archive name")


def _finalize_private_archive(partial_path: Path, archive_path: Path) -> None:
    partial_path.chmod(0o600)
    try:
        os.link(partial_path, archive_path)
    except FileExistsError as exc:
        raise SelfHostedOpsError(f"Backup archive already exists: {archive_path}") from exc
    except OSError as exc:
        raise SelfHostedOpsError(f"Could not finalize backup archive: {archive_path}") from exc
    finally:
        partial_path.unlink(missing_ok=True)


def _preflight_db(args: argparse.Namespace) -> None:
    if args.skip_preflight:
        return
    command = [
        *_compose_cmd(args.compose_file),
        "exec",
        "-T",
        args.db_service,
        "pg_isready",
        "-U",
        args.db_user,
        "-q",
    ]
    if not _run_quiet(command):
        raise SelfHostedOpsError("Database is not accepting connections")


def _run_backup(args: argparse.Namespace) -> int:
    try:
        compose_file = _require_compose_file(Path(args.compose_file))
        args.compose_file = compose_file
        _preflight_db(args)

        backup_dir = Path(args.output_dir).expanduser()
        if not backup_dir.is_absolute():
            backup_dir = compose_file.parent / backup_dir
        backup_dir = backup_dir.resolve()
        backup_dir.mkdir(parents=True, exist_ok=True)
        backup_dir.chmod(0o700)

        include_paths: list[Path] = []
        if not args.no_default_includes:
            include_paths.extend(_default_include_files(compose_file))
        for value in args.include_file:
            include_path = Path(value).expanduser()
            if not include_path.is_absolute():
                include_path = compose_file.parent / include_path
            include_path = include_path.resolve()
            if not include_path.is_file():
                raise SelfHostedOpsError(f"Include file not found: {include_path}")
            include_paths.append(include_path)

        with tempfile.TemporaryDirectory(prefix="contextify-cloud-backup.") as tmpdir:
            dump_path = Path(tmpdir) / DUMP_NAME
            command = [
                *_compose_cmd(compose_file),
                "exec",
                "-T",
                args.db_service,
                "pg_dump",
                "-U",
                args.db_user,
                "-Fc",
                args.db_name,
            ]
            with dump_path.open("wb") as dump_handle:
                _run_checked(command, stdout=dump_handle)

            dump_size = dump_path.stat().st_size
            if dump_size < args.min_dump_bytes:
                raise SelfHostedOpsError(
                    f"Dump too small ({dump_size} bytes < {args.min_dump_bytes}); refusing backup"
                )

            included_files = _collect_include_files(include_paths, compose_file.parent)
            manifest = {
                "archive_version": 1,
                "created_at": _utc_now().isoformat(),
                "db": {
                    "compose_file": str(compose_file),
                    "service": args.db_service,
                    "name": args.db_name,
                    "user": args.db_user,
                    "dump_path": DUMP_NAME,
                    "dump_bytes": dump_size,
                    "dump_sha256": _sha256_file(dump_path),
                },
                "files": [
                    {
                        "source_path": str(item.source_path),
                        "archive_path": item.archive_path,
                        "bytes": item.size,
                        "sha256": item.sha256,
                        "mode": oct(item.mode),
                    }
                    for item in included_files
                ],
            }
            manifest_bytes = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")

            archive_path: Path | None = None
            for _ in range(1000):
                candidate_archive_path, partial_path = _allocate_archive_paths(backup_dir)
                try:
                    with _open_private_tar(partial_path) as archive:
                        _write_bytes_member(archive, MANIFEST_NAME, manifest_bytes, 0o600)
                        _add_file_to_tar(archive, dump_path, DUMP_NAME, 0o600)
                        for item in included_files:
                            _add_file_to_tar(
                                archive,
                                item.source_path,
                                item.archive_path,
                                item.mode,
                            )
                    _finalize_private_archive(partial_path, candidate_archive_path)
                    archive_path = candidate_archive_path
                    break
                except SelfHostedOpsError as exc:
                    if "already exists" in str(exc):
                        continue
                    raise
            if archive_path is None:
                raise SelfHostedOpsError("Could not allocate a unique backup archive name")

        args.created_archive = archive_path
        _rotate_archives(backup_dir, args.retention_days, args.min_keep)
    except SelfHostedOpsError as exc:
        print(f"Backup failed: {exc}", file=sys.stderr)
        return 2

    print(f"Backup written: {archive_path}")
    return 0


def _create_backup_or_raise(
    *,
    compose_file: Path,
    output_dir: str,
    db_service: str,
    db_user: str,
    db_name: str,
    min_dump_bytes: int,
    retention_days: int,
    min_keep: int,
    skip_preflight: bool,
) -> Path:
    args = argparse.Namespace(
        compose_file=str(compose_file),
        output_dir=output_dir,
        db_service=db_service,
        db_user=db_user,
        db_name=db_name,
        retention_days=retention_days,
        min_keep=min_keep,
        min_dump_bytes=min_dump_bytes,
        include_file=[],
        no_default_includes=False,
        skip_preflight=skip_preflight,
    )
    code = _run_backup(args)
    if code != 0:
        raise SelfHostedOpsError("Pre-update backup failed")
    archive_path = getattr(args, "created_archive", None)
    if not isinstance(archive_path, Path):
        raise SelfHostedOpsError("Pre-update backup path was not captured")
    return archive_path


def _read_manifest(archive: tarfile.TarFile) -> dict[str, Any]:
    try:
        member = archive.getmember(MANIFEST_NAME)
    except KeyError as exc:
        raise SelfHostedOpsError(f"Archive does not contain {MANIFEST_NAME}") from exc
    if not member.isfile():
        raise SelfHostedOpsError(f"Archive does not contain readable {MANIFEST_NAME}")
    source = archive.extractfile(member)
    if source is None:
        raise SelfHostedOpsError(f"Archive does not contain readable {MANIFEST_NAME}")
    try:
        with source:
            manifest = json.load(source)
    except json.JSONDecodeError as exc:
        raise SelfHostedOpsError(f"Archive contains invalid {MANIFEST_NAME}") from exc
    if not isinstance(manifest, dict):
        raise SelfHostedOpsError(f"Archive contains invalid {MANIFEST_NAME}")
    return manifest


def _expected_dump_metadata(manifest: dict[str, Any]) -> tuple[int, str]:
    if manifest.get("archive_version") != 1:
        raise SelfHostedOpsError("Unsupported backup archive version")
    db = manifest.get("db")
    if not isinstance(db, dict):
        raise SelfHostedOpsError("Archive manifest is missing db metadata")
    if db.get("dump_path") != DUMP_NAME:
        raise SelfHostedOpsError("Archive manifest references an unexpected dump path")
    expected_size = db.get("dump_bytes")
    expected_sha = db.get("dump_sha256")
    if not isinstance(expected_size, int) or expected_size < 0:
        raise SelfHostedOpsError("Archive manifest has invalid dump size")
    if not isinstance(expected_sha, str) or len(expected_sha) != 64:
        raise SelfHostedOpsError("Archive manifest has invalid dump checksum")
    expected_sha = expected_sha.lower()
    if any(char not in "0123456789abcdef" for char in expected_sha):
        raise SelfHostedOpsError("Archive manifest has invalid dump checksum")
    return expected_size, expected_sha


def _extract_dump(archive_path: Path, destination: Path) -> Path:
    try:
        with tarfile.open(archive_path, mode="r") as archive:
            manifest = _read_manifest(archive)
            expected_size, expected_sha = _expected_dump_metadata(manifest)
            try:
                member = archive.getmember(DUMP_NAME)
            except KeyError as exc:
                raise SelfHostedOpsError(f"Archive does not contain {DUMP_NAME}") from exc
            if not member.isfile():
                raise SelfHostedOpsError(f"Archive does not contain {DUMP_NAME}")
            dump_path = destination / DUMP_NAME
            source = archive.extractfile(member)
            if source is None:
                raise SelfHostedOpsError(f"Archive does not contain readable {DUMP_NAME}")
            with source, dump_path.open("wb") as output:
                shutil.copyfileobj(source, output)
    except tarfile.TarError as exc:
        raise SelfHostedOpsError(f"Invalid backup archive: {archive_path}") from exc

    actual_size = dump_path.stat().st_size
    actual_sha = _sha256_file(dump_path)
    if actual_size != expected_size or actual_sha != expected_sha:
        raise SelfHostedOpsError("Archive dump checksum mismatch; refusing restore")
    return dump_path


def _run_restore(args: argparse.Namespace) -> int:
    try:
        if not args.confirm_overwrite:
            raise SelfHostedOpsError(
                "Restore overwrites the target database. Re-run with --confirm-overwrite."
            )
        compose_file = _require_compose_file(Path(args.compose_file))
        args.compose_file = compose_file
        archive_path = Path(args.archive).expanduser()
        if not archive_path.is_file():
            raise SelfHostedOpsError(f"Backup archive not found: {archive_path}")
        _preflight_db(args)

        compose = _compose_cmd(compose_file)

        with tempfile.TemporaryDirectory(prefix="contextify-cloud-restore.") as tmpdir:
            dump_path = _extract_dump(archive_path, Path(tmpdir))
            print("Stopping api before restore...")
            _run_checked([*compose, "stop", "api"])
            command = [
                *compose,
                "exec",
                "-T",
                args.db_service,
                "pg_restore",
                "-U",
                args.db_user,
                "-d",
                args.db_name,
                "--clean",
                "--if-exists",
                "--no-owner",
                "--no-privileges",
                "--single-transaction",
                "--exit-on-error",
            ]
            with dump_path.open("rb") as dump_handle:
                _run_checked(command, stdin=dump_handle)

        print("Restarting services...")
        _run_checked([*compose, "up", "-d", "--wait"])
    except SelfHostedOpsError as exc:
        print(f"Restore failed: {exc}", file=sys.stderr)
        return 2

    print(f"Restore completed from: {archive_path}")
    return 0


def _fetch_health_payload(url: str) -> dict[str, Any]:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise SelfHostedOpsError("Health URL must use http or https")

    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            data = response.read(MAX_HEALTH_RESPONSE_BYTES + 1)
            if len(data) > MAX_HEALTH_RESPONSE_BYTES:
                raise SelfHostedOpsError(f"Health check response too large from {url}")
    except SelfHostedOpsError:
        raise
    except Exception as exc:
        raise SelfHostedOpsError(f"Health check failed for {url}: {exc}") from exc

    try:
        payload = json.loads(data.decode("utf-8"))
    except Exception as exc:
        raise SelfHostedOpsError(f"Health check returned non-JSON response from {url}") from exc
    if not isinstance(payload, dict):
        raise SelfHostedOpsError(f"Health check returned non-object JSON from {url}")
    return payload


def _check_health(url: str) -> None:
    payload = _fetch_health_payload(url)
    if str(payload.get("status", "")).lower() not in {"ok", "degraded"}:
        raise SelfHostedOpsError(f"Health check returned unexpected payload from {url}: {payload}")


def _health_url_from_public_url(value: str) -> str:
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme not in {"http", "https"}:
        raise SelfHostedOpsError("Public URL must use http or https")
    if parsed.path.rstrip("/") == "/api/v1/health":
        return value
    health_url = parsed._replace(path="/api/v1/health", params="", query="", fragment="")
    return urllib.parse.urlunparse(health_url)


def _parse_compose_ps(output: str, services: set[str]) -> dict[str, dict[str, Any]]:
    text = output.strip()
    if not text:
        return {}

    parsed: Any
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            parsed = [parsed]
    except json.JSONDecodeError:
        rows = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            rows.append(item)
        parsed = rows

    if not isinstance(parsed, list):
        return {}

    result: dict[str, dict[str, Any]] = {}
    for item in parsed:
        if not isinstance(item, dict):
            continue
        service = item.get("Service") or item.get("service") or item.get("Name") or item.get("name")
        if not isinstance(service, str) or service not in services:
            continue
        result[service] = item
    return result


def _service_field(info: dict[str, Any], *names: str) -> str:
    for name in names:
        value = info.get(name)
        if isinstance(value, str):
            return value
    return ""


def _check_compose_services(
    compose_file: Path,
    *,
    api_service: str,
    db_service: str,
) -> HealthCheck:
    services = {api_service, db_service}
    output = _run_capture(
        [*_compose_cmd(compose_file), "ps", "--format", "json", api_service, db_service]
    )
    parsed = _parse_compose_ps(output, services)
    missing = sorted(services - set(parsed))
    if missing:
        return HealthCheck(
            name="compose_services",
            status="failed",
            message=f"Missing compose service state for: {', '.join(missing)}",
            detail={"services": parsed},
        )

    degraded: list[str] = []
    detail: dict[str, Any] = {}
    for service, info in sorted(parsed.items()):
        state = _service_field(info, "State", "state").lower()
        health = _service_field(info, "Health", "health").lower()
        detail[service] = {"state": state or None, "health": health or None}
        if state and state != "running":
            degraded.append(f"{service} state={state}")
        if health and health not in {"healthy", "none", "running"}:
            degraded.append(f"{service} health={health}")

    if degraded:
        return HealthCheck(
            name="compose_services",
            status="degraded",
            message="; ".join(degraded),
            detail=detail,
        )
    return HealthCheck(
        name="compose_services",
        status="ok",
        message=f"{api_service} and {db_service} are running",
        detail=detail,
    )


def _check_database_ready(
    compose_file: Path,
    *,
    db_service: str,
    db_user: str,
) -> HealthCheck:
    command = [
        *_compose_cmd(compose_file),
        "exec",
        "-T",
        db_service,
        "pg_isready",
        "-U",
        db_user,
        "-q",
    ]
    ok, error = _run_success(command)
    if ok:
        return HealthCheck(
            name="database",
            status="ok",
            message=f"{db_service} accepts PostgreSQL connections",
        )
    return HealthCheck(
        name="database",
        status="failed",
        message=f"{db_service} is not accepting PostgreSQL connections",
        detail={"error": error} if error else None,
    )


def _check_api_health(name: str, url: str) -> HealthCheck:
    payload = _fetch_health_payload(url)
    status = str(payload.get("status", "")).lower()
    detail: dict[str, Any] = {"url": url, "remote_status": status}
    self_hosted = payload.get("self_hosted")
    if isinstance(self_hosted, bool):
        detail["self_hosted"] = self_hosted
    if status == "ok":
        return HealthCheck(
            name=name,
            status="ok",
            message=f"{url} returned status=ok",
            detail=detail,
        )
    if status == "degraded":
        return HealthCheck(
            name=name,
            status="degraded",
            message=f"{url} returned status=degraded",
            detail=detail,
        )
    return HealthCheck(
        name=name,
        status="failed",
        message=f"{url} returned unexpected payload",
        detail=detail,
    )


def _overall_health_status(checks: list[HealthCheck]) -> str:
    if any(check.status == "failed" for check in checks):
        return "failed"
    if any(check.status == "degraded" for check in checks):
        return "degraded"
    return "ok"


def _self_hosted_from_checks(checks: list[HealthCheck]) -> bool | None:
    for preferred in ("local_api", "public_api"):
        for check in checks:
            if check.name != preferred or check.detail is None:
                continue
            value = check.detail.get("self_hosted")
            if isinstance(value, bool):
                return value
    return None


def _health_payload(checks: list[HealthCheck]) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "status": _overall_health_status(checks),
        "checks": [
            {
                "name": check.name,
                "status": check.status,
                "message": check.message,
                **({"detail": check.detail} if check.detail is not None else {}),
            }
            for check in checks
        ],
    }
    self_hosted = _self_hosted_from_checks(checks)
    if self_hosted is not None:
        payload["self_hosted"] = self_hosted
    return payload


def _print_health_text(payload: dict[str, Any]) -> None:
    print(f"Self-hosted health: {payload['status']}")
    if "self_hosted" in payload:
        print(f"Self-hosted mode: {'yes' if payload['self_hosted'] else 'no'}")
    for check in payload["checks"]:
        print(f"- {check['name']}: {check['status']} - {check['message']}")


def _safe_health_check(name: str, callback: Callable[[], HealthCheck]) -> HealthCheck:
    try:
        return callback()
    except SelfHostedOpsError as exc:
        return HealthCheck(name=name, status="failed", message=str(exc))


def _run_health(args: argparse.Namespace) -> int:
    checks: list[HealthCheck] = []
    try:
        compose_file = _require_compose_file(Path(args.compose_file))
        checks.append(
            HealthCheck(
                name="compose_file",
                status="ok",
                message=f"Found compose file: {compose_file}",
                detail={"path": str(compose_file)},
            )
        )
        checks.append(
            _safe_health_check(
                "compose_services",
                lambda: _check_compose_services(
                    compose_file,
                    api_service=args.api_service,
                    db_service=args.db_service,
                ),
            )
        )
        checks.append(
            _safe_health_check(
                "database",
                lambda: _check_database_ready(
                    compose_file,
                    db_service=args.db_service,
                    db_user=args.db_user,
                ),
            )
        )
    except SelfHostedOpsError as exc:
        checks.append(HealthCheck(name="compose_file", status="failed", message=str(exc)))

    checks.append(
        _safe_health_check(
            "local_api",
            lambda: _check_api_health("local_api", args.local_health_url),
        )
    )
    if args.public_url:
        checks.append(
            _safe_health_check(
                "public_api",
                lambda: _check_api_health(
                    "public_api",
                    _health_url_from_public_url(args.public_url),
                ),
            )
        )

    payload = _health_payload(checks)
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        _print_health_text(payload)

    status = payload["status"]
    if status == "ok":
        return 0
    if status == "degraded":
        return 1
    return 2


def _rollback_instructions(
    repo_dir: Path,
    compose_file: Path,
    previous_sha: str,
    backup_path: Path | None,
) -> str:
    lines = [
        "Rollback procedure:",
        f"  cd {shlex.quote(str(repo_dir))}",
        f"  git checkout {shlex.quote(previous_sha)}",
        f"  docker compose -f {shlex.quote(str(compose_file))} build api",
        f"  docker compose -f {shlex.quote(str(compose_file))} up -d --wait",
    ]
    if backup_path is not None:
        lines.extend(
            [
                "  # If the migration itself damaged data, restore the pre-update backup:",
                f"  contextify-cloud restore {shlex.quote(str(backup_path))} "
                f"--compose-file {shlex.quote(str(compose_file))} --confirm-overwrite",
            ]
        )
    else:
        lines.extend(
            [
                "  # No pre-update backup archive path is available for this run.",
                "  # Restore from your latest known-good backup if data was damaged.",
            ]
        )
    return "\n".join(lines)


def _current_git_upstream(repo_dir: Path) -> str:
    try:
        return _run_capture([
            "git",
            "-C",
            str(repo_dir),
            "rev-parse",
            "--abbrev-ref",
            "--symbolic-full-name",
            "@{u}",
        ])
    except SelfHostedOpsError as exc:
        raise SelfHostedOpsError(
            "Current branch has no upstream tracking branch. Set an upstream "
            "with `git branch --set-upstream-to=origin/<branch>` or rerun "
            "update with --skip-pull after placing the intended release code."
        ) from exc


def _run_update(args: argparse.Namespace) -> int:
    repo_dir = Path(args.repo_dir).expanduser().resolve()
    compose_candidate = _resolve_repo_path(args.compose_file, repo_dir)
    backup_path: Path | None = None
    try:
        compose_file = _require_compose_file(compose_candidate)
        previous_sha = _run_capture(["git", "-C", str(repo_dir), "rev-parse", "HEAD"])
        print(f"Current revision: {previous_sha}")

        if not args.skip_backup:
            backup_dir = _resolve_repo_path(args.backup_dir, repo_dir)
            backup_path = _create_backup_or_raise(
                compose_file=compose_file,
                output_dir=str(backup_dir),
                db_service=args.db_service,
                db_user=args.db_user,
                db_name=args.db_name,
                min_dump_bytes=args.min_dump_bytes,
                retention_days=args.retention_days,
                min_keep=args.min_keep,
                skip_preflight=args.skip_preflight,
            )

        if args.skip_pull:
            print("Skipping git pull (--skip-pull).")
        else:
            upstream = _current_git_upstream(repo_dir)
            print(f"Pulling latest code from {upstream}...")
            _run_checked(["git", "-C", str(repo_dir), "pull", "--ff-only"])

        compose = _compose_cmd(compose_file)
        print("Building api image...")
        _run_checked([*compose, "build", "api"])

        print("Ensuring database is running...")
        _run_checked([*compose, "up", "-d", "db"])

        print("Stopping api before migrations...")
        _run_checked([*compose, "stop", "api"])

        print("Running migrations...")
        _run_checked([*compose, "run", "--rm", "api", "alembic", "upgrade", "head"])

        print("Restarting services...")
        _run_checked([*compose, "up", "-d", "--wait"])

        print(f"Checking health: {args.health_url}")
        _check_health(args.health_url)
    except SelfHostedOpsError as exc:
        print(f"Update failed: {exc}", file=sys.stderr)
        previous = locals().get("previous_sha", "<previous-sha>")
        rollback_compose = Path(str(locals().get("compose_file", compose_candidate)))
        print(
            _rollback_instructions(repo_dir, rollback_compose, str(previous), backup_path),
            file=sys.stderr,
        )
        return 2

    print("Update completed successfully.")
    return 0


def _launchd_plist(args: argparse.Namespace) -> str:
    repo_dir = Path(args.repo_dir).expanduser()
    log_dir = Path(args.log_dir).expanduser()
    command_prefix = " ".join(shlex.quote(part) for part in shlex.split(args.command))
    if args.job == "backup":
        subcommand = (
            "backup "
            f"--compose-file {shlex.quote(args.compose_file)} "
            f"--output-dir {shlex.quote(args.output_dir)} "
            f"--retention-days {shlex.quote(str(args.retention_days))}"
        )
        log_name = "contextify-cloud-backup"
    else:
        subcommand = (
            "update "
            f"--repo-dir {shlex.quote(str(repo_dir))} "
            f"--compose-file {shlex.quote(args.compose_file)} "
            f"--backup-dir {shlex.quote(args.output_dir)} "
            f"--retention-days {shlex.quote(str(args.retention_days))} "
            f"--health-url {shlex.quote(args.health_url)}"
        )
        log_name = "contextify-cloud-update"

    command = f"cd {shlex.quote(str(repo_dir))} && {command_prefix} {subcommand}"
    escaped_command = xml_escape(command)
    escaped_repo_dir = xml_escape(str(repo_dir))
    label = args.label or f"com.contextify.cloud.{args.job}"
    escaped_label = xml_escape(label)
    escaped_stdout = xml_escape(str(log_dir / f"{log_name}.log"))
    escaped_stderr = xml_escape(str(log_dir / f"{log_name}.err.log"))
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{escaped_label}</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/zsh</string>
    <string>-lc</string>
    <string>{escaped_command}</string>
  </array>
  <key>WorkingDirectory</key>
  <string>{escaped_repo_dir}</string>
  <key>StartCalendarInterval</key>
  <dict>
    <key>Hour</key>
    <integer>{args.hour}</integer>
    <key>Minute</key>
    <integer>{args.minute}</integer>
  </dict>
  <key>StandardOutPath</key>
  <string>{escaped_stdout}</string>
  <key>StandardErrorPath</key>
  <string>{escaped_stderr}</string>
</dict>
</plist>
"""


def _run_launchd_plist(args: argparse.Namespace) -> int:
    try:
        plist = _launchd_plist(args)
        if args.output:
            output = Path(args.output).expanduser()
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(plist, encoding="utf-8")
            print(f"LaunchAgent plist written: {output}")
        else:
            print(plist, end="")
        return 0
    except (OSError, ValueError) as exc:
        print(f"LaunchAgent plist failed: {exc}", file=sys.stderr)
        return 2


def _bounded_int(name: str, minimum: int, maximum: int) -> Callable[[str], int]:
    def parse(value: str) -> int:
        try:
            parsed = int(value)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(
                f"{name} must be an integer between {minimum} and {maximum}"
            ) from exc
        if parsed < minimum or parsed > maximum:
            raise argparse.ArgumentTypeError(f"{name} must be between {minimum} and {maximum}")
        return parsed

    return parse


def add_self_hosted_ops_parsers(subparsers: Any) -> None:
    backup = subparsers.add_parser(
        "backup",
        help="Write a self-hosted backup archive",
        description="Write a self-hosted backup archive using docker compose pg_dump.",
    )
    backup.add_argument("--compose-file", default="docker-compose.selfhosted.yml")
    backup.add_argument("--output-dir", default="backups/self-hosted")
    backup.add_argument("--db-service", default="db")
    backup.add_argument("--db-user", default="contextify")
    backup.add_argument("--db-name", default="contextify")
    backup.add_argument("--retention-days", type=int, default=30)
    backup.add_argument("--min-keep", type=int, default=3)
    backup.add_argument("--min-dump-bytes", type=int, default=MIN_DUMP_BYTES_DEFAULT)
    backup.add_argument("--include-file", action="append", default=[])
    backup.add_argument("--no-default-includes", action="store_true")
    backup.add_argument("--skip-preflight", action="store_true")
    backup.set_defaults(func=_run_backup)

    restore = subparsers.add_parser(
        "restore",
        help="Restore a self-hosted backup archive",
        description="Restore a self-hosted backup archive using docker compose pg_restore.",
    )
    restore.add_argument("archive")
    restore.add_argument("--compose-file", default="docker-compose.selfhosted.yml")
    restore.add_argument("--db-service", default="db")
    restore.add_argument("--db-user", default="contextify")
    restore.add_argument("--db-name", default="contextify")
    restore.add_argument("--confirm-overwrite", action="store_true")
    restore.add_argument("--skip-preflight", action="store_true")
    restore.set_defaults(func=_run_restore)

    update = subparsers.add_parser(
        "update",
        help="Update a self-hosted server",
        description="Pull, rebuild, migrate, restart, and health-check a self-hosted server.",
    )
    update.add_argument("--repo-dir", default=str(Path.cwd()))
    update.add_argument("--compose-file", default="docker-compose.selfhosted.yml")
    update.add_argument("--backup-dir", default="backups/self-hosted")
    update.add_argument("--db-service", default="db")
    update.add_argument("--db-user", default="contextify")
    update.add_argument("--db-name", default="contextify")
    update.add_argument("--retention-days", type=int, default=30)
    update.add_argument("--min-keep", type=int, default=3)
    update.add_argument("--min-dump-bytes", type=int, default=MIN_DUMP_BYTES_DEFAULT)
    update.add_argument("--health-url", default="http://127.0.0.1:8443/api/v1/health")
    update.add_argument("--skip-backup", action="store_true")
    update.add_argument("--skip-pull", action="store_true")
    update.add_argument("--skip-preflight", action="store_true")
    update.set_defaults(func=_run_update)

    health = subparsers.add_parser(
        "health",
        help="Check a self-hosted server",
        description="Check self-hosted compose, database, and API health.",
    )
    health.add_argument("--compose-file", default="docker-compose.selfhosted.yml")
    health.add_argument("--api-service", default="api")
    health.add_argument("--db-service", default="db")
    health.add_argument("--db-user", default="contextify")
    health.add_argument("--local-health-url", default="http://127.0.0.1:8443/api/v1/health")
    health.add_argument(
        "--public-url",
        help="Optional public base URL or /api/v1/health URL to check.",
    )
    health.add_argument("--json", action="store_true")
    health.set_defaults(func=_run_health)

    launchd = subparsers.add_parser(
        "launchd-plist",
        help="Print or write a macOS LaunchAgent plist for scheduled backups",
        description=(
            "Print or write a macOS LaunchAgent plist for scheduled self-hosted maintenance."
        ),
    )
    launchd.add_argument("--job", choices=["backup", "update"], default="backup")
    launchd.add_argument("--repo-dir", default=str(Path.cwd()))
    launchd.add_argument("--command", default="scripts/contextify-cloud-selfhosted")
    launchd.add_argument("--compose-file", default="docker-compose.selfhosted.yml")
    launchd.add_argument("--output-dir", default="backups/self-hosted")
    launchd.add_argument("--retention-days", type=int, default=30)
    launchd.add_argument("--health-url", default="http://127.0.0.1:8443/api/v1/health")
    launchd.add_argument("--hour", type=_bounded_int("hour", 0, 23), default=4)
    launchd.add_argument("--minute", type=_bounded_int("minute", 0, 59), default=0)
    launchd.add_argument("--label")
    launchd.add_argument("--log-dir", default="~/Library/Logs")
    launchd.add_argument("--output")
    launchd.set_defaults(func=_run_launchd_plist)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m contextify_cloud.cli.self_hosted_ops",
        description="Run Contextify self-hosted maintenance commands.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    add_self_hosted_ops_parsers(subparsers)
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
