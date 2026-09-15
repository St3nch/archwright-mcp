"""Binary-safe, hash-verified transfers over the hardened SFTP transport."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from archwright_mcp.errors import ArchwrightError, ErrorCode, ValidationError
from archwright_mcp.transport.ssh import SshTransport

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_STAGING_COMPONENT = re.compile(r"^[A-Za-z0-9._-]+$")
_STAGING_ROOTS = (
    PurePosixPath("/var/lib/archwright/runs"),
    PurePosixPath("/var/lib/archwright/jobs"),
    PurePosixPath("/var/lib/archwright/uploads"),
)


@dataclass(frozen=True, slots=True)
class TransferResult:
    remote_path: PurePosixPath
    sha256: str
    size_bytes: int


def sha256_file(path: Path, *, maximum_bytes: int | None = None) -> tuple[str, int]:
    """Hash a local regular file without following a final-component symlink."""

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValidationError(
            "unable to open transfer source", details={"path": str(path)}
        ) from exc
    digest = hashlib.sha256()
    size = 0
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValidationError("transfer source must be a regular file")
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
            if maximum_bytes is not None and size > maximum_bytes:
                raise ValidationError("transfer source exceeds its size limit")
    finally:
        os.close(descriptor)
    return digest.hexdigest(), size


def validate_staging_path(path: PurePosixPath) -> None:
    """Require transfer destinations to remain inside an Archwright staging root."""

    if not path.is_absolute() or ".." in path.parts or path.name in {"", ".", ".."}:
        raise ValidationError("remote transfer path must be a normalized absolute file path")
    if not any(path.is_relative_to(root) and path != root for root in _STAGING_ROOTS):
        raise ValidationError("remote transfer path is outside Archwright staging roots")
    relative_parts = next(
        path.relative_to(root).parts for root in _STAGING_ROOTS if path.is_relative_to(root)
    )
    if any(not _SAFE_STAGING_COMPONENT.fullmatch(part) for part in relative_parts):
        raise ValidationError("remote transfer path must use generated safe components")


def sftp_quote(value: str) -> str:
    """Quote one generated SFTP batch argument."""

    if "\x00" in value or "\n" in value or "\r" in value:
        raise ValidationError("SFTP path contains a forbidden control character")
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    for character in "*?[]":
        escaped = escaped.replace(character, f"\\{character}")
    return f'"{escaped}"'


class VerifiedTransfer:
    def __init__(self, transport: SshTransport) -> None:
        self.transport = transport

    async def upload_file(
        self,
        local_path: Path,
        remote_path: PurePosixPath,
        *,
        timeout_seconds: float = 60,
        maximum_bytes: int = 64 * 1024 * 1024,
    ) -> TransferResult:
        validate_staging_path(remote_path)
        if maximum_bytes < 1:
            raise ValidationError("transfer size limit must be positive")
        try:
            source_fd = os.open(
                local_path,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
            )
        except OSError as exc:
            raise ValidationError("unable to open transfer source") from exc
        try:
            descriptor, raw_snapshot = tempfile.mkstemp(prefix="archwright-snapshot-")
        except OSError as exc:
            os.close(source_fd)
            raise ValidationError("unable to create transfer snapshot") from exc
        snapshot = Path(raw_snapshot)
        digest = hashlib.sha256()
        size = 0
        try:
            metadata = os.fstat(source_fd)
            if not stat.S_ISREG(metadata.st_mode):
                raise ValidationError("transfer source must be a regular file")
            os.fchmod(descriptor, 0o600)
            while chunk := os.read(source_fd, 1024 * 1024):
                size += len(chunk)
                if size > maximum_bytes:
                    raise ValidationError("transfer source exceeds its size limit")
                digest.update(chunk)
                view = memoryview(chunk)
                while view:
                    written = os.write(descriptor, view)
                    view = view[written:]
            os.fsync(descriptor)
            local_sha256 = digest.hexdigest()
            batch = (
                f"put {sftp_quote(str(snapshot))} {sftp_quote(str(remote_path))}\n"
                f"chmod 0600 {sftp_quote(str(remote_path))}\n"
            ).encode()
            uploaded = await self.transport.run_sftp_batch(batch, timeout_seconds=timeout_seconds)
            if not uploaded.succeeded:
                raise ArchwrightError(
                    ErrorCode.TRANSFER_FAILED,
                    "SFTP upload failed",
                    details={"exit_code": uploaded.exit_code},
                )
            remote_sha256 = await self.remote_sha256(remote_path, timeout_seconds=timeout_seconds)
            if remote_sha256 != local_sha256:
                raise ArchwrightError(
                    ErrorCode.REMOTE_HASH_MISMATCH,
                    "uploaded file hash does not match local source",
                    details={"remote_path": str(remote_path)},
                )
            return TransferResult(remote_path=remote_path, sha256=local_sha256, size_bytes=size)
        except OSError as exc:
            raise ValidationError("unable to snapshot transfer source") from exc
        finally:
            os.close(source_fd)
            os.close(descriptor)
            snapshot.unlink(missing_ok=True)

    async def upload_bytes(
        self,
        content: bytes,
        remote_path: PurePosixPath,
        *,
        timeout_seconds: float = 60,
        maximum_bytes: int = 64 * 1024 * 1024,
    ) -> TransferResult:
        """Upload bytes without placing content in an argv or shell string."""

        descriptor, raw_path = tempfile.mkstemp(prefix="archwright-upload-")
        local_path = Path(raw_path)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            return await self.upload_file(
                local_path,
                remote_path,
                timeout_seconds=timeout_seconds,
                maximum_bytes=maximum_bytes,
            )
        finally:
            local_path.unlink(missing_ok=True)

    async def download_file(
        self,
        remote_path: PurePosixPath,
        local_path: Path,
        *,
        timeout_seconds: float = 60,
    ) -> TransferResult:
        """Download a staged file and verify it against the target's hash."""

        validate_staging_path(remote_path)
        if not local_path.is_absolute():
            raise ValidationError("local transfer destination must be absolute")
        remote_sha256 = await self.remote_sha256(remote_path, timeout_seconds=timeout_seconds)
        local_path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, raw_temporary = tempfile.mkstemp(
            prefix=".archwright-download-", dir=local_path.parent
        )
        temporary = Path(raw_temporary)
        os.close(descriptor)
        try:
            batch = f"get {sftp_quote(str(remote_path))} {sftp_quote(str(temporary))}\n".encode()
            downloaded = await self.transport.run_sftp_batch(batch, timeout_seconds=timeout_seconds)
            if not downloaded.succeeded:
                raise ArchwrightError(
                    ErrorCode.TRANSFER_FAILED,
                    "SFTP download failed",
                    details={"exit_code": downloaded.exit_code},
                )
            local_sha256, size = sha256_file(temporary)
            if local_sha256 != remote_sha256:
                raise ArchwrightError(
                    ErrorCode.REMOTE_HASH_MISMATCH,
                    "downloaded file hash does not match remote source",
                    details={"remote_path": str(remote_path)},
                )
            os.replace(temporary, local_path)
        finally:
            temporary.unlink(missing_ok=True)
        return TransferResult(remote_path=remote_path, sha256=remote_sha256, size_bytes=size)

    async def remote_sha256(self, remote_path: PurePosixPath, *, timeout_seconds: float) -> str:
        validate_staging_path(remote_path)
        result = await self.transport.run(
            ["/usr/bin/sha256sum", "--", str(remote_path)],
            timeout_seconds=timeout_seconds,
        )
        if not result.succeeded:
            raise ArchwrightError(
                ErrorCode.TRANSFER_FAILED,
                "unable to hash remote transfer artifact",
                details={"exit_code": result.exit_code},
            )
        candidate = result.stdout.split(maxsplit=1)[0].lower() if result.stdout.strip() else ""
        if not _SHA256.fullmatch(candidate):
            raise ArchwrightError(
                ErrorCode.TRANSFER_FAILED,
                "remote hash output was malformed",
            )
        return candidate
