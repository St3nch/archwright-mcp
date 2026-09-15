from __future__ import annotations

import hashlib
from pathlib import Path, PurePosixPath

import pytest

from archwright_mcp.errors import ArchwrightError, ErrorCode, ValidationError
from archwright_mcp.transport.ssh import ProcessOutput
from archwright_mcp.transport.transfer import (
    VerifiedTransfer,
    sftp_quote,
    sha256_file,
    validate_staging_path,
)


class FakeTransport:
    def __init__(
        self,
        remote_hash: str,
        *,
        sftp_exit: int = 0,
        download_content: bytes | None = None,
    ) -> None:
        self.remote_hash = remote_hash
        self.sftp_exit = sftp_exit
        self.download_content = download_content
        self.batch: bytes | None = None
        self.remote_argv: list[str] | None = None

    async def run_sftp_batch(
        self, batch: bytes, *, timeout_seconds: float, output_limit_bytes: int | None = None
    ) -> ProcessOutput:
        self.batch = batch
        if self.download_content is not None and batch.startswith(b"get "):
            local = Path(batch.decode().split()[-1].strip('"'))
            local.write_bytes(self.download_content)
        return ProcessOutput(self.sftp_exit, "", "sftp failed", False, False)

    async def run(
        self,
        remote_argv: list[str],
        *,
        timeout_seconds: float,
        output_limit_bytes: int | None = None,
    ) -> ProcessOutput:
        self.remote_argv = remote_argv
        return ProcessOutput(0, f"{self.remote_hash}  file\n", "", False, False)


@pytest.mark.parametrize(
    "path",
    [
        PurePosixPath("relative/file"),
        PurePosixPath("/etc/passwd"),
        PurePosixPath("/var/lib/archwright/runs"),
        PurePosixPath("/var/lib/archwright/runs/../receipts/file"),
    ],
)
def test_staging_path_refuses_escape(path: PurePosixPath) -> None:
    with pytest.raises(ValidationError):
        validate_staging_path(path)


def test_sftp_quote_escapes_quotes_and_backslashes() -> None:
    assert sftp_quote('/tmp/a "file"\\x') == '"/tmp/a \\"file\\"\\\\x"'


def test_sftp_quote_escapes_glob_metacharacters() -> None:
    assert sftp_quote("/tmp/a[*?]") == '"/tmp/a\\[\\*\\?\\]"'


def test_sha256_file_rejects_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_bytes(b"content")
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(ValidationError, match="unable to open"):
        sha256_file(link)


@pytest.mark.asyncio
async def test_upload_rejects_symlink_source_before_sftp(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_bytes(b"content")
    link = tmp_path / "link"
    link.symlink_to(target)
    fake = FakeTransport(hashlib.sha256(b"content").hexdigest())
    with pytest.raises(ValidationError, match="open transfer source"):
        await VerifiedTransfer(fake).upload_file(  # type: ignore[arg-type]
            link, PurePosixPath("/var/lib/archwright/uploads/test/payload")
        )
    assert fake.batch is None


@pytest.mark.asyncio
async def test_upload_verifies_hash_and_uses_sftp_stdin(tmp_path: Path) -> None:
    source = tmp_path / "payload"
    source.write_bytes(b"hello")
    digest = hashlib.sha256(b"hello").hexdigest()
    fake = FakeTransport(digest)
    transfer = VerifiedTransfer(fake)  # type: ignore[arg-type]
    remote = PurePosixPath("/var/lib/archwright/uploads/test/payload")
    result = await transfer.upload_file(source, remote)
    assert result.sha256 == digest
    assert result.size_bytes == 5
    assert fake.batch is not None and fake.batch.startswith(b"put ")
    assert b"\nchmod 0600 " in fake.batch
    assert fake.remote_argv == ["/usr/bin/sha256sum", "--", str(remote)]


@pytest.mark.asyncio
async def test_upload_hash_mismatch_fails_closed(tmp_path: Path) -> None:
    source = tmp_path / "payload"
    source.write_bytes(b"hello")
    fake = FakeTransport("0" * 64)
    transfer = VerifiedTransfer(fake)  # type: ignore[arg-type]
    with pytest.raises(ArchwrightError) as captured:
        await transfer.upload_file(
            source, PurePosixPath("/var/lib/archwright/uploads/test/payload")
        )
    assert captured.value.code is ErrorCode.REMOTE_HASH_MISMATCH


@pytest.mark.asyncio
async def test_upload_enforces_size_while_snapshotting(tmp_path: Path) -> None:
    source = tmp_path / "payload"
    source.write_bytes(b"too large")
    fake = FakeTransport("0" * 64)
    transfer = VerifiedTransfer(fake)  # type: ignore[arg-type]
    with pytest.raises(ValidationError, match="size limit"):
        await transfer.upload_file(
            source,
            PurePosixPath("/var/lib/archwright/uploads/test/payload"),
            maximum_bytes=3,
        )
    assert fake.batch is None


@pytest.mark.asyncio
async def test_sftp_failure_does_not_attempt_remote_hash(tmp_path: Path) -> None:
    source = tmp_path / "payload"
    source.write_bytes(b"hello")
    fake = FakeTransport("0" * 64, sftp_exit=1)
    transfer = VerifiedTransfer(fake)  # type: ignore[arg-type]
    with pytest.raises(ArchwrightError) as captured:
        await transfer.upload_file(
            source, PurePosixPath("/var/lib/archwright/uploads/test/payload")
        )
    assert captured.value.code is ErrorCode.TRANSFER_FAILED
    assert fake.remote_argv is None


@pytest.mark.asyncio
async def test_download_is_verified_before_atomic_destination_replace(tmp_path: Path) -> None:
    content = b"downloaded\x00bytes"
    digest = hashlib.sha256(content).hexdigest()
    fake = FakeTransport(digest, download_content=content)
    transfer = VerifiedTransfer(fake)  # type: ignore[arg-type]
    destination = (tmp_path / "result").resolve()
    destination.write_bytes(b"old")
    result = await transfer.download_file(
        PurePosixPath("/var/lib/archwright/uploads/test/result"), destination
    )
    assert result.sha256 == digest
    assert destination.read_bytes() == content


@pytest.mark.asyncio
async def test_bad_download_preserves_existing_destination(tmp_path: Path) -> None:
    fake = FakeTransport("0" * 64, download_content=b"corrupt")
    transfer = VerifiedTransfer(fake)  # type: ignore[arg-type]
    destination = (tmp_path / "result").resolve()
    destination.write_bytes(b"old")
    with pytest.raises(ArchwrightError) as captured:
        await transfer.download_file(
            PurePosixPath("/var/lib/archwright/uploads/test/result"), destination
        )
    assert captured.value.code is ErrorCode.REMOTE_HASH_MISMATCH
    assert destination.read_bytes() == b"old"
