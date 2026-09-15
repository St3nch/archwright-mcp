from __future__ import annotations

import base64
import hashlib
import json
import os
import pwd
import subprocess
from pathlib import Path

import pytest

from archwright_mcp.target import runtime


def operation_id() -> str:
    return "op-" + "a" * 32


def write_supervisor_request(root: Path, *, script: bytes, **changes: object) -> None:
    operation = root / operation_id()
    operation.mkdir(parents=True)
    (operation / "script").write_bytes(script)
    (operation / "script").chmod(0o700)
    manifest: dict[str, object] = {
        "operation_id": operation_id(),
        "script_size": len(script),
        "script_sha256": hashlib.sha256(script).hexdigest(),
        "interpreter": "/usr/bin/bash",
        "arguments": [],
        "privilege": "root",
        "user": None,
        "working_directory": "/",
        "resolved_environment": {},
        "timeout_seconds": 5,
        "output_limit_bytes": 1024,
        "output_policy": "capture",
    }
    manifest.update(changes)
    (operation / "request.json").write_text(json.dumps(manifest))


def test_operation_names_are_generated_from_exact_id(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(runtime, "JOB_ROOT", tmp_path)
    job, unit, path = runtime._operation_parts(operation_id())
    assert job == "job-" + "a" * 32
    assert unit == "archwright-job-" + "a" * 32 + ".service"
    assert path == tmp_path / operation_id()
    with pytest.raises(runtime.RuntimeRefusal):
        runtime._operation_parts("../../evil")


def test_manifest_reader_rejects_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_text("{}")
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(runtime.RuntimeRefusal, match="open staged"):
        runtime._read_bounded_json(link)


def test_supervisor_captures_bounded_output(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(runtime, "JOB_ROOT", tmp_path)
    monkeypatch.setattr(runtime, "_validate_live", lambda manifest: None)
    write_supervisor_request(
        tmp_path,
        script=b"#!/bin/bash\nprintf '%02048d' 0\nprintf '%02048d' 0 >&2\n",
        output_limit_bytes=128,
    )
    assert runtime.supervise(operation_id()) == 0
    result = json.loads((tmp_path / operation_id() / "result.json").read_text())
    assert result["state"] == "succeeded"
    assert result["stdout_truncated"] is True
    assert result["stderr_truncated"] is True
    assert len(result["stdout_b64"]) < 256
    assert not (tmp_path / operation_id() / "request.json").exists()


def test_sensitive_supervisor_discards_output(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(runtime, "JOB_ROOT", tmp_path)
    monkeypatch.setattr(runtime, "_validate_live", lambda manifest: None)
    write_supervisor_request(
        tmp_path,
        script=b"#!/bin/bash\nprintf '%s' secret-sentinel\n",
        output_policy="discard",
    )
    assert runtime.supervise(operation_id()) == 0
    result_text = (tmp_path / operation_id() / "result.json").read_text()
    assert "secret-sentinel" not in result_text
    assert json.loads(result_text)["output_suppressed"] is True


def test_supervisor_timeout_kills_process_group(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(runtime, "JOB_ROOT", tmp_path)
    monkeypatch.setattr(runtime, "_validate_live", lambda manifest: None)
    write_supervisor_request(
        tmp_path,
        script=b"#!/bin/bash\nsleep 30 &\nwait\n",
        timeout_seconds=0.01,
    )
    assert runtime.supervise(operation_id()) == 1
    result = json.loads((tmp_path / operation_id() / "result.json").read_text())
    assert result["state"] == "timed_out"
    assert result["timed_out"] is True


def test_supervisor_timeout_kills_descendant_after_leader_exits(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(runtime, "JOB_ROOT", tmp_path)
    monkeypatch.setattr(runtime, "_TERMINATION_GRACE_SECONDS", 0.05)
    monkeypatch.setattr(runtime, "_validate_live", lambda manifest: None)
    write_supervisor_request(
        tmp_path,
        script=(b"#!/bin/bash\n(trap '' TERM; while :; do /usr/bin/sleep 1; done) &\nexit 0\n"),
        timeout_seconds=0.01,
    )
    assert runtime.supervise(operation_id()) == 1
    result = json.loads((tmp_path / operation_id() / "result.json").read_text())
    assert result["state"] == "timed_out"


def test_supervisor_runs_user_script_through_verified_descriptor(
    tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    account = pwd.getpwnam("nobody")
    try:
        subprocess.run(
            ["/usr/bin/true"],
            check=True,
            user=account.pw_uid,
            group=account.pw_gid,
            extra_groups=[account.pw_gid],
        )
    except PermissionError:
        pytest.skip("test container cannot exercise credential dropping")
    monkeypatch.setattr(runtime, "JOB_ROOT", tmp_path)
    monkeypatch.setattr(runtime, "_validate_live", lambda manifest: None)
    write_supervisor_request(
        tmp_path,
        script=b"#!/bin/bash\n/usr/bin/id -u\n",
        privilege="user",
        user=account.pw_name,
        working_directory="/tmp",
    )
    assert runtime.supervise(operation_id()) == 0
    result = json.loads((tmp_path / operation_id() / "result.json").read_text())
    assert result["state"] == "succeeded"
    assert result["stdout_b64"] == base64.b64encode(f"{account.pw_uid}\n".encode()).decode()


def test_supervisor_timeout_applies_after_output_pipes_close(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(runtime, "JOB_ROOT", tmp_path)
    monkeypatch.setattr(runtime, "_validate_live", lambda manifest: None)
    write_supervisor_request(
        tmp_path,
        script=b"#!/bin/bash\nexec >/dev/null 2>&1\n/usr/bin/sleep 1\n",
        timeout_seconds=0.02,
    )
    assert runtime.supervise(operation_id()) == 1
    result = json.loads((tmp_path / operation_id() / "result.json").read_text())
    assert result["state"] == "timed_out"


def test_prepare_creates_private_operation_staging(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    upload_root = tmp_path / "uploads"
    upload_root.mkdir()
    account = pwd.getpwuid(os.getuid())
    monkeypatch.setattr(runtime, "UPLOAD_ROOT", upload_root)
    monkeypatch.setattr(runtime, "UPLOAD_ACCOUNT", account.pw_name)
    monkeypatch.setattr(
        runtime, "_validate_live", lambda manifest: type("Live", (), {"boot_id": "boot-id"})()
    )
    result = runtime.prepare(operation_id(), "a" * 64, "boot-id")
    staging = upload_root / operation_id()
    assert result["state"] == "prepared"
    assert staging.is_dir()
    assert staging.stat().st_mode & 0o777 == 0o700
