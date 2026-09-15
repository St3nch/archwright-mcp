"""Fixed target-side helper for identity evidence and supervised execution.

This module is packaged as a standard-library zipapp. It is invoked through the
temporary bootstrap account's noninteractive sudo rule; it is not a listener.
"""

from __future__ import annotations

import base64
import contextlib
import fcntl
import hashlib
import json
import os
import pwd
import re
import selectors
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from archwright_mcp.errors import ValidationError
from archwright_mcp.models import EnrolledIdentity
from archwright_mcp.target.identity import BlockDevice, LiveIdentity, parse_lsblk_identity
from archwright_mcp.target.verification import verify_identity

RUNTIME_ROOT = Path("/var/lib/archwright")
UPLOAD_ROOT = RUNTIME_ROOT / "uploads"
JOB_ROOT = RUNTIME_ROOT / "jobs"
TARGET_ENROLLMENT_PATH = Path("/etc/archwright/enrollment.json")
UPLOAD_ACCOUNT = "arch-bootstrap"
_OPERATION_ID = re.compile(r"^op-([0-9a-f]{32})$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_MANIFEST_BYTES = 256 * 1024
_READ_CHUNK = 64 * 1024
_TERMINATION_GRACE_SECONDS = 5.0
_BLKROSET = 0x125D
_LSBLK = (
    "/usr/bin/lsblk",
    "--json",
    "--bytes",
    "--output",
    "NAME,KNAME,PATH,TYPE,FSTYPE,UUID,MOUNTPOINTS,PKNAME,MODEL,SERIAL,RO,WWN,MAJ:MIN",
)


class RuntimeRefusal(Exception):
    """A safe, expected target-runtime refusal."""


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8").strip()


def _run_fixed(argv: tuple[str, ...]) -> str:
    completed = subprocess.run(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
    )
    if completed.returncode != 0:
        raise RuntimeRefusal("a fixed identity probe failed")
    return completed.stdout.decode("utf-8", errors="strict").strip()


def _mount_options() -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for line in _read_text(Path("/proc/self/mountinfo")).splitlines():
        fields = line.split()
        if len(fields) < 10 or "-" not in fields:
            raise RuntimeRefusal("mount identity evidence is malformed")
        separator = fields.index("-")
        if separator + 3 >= len(fields):
            raise RuntimeRefusal("mount identity evidence is incomplete")
        major_minor = fields[2]
        options = fields[5].split(",") + fields[separator + 3].split(",")
        result.setdefault(major_minor, []).extend(options)
    return result


def _active_swap_devices() -> set[tuple[int, int]]:
    active: set[tuple[int, int]] = set()
    lines = _read_text(Path("/proc/swaps")).splitlines()
    for line in lines[1:]:
        fields = line.split()
        if not fields:
            continue
        try:
            metadata = os.stat(fields[0])
        except OSError:
            continue
        if stat.S_ISBLK(metadata.st_mode):
            active.add((os.major(metadata.st_rdev), os.minor(metadata.st_rdev)))
    return active


def _by_id_map(root: Path = Path("/dev/disk/by-id")) -> dict[tuple[int, int], list[str]]:
    result: dict[tuple[int, int], list[str]] = {}
    try:
        entries = tuple(root.iterdir())
    except OSError:
        return result
    for entry in entries:
        try:
            metadata = entry.stat()
        except OSError:
            continue
        if stat.S_ISBLK(metadata.st_mode):
            key = (os.major(metadata.st_rdev), os.minor(metadata.st_rdev))
            result.setdefault(key, []).append(str(entry))
    for paths in result.values():
        paths.sort()
    return result


def _optional_sysfs(path: Path) -> str | None:
    try:
        value = _read_text(path)
    except OSError:
        return None
    return value or None


def _annotate_block_devices(raw: dict[str, Any]) -> None:
    mount_options = _mount_options()
    swaps = _active_swap_devices()
    by_id = _by_id_map()

    def visit(item: Any) -> None:
        if not isinstance(item, dict):
            raise RuntimeRefusal("lsblk returned an invalid device entry")
        name = item.get("name")
        major_minor = item.get("maj:min")
        if not isinstance(name, str) or not isinstance(major_minor, str):
            raise RuntimeRefusal("lsblk omitted stable device evidence")
        try:
            major_text, minor_text = major_minor.split(":", maxsplit=1)
            device_number = (int(major_text), int(minor_text))
        except (TypeError, ValueError) as exc:
            raise RuntimeRefusal("lsblk returned malformed major:minor evidence") from exc
        sysfs = Path("/sys/class/block") / name
        try:
            holders = sorted(entry.name for entry in (sysfs / "holders").iterdir())
        except OSError as exc:
            raise RuntimeRefusal("unable to inspect block-device holders") from exc
        item["mount_options"] = sorted(set(mount_options.get(major_minor, [])))
        item["holders"] = holders
        item["by_id_paths"] = by_id.get(device_number, [])
        item["sysfs_serial"] = _optional_sysfs(sysfs / "device" / "serial")
        item["namespace_id"] = _optional_sysfs(sysfs / "nsid")
        item["swap_active"] = device_number in swaps
        children = item.get("children", [])
        if not isinstance(children, list):
            raise RuntimeRefusal("lsblk returned malformed child evidence")
        for child in children:
            visit(child)

    devices = raw.get("blockdevices")
    if not isinstance(devices, list):
        raise RuntimeRefusal("lsblk omitted its device list")
    for device in devices:
        visit(device)


def collect_identity_payload() -> dict[str, str]:
    """Collect one boot-consistent, privileged identity snapshot."""

    boot_before = _read_text(Path("/proc/sys/kernel/random/boot_id"))
    lsblk_raw = json.loads(_run_fixed(_LSBLK))
    if not isinstance(lsblk_raw, dict):
        raise RuntimeRefusal("lsblk identity is not an object")
    _annotate_block_devices(lsblk_raw)
    machine_id = _read_text(Path("/etc/machine-id"))
    dmi_product_uuid = _read_text(Path("/sys/class/dmi/id/product_uuid"))
    dmi_product_name = _read_text(Path("/sys/class/dmi/id/product_name"))
    dmi_board_name = _read_text(Path("/sys/class/dmi/id/board_name"))
    hostname = _read_text(Path("/etc/hostname"))
    boot_after = _read_text(Path("/proc/sys/kernel/random/boot_id"))
    return {
        "machine_id": machine_id,
        "dmi_product_uuid": dmi_product_uuid,
        "dmi_product_name": dmi_product_name,
        "dmi_board_name": dmi_board_name,
        "hostname": hostname,
        "boot_id_before": boot_before,
        "boot_id_after": boot_after,
        "lsblk": json.dumps(lsblk_raw, sort_keys=True, separators=(",", ":")),
    }


def _live_identity(payload: dict[str, str]) -> LiveIdentity:
    if payload["boot_id_before"] != payload["boot_id_after"]:
        raise RuntimeRefusal("target rebooted while identity was collected")
    devices, root, root_parent = parse_lsblk_identity(payload["lsblk"])
    return LiveIdentity(
        machine_id=payload["machine_id"],
        dmi_product_uuid=payload["dmi_product_uuid"],
        dmi_product_name=payload["dmi_product_name"],
        dmi_board_name=payload["dmi_board_name"],
        hostname=payload["hostname"],
        boot_id=payload["boot_id_before"],
        root_filesystem_uuid=root.filesystem_uuid or "",
        root_parent_serial=root_parent.serial or "",
        root_device_path=root.path,
        block_devices=devices,
    )


def _parse_enrollment(value: Any) -> EnrolledIdentity:
    if not isinstance(value, dict):
        raise RuntimeRefusal("execution manifest has no enrollment")
    required_strings = (
        "target_name",
        "machine_id",
        "dmi_product_uuid",
        "dmi_product_name",
        "dmi_board_name",
        "root_filesystem_uuid",
        "root_parent_serial",
        "expected_target_serial",
    )
    if any(not isinstance(value.get(key), str) for key in required_strings):
        raise RuntimeRefusal("execution manifest enrollment has invalid string evidence")
    protected = value.get("protected_serials")
    fingerprints = value.get("ssh_host_key_fingerprints")
    if (
        not isinstance(protected, list)
        or not all(isinstance(item, str) for item in protected)
        or not isinstance(fingerprints, list)
        or not all(isinstance(item, str) for item in fingerprints)
    ):
        raise RuntimeRefusal("execution manifest enrollment has invalid list evidence")
    try:
        return EnrolledIdentity(
            target_name=value["target_name"],
            machine_id=value["machine_id"],
            dmi_product_uuid=value["dmi_product_uuid"],
            dmi_product_name=value["dmi_product_name"],
            dmi_board_name=value["dmi_board_name"],
            root_filesystem_uuid=value["root_filesystem_uuid"],
            root_parent_serial=value["root_parent_serial"],
            expected_target_serial=value["expected_target_serial"],
            protected_serials=tuple(protected),
            ssh_host_key_fingerprints=tuple(fingerprints),
        )
    except (KeyError, TypeError, ValueError, ValidationError) as exc:
        raise RuntimeRefusal("execution manifest enrollment is invalid") from exc


def _trusted_enrollment() -> EnrolledIdentity:
    descriptor, metadata = _open_regular(TARGET_ENROLLMENT_PATH, maximum=_MAX_MANIFEST_BYTES)
    if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o022 or metadata.st_nlink != 1:
        os.close(descriptor)
        raise RuntimeRefusal("target enrollment permissions are unsafe")
    try:
        with os.fdopen(descriptor, "rb") as stream:
            payload = stream.read(_MAX_MANIFEST_BYTES + 1)
    except OSError as exc:
        raise RuntimeRefusal("unable to read target enrollment") from exc
    if len(payload) > _MAX_MANIFEST_BYTES:
        raise RuntimeRefusal("target enrollment exceeds its size limit")
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeRefusal("target enrollment is malformed") from exc
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise RuntimeRefusal("target enrollment schema is invalid")
    enrolled = _parse_enrollment(value.get("identity"))
    if value.get("identity_digest") != enrolled.digest:
        raise RuntimeRefusal("target enrollment digest is invalid")
    return enrolled


def _validate_live(manifest: dict[str, Any]) -> LiveIdentity:
    enrolled = _trusted_enrollment()
    expected_digest = manifest.get("target_identity_digest")
    if expected_digest != enrolled.digest:
        raise RuntimeRefusal("execution manifest identity digest is invalid")
    live = _live_identity(collect_identity_payload())
    expected_boot = manifest.get("boot_id")
    if live.boot_id != expected_boot:
        raise RuntimeRefusal("target boot changed before execution")
    verification = verify_identity(enrolled, live)
    if not verification.passed:
        raise RuntimeRefusal("target identity or protected storage did not verify")
    return live


def _set_read_only(device_path: str, expected_major_minor: str) -> None:
    try:
        descriptor = os.open(
            device_path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
        )
    except OSError as exc:
        raise RuntimeRefusal("unable to open protected block device") from exc
    try:
        metadata = os.fstat(descriptor)
        actual = f"{os.major(metadata.st_rdev)}:{os.minor(metadata.st_rdev)}"
        if not stat.S_ISBLK(metadata.st_mode) or actual != expected_major_minor:
            raise RuntimeRefusal("protected block-device identity changed before enforcement")
        fcntl.ioctl(descriptor, _BLKROSET, struct.pack("i", 1))
    except OSError as exc:
        raise RuntimeRefusal("unable to enforce protected storage read-only") from exc
    finally:
        os.close(descriptor)


def protect(target_identity_digest: str, boot_id: str) -> dict[str, Any]:
    """Resolve and protect every enrolled device inside one root helper boundary."""

    enrolled = _trusted_enrollment()
    if target_identity_digest != enrolled.digest:
        raise RuntimeRefusal("protected-storage authorization digest is invalid")
    maximum_effects = 256
    effects = 0
    while True:
        live = _live_identity(collect_identity_payload())
        if live.boot_id != boot_id:
            raise RuntimeRefusal("target boot changed during protected-storage enforcement")
        verification = verify_identity(enrolled, live, require_protected_read_only=False)
        if not verification.passed:
            raise RuntimeRefusal("target identity or protected storage is unsafe for enforcement")
        writable: list[BlockDevice] = []
        for serial in enrolled.protected_serials:
            disks = live.disks_for_serial(serial)
            if len(disks) != 1:
                raise RuntimeRefusal("protected serial did not resolve exactly once")
            disk = disks[0]
            nodes = (*reversed(live.descendants_of(disk.name)), disk)
            writable.extend(node for node in nodes if not node.read_only)
        if not writable:
            final = verify_identity(enrolled, live)
            if not final.passed:
                raise RuntimeRefusal("protected storage did not verify after enforcement")
            return {
                "schema_version": 1,
                "ok": True,
                "target_identity_digest": enrolled.digest,
                "boot_id": live.boot_id,
                "effects": effects,
            }
        if effects >= maximum_effects:
            raise RuntimeRefusal("protected storage did not converge to read-only")
        node = writable[0]
        _set_read_only(node.path, node.major_minor)
        effects += 1


def _open_regular(path: Path, *, maximum: int) -> tuple[int, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RuntimeRefusal("unable to open staged artifact") from exc
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
        os.close(descriptor)
        raise RuntimeRefusal("staged artifact is not a bounded regular file")
    return descriptor, metadata


def _read_bounded_json(path: Path) -> tuple[dict[str, Any], bytes]:
    descriptor, _ = _open_regular(path, maximum=_MAX_MANIFEST_BYTES)
    try:
        with os.fdopen(descriptor, "rb") as stream:
            payload = stream.read(_MAX_MANIFEST_BYTES + 1)
    except OSError as exc:
        raise RuntimeRefusal("unable to read execution manifest") from exc
    if len(payload) > _MAX_MANIFEST_BYTES:
        raise RuntimeRefusal("execution manifest exceeds its size limit")
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeRefusal("execution manifest is malformed") from exc
    if not isinstance(value, dict):
        raise RuntimeRefusal("execution manifest is not an object")
    return value, payload


def _copy_sealed(source: Path, destination: Path, *, size: int, digest: str) -> None:
    descriptor, metadata = _open_regular(source, maximum=size)
    if metadata.st_size != size:
        os.close(descriptor)
        raise RuntimeRefusal("staged script size changed")
    output = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    actual = hashlib.sha256()
    copied = 0
    try:
        while chunk := os.read(descriptor, _READ_CHUNK):
            if copied + len(chunk) > size:
                raise RuntimeRefusal("staged script grew beyond its authorized size")
            actual.update(chunk)
            copied += len(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(output, view)
                view = view[written:]
        os.fsync(output)
    finally:
        os.close(descriptor)
        os.close(output)
    if copied != size or actual.hexdigest() != digest:
        destination.unlink(missing_ok=True)
        raise RuntimeRefusal("staged script hash did not match the authorized artifact")


def _operation_parts(operation_id: str) -> tuple[str, str, Path]:
    match = _OPERATION_ID.fullmatch(operation_id)
    if match is None:
        raise RuntimeRefusal("invalid operation ID")
    token = match.group(1)
    return f"job-{token}", f"archwright-job-{token}.service", JOB_ROOT / operation_id


def _upload_dir(operation_id: str) -> Path:
    _operation_parts(operation_id)
    return UPLOAD_ROOT / operation_id


def prepare(operation_id: str, target_identity_digest: str, boot_id: str) -> dict[str, Any]:
    """Verify the target, then create one private upload directory."""

    if not _SHA256.fullmatch(target_identity_digest) or not boot_id:
        raise RuntimeRefusal("invalid staging authorization")
    live = _validate_live({"target_identity_digest": target_identity_digest, "boot_id": boot_id})
    try:
        account = pwd.getpwnam(UPLOAD_ACCOUNT)
    except KeyError as exc:
        raise RuntimeRefusal("bootstrap upload account does not exist") from exc
    directory = _upload_dir(operation_id)
    try:
        directory.mkdir(mode=0o700, parents=False, exist_ok=False)
        os.chown(directory, account.pw_uid, account.pw_gid)
        parent = os.open(UPLOAD_ROOT, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    except OSError as exc:
        with contextlib.suppress(OSError):
            directory.rmdir()
        raise RuntimeRefusal("unable to create private staging directory") from exc
    return {
        "schema_version": 1,
        "state": "prepared",
        "operation_id": operation_id,
        "target_identity_digest": target_identity_digest,
        "boot_id": live.boot_id,
    }


def _write_json_atomic(path: Path, value: dict[str, Any]) -> None:
    descriptor, raw = tempfile.mkstemp(prefix=".runtime-", dir=path.parent)
    temporary = Path(raw)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def launch(operation_id: str, manifest_sha256: str) -> dict[str, Any]:
    """Seal staged artifacts, verify again, and launch one transient service."""

    if not _SHA256.fullmatch(manifest_sha256):
        raise RuntimeRefusal("invalid manifest digest")
    job_id, unit_name, operation_dir = _operation_parts(operation_id)
    upload_dir = _upload_dir(operation_id)
    try:
        upload_metadata = upload_dir.stat(follow_symlinks=False)
        upload_account = pwd.getpwnam(UPLOAD_ACCOUNT)
    except (OSError, KeyError) as exc:
        raise RuntimeRefusal("private staging directory is unavailable") from exc
    if (
        not stat.S_ISDIR(upload_metadata.st_mode)
        or upload_metadata.st_uid != upload_account.pw_uid
        or stat.S_IMODE(upload_metadata.st_mode) != 0o700
    ):
        raise RuntimeRefusal("private staging directory has unsafe ownership or mode")
    manifest_path = upload_dir / "request.json"
    script_path = upload_dir / "script"
    manifest, manifest_bytes = _read_bounded_json(manifest_path)
    if hashlib.sha256(manifest_bytes).hexdigest() != manifest_sha256:
        raise RuntimeRefusal("execution manifest hash mismatch")
    if manifest.get("operation_id") != operation_id:
        raise RuntimeRefusal("execution manifest operation mismatch")
    script_size = manifest.get("script_size")
    script_digest = manifest.get("script_sha256")
    if (
        isinstance(script_size, bool)
        or not isinstance(script_size, int)
        or not 1 <= script_size <= 1_048_576
        or not isinstance(script_digest, str)
        or not _SHA256.fullmatch(script_digest)
    ):
        raise RuntimeRefusal("execution manifest script descriptor is invalid")
    _validate_live(manifest)
    try:
        operation_dir.mkdir(mode=0o700, parents=False, exist_ok=False)
    except OSError as exc:
        raise RuntimeRefusal("unable to create a private operation directory") from exc
    launch_attempted = False
    try:
        _copy_sealed(
            script_path,
            operation_dir / "script",
            size=script_size,
            digest=script_digest,
        )
        _write_json_atomic(operation_dir / "request.json", manifest)
        runtime = str(Path(sys.argv[0]).resolve())
        timeout = manifest.get("timeout_seconds")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
            raise RuntimeRefusal("execution timeout is invalid")
        command = (
            "/usr/bin/systemd-run",
            "--system",
            "--quiet",
            f"--unit={unit_name}",
            "--property=Type=exec",
            "--property=Restart=no",
            "--property=KillMode=control-group",
            "--property=TimeoutStopSec=10s",
            f"--property=RuntimeMaxSec={int(timeout) + 30}s",
            "--property=LimitCORE=0",
            "--property=StandardOutput=null",
            "--property=StandardError=null",
            "--expand-environment=no",
            runtime,
            "supervise",
            operation_id,
        )
        launch_attempted = True
        launched = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
        )
        if launched.returncode != 0:
            raise RuntimeRefusal("systemd refused the generated execution unit")
    except BaseException:
        if not launch_attempted:
            shutil.rmtree(operation_dir, ignore_errors=True)
        raise
    finally:
        shutil.rmtree(upload_dir, ignore_errors=True)
    return {
        "state": "starting",
        "operation_id": operation_id,
        "job_id": job_id,
        "unit_name": unit_name,
        "script_sha256": script_digest,
    }


def _validated_manifest_for_supervisor(operation_id: str) -> tuple[dict[str, Any], Path, int]:
    _, _, operation_dir = _operation_parts(operation_id)
    manifest, _ = _read_bounded_json(operation_dir / "request.json")
    if manifest.get("operation_id") != operation_id:
        raise RuntimeRefusal("sealed execution manifest operation mismatch")
    script = operation_dir / "script"
    size = manifest.get("script_size")
    digest = manifest.get("script_sha256")
    if not isinstance(size, int) or not isinstance(digest, str):
        raise RuntimeRefusal("sealed script descriptor is invalid")
    descriptor, metadata = _open_regular(script, maximum=1_048_576)
    actual = hashlib.sha256()
    try:
        while chunk := os.read(descriptor, _READ_CHUNK):
            actual.update(chunk)
        if metadata.st_size != size or actual.hexdigest() != digest:
            raise RuntimeRefusal("sealed script no longer matches its authorization")
        os.lseek(descriptor, 0, os.SEEK_SET)
        _validate_live(manifest)
        return manifest, operation_dir, descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _execution_identity(
    manifest: dict[str, Any],
) -> tuple[int | None, int | None, list[int] | None, dict[str, str]]:
    privilege = manifest.get("privilege")
    if privilege == "root":
        return None, None, None, {"HOME": "/root", "USER": "root", "LOGNAME": "root"}
    if privilege != "user":
        raise RuntimeRefusal("execution privilege is invalid")
    user_name = manifest.get("user") or "arch-bootstrap"
    if not isinstance(user_name, str):
        raise RuntimeRefusal("execution user is invalid")
    try:
        account = pwd.getpwnam(user_name)
        groups = os.getgrouplist(user_name, account.pw_gid)
    except (KeyError, OSError) as exc:
        raise RuntimeRefusal("execution user does not exist") from exc
    if account.pw_uid == 0:
        raise RuntimeRefusal("user execution resolved to the root account")
    environment = {"HOME": account.pw_dir, "USER": user_name, "LOGNAME": user_name}
    return account.pw_uid, account.pw_gid, groups, environment


def _terminate_group(process: subprocess.Popen[bytes]) -> None:
    """Terminate the complete child session even if its original leader exited."""

    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + _TERMINATION_GRACE_SECONDS
    while time.monotonic() < deadline:
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.05)
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    if process.poll() is None:
        process.wait()


def supervise(operation_id: str) -> int:
    """Run the sealed artifact and persist bounded binary-safe evidence."""

    _, _, operation_dir = _operation_parts(operation_id)
    try:
        manifest, operation_dir, script_descriptor = _validated_manifest_for_supervisor(
            operation_id
        )
        uid, gid, groups, identity_environment = _execution_identity(manifest)
        interpreter = manifest.get("interpreter")
        arguments = manifest.get("arguments")
        cwd = manifest.get("working_directory")
        environment = manifest.get("resolved_environment")
        timeout = manifest.get("timeout_seconds")
        output_limit = manifest.get("output_limit_bytes")
        output_policy = manifest.get("output_policy")
        if (
            not isinstance(interpreter, str)
            or not isinstance(arguments, list)
            or not all(isinstance(item, str) for item in arguments)
            or not isinstance(cwd, str)
            or not isinstance(environment, dict)
            or not all(
                isinstance(key, str) and isinstance(value, str)
                for key, value in environment.items()
            )
            or isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or isinstance(output_limit, bool)
            or not isinstance(output_limit, int)
            or not 1 <= output_limit <= 65_536
            or output_policy not in {"capture", "discard"}
        ):
            raise RuntimeRefusal("sealed execution settings are invalid")
        process_environment = {
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/bin:/bin",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            **identity_environment,
            **environment,
        }
        try:
            process = subprocess.Popen(
                [interpreter, f"/proc/self/fd/{script_descriptor}", *arguments],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=cwd,
                env=process_environment,
                start_new_session=True,
                user=uid,
                group=gid,
                extra_groups=groups,
                pass_fds=(script_descriptor,),
            )
        finally:
            os.close(script_descriptor)
        if process.stdout is None or process.stderr is None:
            raise RuntimeRefusal("execution output pipes are unavailable")
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        retained = {"stdout": bytearray(), "stderr": bytearray()}
        truncated = {"stdout": False, "stderr": False}
        deadline = time.monotonic() + timeout
        timed_out = False
        while selector.get_map() or process.poll() is None:
            remaining_time = deadline - time.monotonic()
            if remaining_time <= 0:
                timed_out = True
                _terminate_group(process)
            if not selector.get_map():
                if process.poll() is None:
                    time.sleep(max(0.0, min(0.05, remaining_time)))
                continue
            for key, _ in selector.select(timeout=max(0.0, min(0.25, remaining_time))):
                chunk = os.read(key.fd, _READ_CHUNK)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                stream = str(key.data)
                if output_policy == "discard":
                    continue
                available = output_limit - len(retained[stream])
                if available > 0:
                    retained[stream].extend(chunk[:available])
                if len(chunk) > available:
                    truncated[stream] = True
        return_code = process.wait()
        result = {
            "schema_version": 1,
            "state": "timed_out" if timed_out else ("succeeded" if return_code == 0 else "failed"),
            "operation_id": operation_id,
            "exit_code": return_code if return_code >= 0 else None,
            "signal": -return_code if return_code < 0 else None,
            "timed_out": timed_out,
            "output_suppressed": output_policy == "discard",
            "stdout_b64": base64.b64encode(retained["stdout"]).decode(),
            "stderr_b64": base64.b64encode(retained["stderr"]).decode(),
            "stdout_truncated": truncated["stdout"],
            "stderr_truncated": truncated["stderr"],
            "script_sha256": manifest["script_sha256"],
        }
        _write_json_atomic(operation_dir / "result.json", result)
        (operation_dir / "request.json").unlink(missing_ok=True)
        return 0 if return_code == 0 and not timed_out else 1
    except BaseException:
        failure = {
            "schema_version": 1,
            "state": "failed",
            "operation_id": operation_id,
            "exit_code": None,
            "signal": None,
            "timed_out": False,
            "output_suppressed": True,
            "stdout_b64": "",
            "stderr_b64": "",
            "stdout_truncated": False,
            "stderr_truncated": False,
            "failure_code": "TARGET_RUNTIME_FAILURE",
        }
        with contextlib.suppress(BaseException):
            _write_json_atomic(operation_dir / "result.json", failure)
        (operation_dir / "request.json").unlink(missing_ok=True)
        return 1


def status(operation_id: str) -> dict[str, Any]:
    _, unit_name, operation_dir = _operation_parts(operation_id)
    result_path = operation_dir / "result.json"
    if result_path.exists():
        result, _ = _read_bounded_json(result_path)
        return result
    active = subprocess.run(
        ("/usr/bin/systemctl", "is-active", "--quiet", unit_name),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return {
        "schema_version": 1,
        "operation_id": operation_id,
        "state": "running" if active.returncode == 0 else "unknown",
    }


def _emit(value: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")


def main() -> int:
    try:
        if os.geteuid() != 0:
            raise RuntimeRefusal("target runtime requires noninteractive root")
        if len(sys.argv) == 2 and sys.argv[1] == "inspect":
            payload = collect_identity_payload()
            if payload["boot_id_before"] != payload["boot_id_after"]:
                payload = collect_identity_payload()
            _emit(payload)
            return 0
        if len(sys.argv) == 5 and sys.argv[1] == "prepare":
            _emit(prepare(sys.argv[2], sys.argv[3], sys.argv[4]))
            return 0
        if len(sys.argv) == 4 and sys.argv[1] == "protect":
            _emit(protect(sys.argv[2], sys.argv[3]))
            return 0
        if len(sys.argv) == 4 and sys.argv[1] == "launch":
            _emit(launch(sys.argv[2], sys.argv[3]))
            return 0
        if len(sys.argv) == 3 and sys.argv[1] == "status":
            _emit(status(sys.argv[2]))
            return 0
        if len(sys.argv) == 3 and sys.argv[1] == "supervise":
            return supervise(sys.argv[2])
        raise RuntimeRefusal("unsupported target runtime invocation")
    except RuntimeRefusal:
        _emit({"schema_version": 1, "ok": False, "error": "TARGET_RUNTIME_REFUSED"})
        return 2
    except BaseException:
        _emit({"schema_version": 1, "ok": False, "error": "TARGET_RUNTIME_FAILURE"})
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
