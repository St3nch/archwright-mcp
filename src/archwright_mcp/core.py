from __future__ import annotations

import hashlib
import json
import os
import shlex
import time
import uuid
from dataclasses import asdict, dataclass
from typing import Any

from .config import Settings
from .errors import ArchwrightError
from .receipts import ReceiptStore, digest_json, now_iso
from .transport.ssh import ProcessResult, SSHTransport


@dataclass(slots=True)
class Enrollment:
    target_name: str
    machine_id: str
    product_uuid: str
    expected_target_serial: str
    protected_serials: list[str]
    root_uuid: str
    enrolled_at: str


class Controller:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.transport = SSHTransport(settings)
        self.receipts = ReceiptStore(settings.receipts_dir, settings.target_name)

    def _run_json(self, command: str, *, root: bool = False) -> Any:
        result = self.transport.remote(command, root=root)
        if result.exit_code != 0:
            raise ArchwrightError(
                "VALIDATION_FAILED",
                "Remote JSON command failed",
                {"command": command, "stderr": result.stderr, "exit_code": result.exit_code},
            )
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise ArchwrightError(
                "VALIDATION_FAILED",
                "Remote command did not return valid JSON",
                {"command": command, "stdout": result.stdout[:4096]},
            ) from exc

    def block_devices(self) -> list[dict[str, Any]]:
        data = self._run_json(
            "lsblk -J -b -o NAME,PATH,TYPE,SIZE,MODEL,SERIAL,WWN,FSTYPE,FSVER,LABEL,UUID,"
            "PARTUUID,PARTLABEL,MOUNTPOINTS,RO,PKNAME"
        )
        return data.get("blockdevices", [])

    def live_identity(self) -> dict[str, Any]:
        machine = self.transport.remote("cat /etc/machine-id").stdout.strip()
        product_uuid = self.transport.remote(
            "cat /sys/class/dmi/id/product_uuid 2>/dev/null || true"
        ).stdout.strip()
        product_name = self.transport.remote(
            "cat /sys/class/dmi/id/product_name 2>/dev/null || true"
        ).stdout.strip()
        board_name = self.transport.remote(
            "cat /sys/class/dmi/id/board_name 2>/dev/null || true"
        ).stdout.strip()
        root = self._run_json("findmnt -J -no SOURCE,UUID,FSTYPE,TARGET /")
        root_fs = (root.get("filesystems") or [{}])[0]
        blocks = self.block_devices()
        identity = {
            "machine_id": machine,
            "product_uuid": product_uuid,
            "product_name": product_name,
            "board_name": board_name,
            "root": root_fs,
            "block_devices": blocks,
        }
        identity["root_parent_serial"] = self._root_parent_serial(identity)
        identity["digest"] = digest_json(identity)
        return identity

    def _flatten_blocks(self, blocks: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        stack = list(blocks or self.block_devices())
        while stack:
            item = stack.pop(0)
            result.append(item)
            children = item.get("children") or []
            if isinstance(children, list):
                stack[0:0] = children
        return result

    def _all_disks(self) -> list[dict[str, Any]]:
        return [d for d in self._flatten_blocks() if d.get("type") == "disk"]

    def _root_parent_serial(self, identity: dict[str, Any]) -> str:
        source = str(identity.get("root", {}).get("source") or "")
        flat = self._flatten_blocks(identity.get("block_devices") or [])
        node = next((x for x in flat if str(x.get("path") or "") == source), None)
        if node is None:
            return ""
        if node.get("type") == "disk":
            return str(node.get("serial") or "").strip()
        pkname = str(node.get("pkname") or "").strip()
        if not pkname:
            return ""
        parent = next((x for x in flat if str(x.get("name") or "") == pkname), None)
        return str((parent or {}).get("serial") or "").strip()

    def _find_disk_by_serial(self, serial: str) -> dict[str, Any] | None:
        for d in self._all_disks():
            if str(d.get("serial") or "").strip() == serial:
                return d
        return None

    def enroll(self, target_name: str, expected_target_serial: str, protected_serials: list[str]) -> dict[str, Any]:
        identity = self.live_identity()
        root_uuid = str(identity.get("root", {}).get("uuid") or "")
        target_disk = self._find_disk_by_serial(expected_target_serial)
        if target_disk is None:
            raise ArchwrightError("VALIDATION_FAILED", "Expected target disk serial is not present", {"serial": expected_target_serial})
        if identity.get("root_parent_serial") != expected_target_serial:
            raise ArchwrightError(
                "TARGET_IDENTITY_MISMATCH",
                "The running root filesystem is not on the expected Arch target disk",
                {"expected_target_serial": expected_target_serial, "root_parent_serial": identity.get("root_parent_serial")},
            )
        missing = [s for s in protected_serials if self._find_disk_by_serial(s) is None]
        if missing:
            raise ArchwrightError("PROTECTED_STORAGE_MISSING", "One or more protected disks are not present", {"missing_serials": missing})
        enrollment = Enrollment(
            target_name=target_name,
            machine_id=identity["machine_id"],
            product_uuid=identity["product_uuid"],
            expected_target_serial=expected_target_serial,
            protected_serials=protected_serials,
            root_uuid=root_uuid,
            enrolled_at=now_iso(),
        )
        payload = asdict(enrollment)
        path = self.settings.enrollment_path
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2, sort_keys=True))
        os.replace(tmp, path)
        self.settings.target_name = target_name
        return {"ok": True, "enrollment": payload, "identity_digest": identity["digest"]}

    def load_enrollment(self) -> Enrollment:
        path = self.settings.enrollment_path
        if not path.exists():
            raise ArchwrightError("TARGET_NOT_ENROLLED", "No enrolled target exists")
        data = json.loads(path.read_text())
        return Enrollment(**data)

    def protected_storage_status(self, enrollment: Enrollment | None = None) -> dict[str, Any]:
        e = enrollment or self.load_enrollment()
        rows = []
        all_ok = True
        for serial in e.protected_serials:
            disk = self._find_disk_by_serial(serial)
            if disk is None:
                rows.append({"serial": serial, "present": False, "read_only": None, "path": None})
                all_ok = False
                continue
            ro = bool(int(disk.get("ro") or 0))
            rows.append({"serial": serial, "present": True, "read_only": ro, "path": disk.get("path")})
            all_ok = all_ok and ro
        return {"ok": all_ok, "devices": rows}

    def verify(self, *, require_protected_ro: bool = True) -> dict[str, Any]:
        e = self.load_enrollment()
        live = self.live_identity()
        mismatches: list[dict[str, Any]] = []
        if live["machine_id"] != e.machine_id:
            mismatches.append({"field": "machine_id", "expected": e.machine_id, "actual": live["machine_id"]})
        if e.product_uuid and live["product_uuid"] != e.product_uuid:
            mismatches.append({"field": "product_uuid", "expected": e.product_uuid, "actual": live["product_uuid"]})
        if self._find_disk_by_serial(e.expected_target_serial) is None:
            mismatches.append({"field": "expected_target_serial", "expected": e.expected_target_serial, "actual": None})
        if live.get("root_parent_serial") != e.expected_target_serial:
            mismatches.append({"field": "root_parent_serial", "expected": e.expected_target_serial, "actual": live.get("root_parent_serial")})
        protected = self.protected_storage_status(e)
        if not protected["ok"] and require_protected_ro:
            mismatches.append({"field": "protected_storage", "actual": protected})
        return {
            "ok": not mismatches,
            "checked_at": now_iso(),
            "identity_digest": live["digest"],
            "mismatches": mismatches,
            "protected_storage": protected,
            "identity": live,
        }

    def enforce_protected_storage(self) -> dict[str, Any]:
        e = self.load_enrollment()
        before = self.protected_storage_status(e)
        actions = []
        for item in before["devices"]:
            if not item["present"]:
                raise ArchwrightError("PROTECTED_STORAGE_MISSING", "Protected disk is absent", {"serial": item["serial"]})
            if item["read_only"]:
                continue
            path = str(item["path"])
            r = self.transport.remote(f"blockdev --setro {shlex.quote(path)}", root=True)
            if r.exit_code != 0:
                raise ArchwrightError("PROTECTED_STORAGE_WRITABLE", "Could not set protected disk read-only", {"serial": item["serial"], "path": path, "stderr": r.stderr})
            actions.append({"serial": item["serial"], "path": path, "action": "setro"})
        after = self.protected_storage_status(e)
        if not after["ok"]:
            raise ArchwrightError("PROTECTED_STORAGE_WRITABLE", "Protected storage is still writable after enforcement", after)
        return {"ok": True, "before": before, "after": after, "actions": actions}

    def mutation_gate(self) -> dict[str, Any]:
        verification = self.verify(require_protected_ro=True)
        if not verification["ok"]:
            code = "PROTECTED_STORAGE_WRITABLE" if any(x["field"] == "protected_storage" for x in verification["mismatches"]) else "TARGET_IDENTITY_MISMATCH"
            raise ArchwrightError(code, "Mutation gate refused the operation", verification)
        return verification

    def _result_dict(self, r: ProcessResult) -> dict[str, Any]:
        return {
            "exit_code": r.exit_code,
            "stdout": r.stdout,
            "stderr": r.stderr,
            "duration_seconds": r.duration_seconds,
            "stdout_truncated": r.stdout_truncated,
            "stderr_truncated": r.stderr_truncated,
        }

    def execute(self, *, tool: str, script: str, root: bool, cwd: str | None = None, timeout_seconds: int | None = None, env: dict[str, str] | None = None, mutation: bool = False, request_extra: dict[str, Any] | None = None) -> dict[str, Any]:
        started = now_iso()
        receipt_id = self.receipts.new_id()
        verification = self.mutation_gate() if mutation else None
        stage = self.settings.staging_dir / f"{receipt_id}.sh"
        stage.write_text(script)
        sha = hashlib.sha256(stage.read_bytes()).hexdigest()
        target_path = f"{self.settings.target_staging_dir}/{receipt_id}.sh"
        self.transport.remote(f"mkdir -p {shlex.quote(self.settings.target_staging_dir)}")
        up = self.transport.upload(stage, target_path)
        if up.exit_code != 0:
            raise ArchwrightError("TRANSFER_FAILED", "Script upload failed", {"stderr": up.stderr})
        verify_hash = self.transport.remote(f"sha256sum {shlex.quote(target_path)}")
        if verify_hash.exit_code != 0 or not verify_hash.stdout.startswith(sha):
            raise ArchwrightError("REMOTE_HASH_MISMATCH", "Transferred script hash mismatch")
        self.transport.remote(f"chmod 700 {shlex.quote(target_path)}")

        execution_path = target_path
        root_path: str | None = None
        if root:
            root_path = f"/run/archwright/{receipt_id}.sh"
            promote = self.transport.remote(
                "install -d -m 700 -o root -g root /run/archwright && "
                f"install -m 700 -o root -g root {shlex.quote(target_path)} {shlex.quote(root_path)} && "
                f"sha256sum {shlex.quote(root_path)}",
                root=True,
            )
            if promote.exit_code != 0 or not promote.stdout.startswith(sha):
                raise ArchwrightError("REMOTE_HASH_MISMATCH", "Root-owned promoted script hash mismatch", {"stderr": promote.stderr})
            execution_path = root_path

        env_prefix = ""
        if env:
            env_prefix = "env " + " ".join(f"{shlex.quote(k)}={shlex.quote(v)}" for k, v in env.items()) + " "
        cd = f"cd {shlex.quote(cwd)} && " if cwd else ""
        command = f"{cd}{env_prefix}/bin/bash {shlex.quote(execution_path)}"
        result = self.transport.remote(command, root=root, timeout=timeout_seconds)
        if root_path:
            self.transport.remote(f"rm -f {shlex.quote(root_path)}", root=True)
        self.transport.remote(f"rm -f {shlex.quote(target_path)}")
        try:
            stage.unlink()
        except OSError:
            pass

        output = self._result_dict(result)
        output["script_sha256"] = sha
        request = {"root": root, "cwd": cwd, "timeout_seconds": timeout_seconds, **(request_extra or {})}
        receipt = self.receipts.persist(
            receipt_id=receipt_id,
            tool=tool,
            started_at=started,
            status="ok" if result.exit_code == 0 else "failed",
            request=request,
            result=output,
            identity_digest=verification["identity_digest"] if verification else None,
        )
        output["operation"] = receipt
        return output

    def simple(self, *, tool: str, command: str, root: bool = False, mutation: bool = False, timeout: int | None = None, request: dict[str, Any] | None = None) -> dict[str, Any]:
        started = now_iso()
        receipt_id = self.receipts.new_id()
        verification = self.mutation_gate() if mutation else None
        result = self.transport.remote(command, root=root, timeout=timeout)
        out = self._result_dict(result)
        if mutation:
            receipt = self.receipts.persist(
                receipt_id=receipt_id,
                tool=tool,
                started_at=started,
                status="ok" if result.exit_code == 0 else "failed",
                request=request or {},
                result=out,
                identity_digest=verification["identity_digest"] if verification else None,
            )
            out["operation"] = receipt
        return out

    def wait(self, timeout_seconds: int = 180, interval_seconds: float = 3.0) -> dict[str, Any]:
        deadline = time.monotonic() + timeout_seconds
        attempts = 0
        while time.monotonic() < deadline:
            attempts += 1
            if self.transport.reachable():
                verification = self.verify(require_protected_ro=True)
                if verification["ok"]:
                    return {"ok": True, "attempts": attempts, "verification": verification}
            time.sleep(interval_seconds)
        raise ArchwrightError("REBOOT_RECONNECT_TIMEOUT", "Target did not return verified before timeout", {"timeout_seconds": timeout_seconds, "attempts": attempts})

    def new_job_id(self) -> str:
        return f"job_{uuid.uuid4().hex[:12]}"
