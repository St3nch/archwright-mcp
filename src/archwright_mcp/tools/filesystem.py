from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path
from typing import Any

from mcp.server import MCPServer

from ..core import Controller
from ..errors import ArchwrightError
from ..receipts import now_iso
from .helpers import command, q


def register(mcp: MCPServer, c: Controller) -> None:
    @mcp.tool()
    def file_read(path: str, max_bytes: int = 262144) -> dict[str, Any]:
        max_bytes = max(1, min(max_bytes, 4 * 1024 * 1024))
        return command(c, "file_read", f"head -c {max_bytes} -- {q(path)}")

    @mcp.tool()
    def file_stat(path: str) -> dict[str, Any]:
        return command(c, "file_stat", f"stat --printf='type=%F\\nsize=%s\\nuid=%u\\ngid=%g\\nmode=%a\\nmtime=%Y\\n' -- {q(path)}; if [ -f {q(path)} ]; then sha256sum -- {q(path)}; fi")

    @mcp.tool()
    def file_write(path: str, content: str, mode: str = "0644", owner: str = "root", group: str = "root", expected_sha256: str | None = None, secret: bool = False) -> dict[str, Any]:
        c.mutation_gate()
        if expected_sha256:
            prior = c.transport.remote(f"sha256sum -- {q(path)} 2>/dev/null | awk '{{print $1}}'")
            actual = prior.stdout.strip()
            if actual != expected_sha256:
                raise ArchwrightError("FILE_PRECONDITION_FAILED", "Existing file hash does not match expected hash", {"path": path, "expected": expected_sha256, "actual": actual})
        started = now_iso()
        receipt_id = c.receipts.new_id()
        fd, local_name = tempfile.mkstemp(prefix="archwright-write-", dir=c.settings.staging_dir)
        os.close(fd)
        local = Path(local_name)
        local.write_text(content)
        sha = hashlib.sha256(content.encode()).hexdigest()
        remote_tmp = f"{c.settings.target_staging_dir}/{receipt_id}.file"
        up = c.transport.upload(local, remote_tmp)
        try:
            local.unlink()
        except OSError:
            pass
        if up.exit_code != 0:
            raise ArchwrightError("TRANSFER_FAILED", "File upload failed", {"stderr": up.stderr})
        verify = c.transport.remote(f"sha256sum {q(remote_tmp)} | awk '{{print $1}}'")
        if verify.stdout.strip() != sha:
            raise ArchwrightError("REMOTE_HASH_MISMATCH", "Uploaded file hash mismatch")
        root_tmp = f"/run/archwright/files/{receipt_id}.file"
        promote = c.transport.remote("install -d -m 700 -o root -g root /run/archwright/files && " f"install -m 600 -o root -g root {q(remote_tmp)} {q(root_tmp)} && " f"sha256sum {q(root_tmp)} | awk '{{print $1}}'", root=True)
        if promote.exit_code != 0 or promote.stdout.strip() != sha:
            c.transport.remote(f"rm -f {q(root_tmp)}", root=True)
            raise ArchwrightError("REMOTE_HASH_MISMATCH", "Root-owned promoted file hash mismatch", {"stderr": promote.stderr})
        cmd = f"install -D -m {q(mode)} -o {q(owner)} -g {q(group)} {q(root_tmp)} {q(path)} && rm -f {q(root_tmp)} {q(remote_tmp)}"
        result = c.transport.remote(cmd, root=True)
        out = c._result_dict(result)
        receipt = c.receipts.persist(receipt_id=receipt_id, tool="file_write", started_at=started, status="ok" if result.exit_code == 0 else "failed", request={"path": path, "mode": mode, "owner": owner, "group": group, "expected_sha256": expected_sha256, "secret": secret}, result={"path": path, "sha256": sha, **out}, identity_digest=c.verify()["identity_digest"])
        return {"ok": result.exit_code == 0, "path": path, "sha256": sha, **out, "operation": receipt}

    @mcp.tool()
    def file_patch(path: str, expected_sha256: str, old: str, new: str, mode: str = "0644", owner: str = "root", group: str = "root") -> dict[str, Any]:
        read = c.transport.remote(f"cat -- {q(path)}")
        if read.exit_code != 0:
            raise ArchwrightError("VALIDATION_FAILED", "Cannot read file for patch", {"path": path})
        actual = hashlib.sha256(read.stdout.encode()).hexdigest()
        if actual != expected_sha256:
            raise ArchwrightError("FILE_PRECONDITION_FAILED", "Patch precondition failed", {"expected": expected_sha256, "actual": actual})
        if read.stdout.count(old) != 1:
            raise ArchwrightError("VALIDATION_FAILED", "Patch old text must occur exactly once", {"occurrences": read.stdout.count(old)})
        return file_write(path, read.stdout.replace(old, new, 1), mode, owner, group, expected_sha256, False)

    @mcp.tool()
    def file_copy(source: str, destination: str, preserve: bool = True) -> dict[str, Any]:
        return command(c, "file_copy", f"cp {'-a' if preserve else '-f'} -- {q(source)} {q(destination)}", root=True, mutation=True, request={"source": source, "destination": destination})

    @mcp.tool()
    def file_move(source: str, destination: str) -> dict[str, Any]:
        return command(c, "file_move", f"mv -- {q(source)} {q(destination)}", root=True, mutation=True, request={"source": source, "destination": destination})

    @mcp.tool()
    def file_remove(path: str, recursive: bool = False) -> dict[str, Any]:
        return command(c, "file_remove", f"rm {'-rf' if recursive else '-f'} -- {q(path)}", root=True, mutation=True, request={"path": path, "recursive": recursive})

    @mcp.tool()
    def directory_list(path: str, max_entries: int = 1000) -> dict[str, Any]:
        return command(c, "directory_list", f"find {q(path)} -mindepth 1 -maxdepth 1 -printf '%y\\t%M\\t%u\\t%g\\t%s\\t%p\\n' | head -n {max(1,min(max_entries,5000))}")

    @mcp.tool()
    def directory_create(path: str, mode: str = "0755", owner: str = "root", group: str = "root") -> dict[str, Any]:
        return command(c, "directory_create", f"install -d -m {q(mode)} -o {q(owner)} -g {q(group)} -- {q(path)}", root=True, mutation=True, request={"path": path, "mode": mode})

    @mcp.tool()
    def file_upload(vps_path: str, target_path: str) -> dict[str, Any]:
        c.mutation_gate()
        local = Path(vps_path).resolve()
        allowed = c.settings.staging_dir.resolve()
        if allowed not in local.parents:
            raise ArchwrightError("VALIDATION_FAILED", "Upload source must be inside staging directory")
        r = c.transport.upload(local, target_path)
        return {"ok": r.exit_code == 0, **c._result_dict(r)}

    @mcp.tool()
    def file_download(target_path: str, vps_name: str) -> dict[str, Any]:
        local = c.settings.staging_dir / Path(vps_name).name
        r = c.transport.download(target_path, local)
        return {"ok": r.exit_code == 0, "vps_path": str(local), **c._result_dict(r)}
