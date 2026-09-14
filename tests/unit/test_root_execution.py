from pathlib import Path

from archwright_mcp.config import Settings, TargetEndpoint
from archwright_mcp.core import Controller
from archwright_mcp.transport.ssh import ProcessResult


class FakeTransport:
    def __init__(self):
        self.calls = []
        self.uploaded = b""

    def remote(self, command, *, root=False, timeout=None, limit=None):
        self.calls.append((command, root))
        if command.startswith("sha256sum ") or "sha256sum /run/archwright/" in command:
            import hashlib
            return ProcessResult(0, hashlib.sha256(self.uploaded).hexdigest() + "  x\n", "", 0.01)
        return ProcessResult(0, "ok\n", "", 0.01)

    def upload(self, local: Path, remote_path: str):
        self.uploaded = local.read_bytes()
        self.calls.append((f"UPLOAD {remote_path}", False))
        return ProcessResult(0, "", "", 0.01)


def test_root_script_promoted_to_root_owned_runtime(tmp_path, monkeypatch):
    settings = Settings(endpoint=TargetEndpoint(identity_file=tmp_path / "key", known_hosts_file=tmp_path / "known"), state_dir=tmp_path / "state", staging_dir=tmp_path / "stage")
    for p in (settings.enrollment_path.parent, settings.receipts_dir, settings.staging_dir):
        p.mkdir(parents=True, exist_ok=True)
    c = Controller(settings)
    fake = FakeTransport()
    c.transport = fake
    monkeypatch.setattr(c, "mutation_gate", lambda: {"identity_digest": "digest"})
    result = c.execute(tool="run_root", script="id -u\n", root=True, mutation=True)
    assert result["exit_code"] == 0
    assert any("/run/archwright/" in cmd and root for cmd, root in fake.calls)
    assert any("/bin/bash /run/archwright/" in cmd and root for cmd, root in fake.calls)
