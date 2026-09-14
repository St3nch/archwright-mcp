from __future__ import annotations

from archwright_mcp.config import Settings, TargetEndpoint
from archwright_mcp.core import Controller


def make_controller(tmp_path):
    settings = Settings(endpoint=TargetEndpoint(identity_file=tmp_path / "key", known_hosts_file=tmp_path / "known"), state_dir=tmp_path / "state", staging_dir=tmp_path / "stage")
    settings.enrollment_path.parent.mkdir(parents=True, exist_ok=True)
    settings.receipts_dir.mkdir(parents=True, exist_ok=True)
    settings.staging_dir.mkdir(parents=True, exist_ok=True)
    return Controller(settings)


def test_root_parent_serial_nested_lsblk(tmp_path):
    c = make_controller(tmp_path)
    identity = {"root": {"source": "/dev/nvme1n1p2"}, "block_devices": [{"name": "nvme1n1", "path": "/dev/nvme1n1", "type": "disk", "serial": "ARCH", "children": [{"name": "nvme1n1p2", "path": "/dev/nvme1n1p2", "type": "part", "pkname": "nvme1n1"}]}, {"name": "nvme0n1", "path": "/dev/nvme0n1", "type": "disk", "serial": "WIN"}]}
    assert c._root_parent_serial(identity) == "ARCH"


def test_flatten_blocks_preserves_disks(tmp_path):
    c = make_controller(tmp_path)
    blocks = [{"name": "d", "type": "disk", "children": [{"name": "p", "type": "part"}]}]
    flat = c._flatten_blocks(blocks)
    assert [x["name"] for x in flat] == ["d", "p"]
