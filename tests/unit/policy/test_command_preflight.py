from pathlib import PurePosixPath

from archwright_mcp.policy.command_preflight import preflight_root_script

WINDOWS = PurePosixPath("/dev/nvme0n1")
WINDOWS_SERIAL = "25044DB4D635"


def test_read_only_diagnostic_on_protected_path_is_allowed() -> None:
    result = preflight_root_script(
        "lsblk /dev/nvme0n1",
        protected_serials=(WINDOWS_SERIAL,),
        protected_paths=(WINDOWS,),
    )
    assert result.allowed is True


def test_mkfs_on_protected_partition_is_refused() -> None:
    result = preflight_root_script(
        "mkfs.ext4 /dev/nvme0n1p3",
        protected_serials=(WINDOWS_SERIAL,),
        protected_paths=(WINDOWS,),
    )
    assert result.allowed is False
    assert result.findings


def test_setrw_on_protected_disk_is_refused() -> None:
    result = preflight_root_script(
        "/usr/bin/blockdev --setrw /dev/nvme0n1",
        protected_serials=(WINDOWS_SERIAL,),
        protected_paths=(WINDOWS,),
    )
    assert result.allowed is False


def test_indented_sudo_command_is_refused() -> None:
    result = preflight_root_script(
        "  sudo -n /usr/bin/wipefs /dev/nvme0n1",
        protected_serials=(WINDOWS_SERIAL,),
        protected_paths=(WINDOWS,),
    )
    assert result.allowed is False


def test_destructive_command_on_target_disk_is_not_misattributed() -> None:
    result = preflight_root_script(
        "wipefs /dev/nvme1n1",
        protected_serials=(WINDOWS_SERIAL,),
        protected_paths=(WINDOWS,),
    )
    assert result.allowed is True
