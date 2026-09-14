import ast
from pathlib import Path

REQUIRED = {"target_status","target_identity","target_enroll","target_verify","target_wait","run","run_root","run_script","which","environment","job_start","job_status","job_output","job_cancel","job_list","file_read","file_write","file_patch","file_copy","file_move","file_remove","file_stat","directory_list","directory_create","file_upload","file_download","package_search","package_info","package_install","package_remove","package_upgrade","package_list","package_files","aur_info","aur_install","flatpak_manage","service_status","service_start","service_stop","service_restart","service_enable","service_disable","service_list","unit_read","daemon_reload","journal_query","dmesg_read","failed_units","process_list","process_tree","process_kill","socket_list","hardware_summary","pci_devices","usb_devices","block_devices","sensors","battery_status","graphics_status","audio_status","network_devices","bluetooth_status","firmware_status","network_status","network_ping","dns_lookup","networkmanager_status","wifi_scan","wifi_connect","firewall_status","firewall_manage","vps_connectivity_test","github_connectivity_test","ssh_status","ssh_keygen","ssh_authorized_keys","ssh_known_hosts","ssh_test","reverse_tunnel_status","reverse_tunnel_restart","mount_list","mount","unmount","filesystem_usage","filesystem_info","swap_status","fstab_read","fstab_validate","protected_storage_status","protected_storage_enforce","boot_status","efi_entries","kernel_status","initramfs_status","initramfs_rebuild","microcode_status","secure_boot_status","user_list","user_create","user_modify","user_remove","sudo_status","permissions_set","desktop_status","display_status","kde_config_read","kde_config_write","xdg_status","wayland_status","git_status_global","git_config_global","github_ssh_test","python_status","uv_status","toolchain_status","container_status","power_status","suspend_test_prepare","suspend","resume_verify","hibernate_status","lid_status","sleep_configuration","reboot","shutdown","reboot_required","boot_verify","receipt_get","receipt_list","change_summary","bootstrap_status","bootstrap_self_test","bootstrap_cleanup_preview","bootstrap_cleanup","bootstrap_disable"}


def discovered_tools() -> set[str]:
    root = Path(__file__).parents[2] / "src" / "archwright_mcp" / "tools"
    found: set[str] = set()
    for path in root.glob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and any(isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute) and dec.func.attr == "tool" for dec in node.decorator_list):
                found.add(node.name)
    return found


def test_complete_tool_contract_present():
    found = discovered_tools()
    assert REQUIRED <= found
    assert len(found) >= len(REQUIRED)
