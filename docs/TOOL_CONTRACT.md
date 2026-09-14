# Tool Contract

Archwright v1 exposes the full bootstrap capability surface from the start. Semantic tools exist for structured, reliable operations; arbitrary user/root execution remains available as the escape hatch.

## Common conventions

All tools return structured JSON-compatible output.

Mutating tools return an `operation` object containing at least:

```text
receipt_id
target_name
target_identity_digest
started_at
finished_at
status
```

Command-like results additionally return:

```text
exit_code
stdout
stderr
stdout_truncated
stderr_truncated
```

Secrets are redacted from receipts and default tool output where Archwright knows a field is secret.

Mutation is refused unless the target is enrolled and live identity verification passes.

## Target and identity

### `target_status`
Read-only summary of transport and target availability.

Returns connection state, endpoint, hostname, OS, kernel, uptime, current user, sudo availability, last verification time and reverse-tunnel health.

### `target_identity`
Returns live identity evidence: machine-id, DMI identifiers, root filesystem UUID, parent block serial, NVMe inventory and protected-device mapping.

### `target_enroll`
Enroll the current target after explicit operator intent. Stores the identity policy used for later mutation checks.

Inputs include target name, expected Arch target disk serial and protected disk serials.

### `target_verify`
Performs the full identity and protected-storage check and returns PASS/FAIL with evidence.

### `target_wait`
Polls for target return after expected disconnect/reboot until timeout. Re-verifies identity before returning ready.

## Command execution

### `run`
Execute a script/command as the bootstrap user.

Inputs:
- `script`: multiline shell text;
- `shell`: default `/bin/bash`;
- `cwd`: optional absolute path;
- `env`: optional non-secret environment mapping;
- `timeout_seconds`;
- `output_limit_bytes`.

Implementation transfers script content as data and executes by path.

### `run_root`
Same model as `run`, executed through `sudo -n`.

Before execution, mutation identity and protected-storage checks run. Obvious protected-device destructive references are refused.

### `run_script`
Explicit script-oriented alias with file name, interpreter, arguments and optional secret-input descriptors. Intended for larger provisioning scripts.

### `which`
Resolve an executable and optionally report version output.

### `environment`
Returns shell, PATH, locale, current user, groups and selected non-secret environment data.

## Durable jobs

### `job_start`
Launch a durable user/root job from transferred script content.

Inputs include privilege, script, shell, cwd, environment, optional runtime timeout and description.

Returns stable job ID and systemd unit.

### `job_status`
Returns running/exited/failed/cancelled state, timestamps and exit code.

### `job_output`
Returns bounded stdout/stderr or journal output, with cursor/since options.

### `job_cancel`
Stops a running job and records cancellation receipt.

### `job_list`
Lists active/recent Archwright jobs.

## Filesystem

### `file_read`
Read a bounded text file. Supports offset/length and optional hash-only mode.

### `file_write`
Atomic file create/replace.

Inputs:
- path;
- content;
- owner/group;
- mode;
- optional expected prior SHA-256;
- `secret` boolean controlling receipt redaction.

### `file_patch`
Targeted replacement with required expected prior SHA-256 by default.

### `file_copy`
Copy path on target with optional metadata preservation.

### `file_move`
Atomic rename where filesystem permits.

### `file_remove`
Remove file or directory. Recursive deletion requires explicit recursive input and is receipt-recorded.

### `file_stat`
Return type, size, ownership, mode, timestamps and SHA-256 for regular files.

### `directory_list`
Bounded directory listing with metadata.

### `directory_create`
Create directory tree with ownership/mode.

### `file_upload`
Transfer a file from VPS-side Archwright staging to laptop.

### `file_download`
Transfer a laptop file to VPS-side Archwright staging.

## Packages

Semantic package tools use Arch-native tools and return structured package results. Raw `run_root` remains available.

### `package_search`
Search official repositories.

### `package_info`
Return repository/package metadata and installed state.

### `package_install`
Install explicit package names with pacman. Defaults to noninteractive failure on unresolved prompts; no blind conflict deletion.

### `package_remove`
Remove explicit package names with requested pacman removal mode.

### `package_upgrade`
Perform a full supported Arch upgrade. Partial-upgrade behavior is not exposed as a semantic operation.

### `package_list`
List installed packages, optionally explicit/foreign/orphans.

### `package_files`
List files owned by package or owner of path.

### `aur_info`
Inspect AUR package metadata/build inputs before mutation.

### `aur_install`
Build/install an explicitly named AUR package as an unprivileged build user, then install resulting package with pacman. Never runs an arbitrary downloaded PKGBUILD directly as root.

### `flatpak_manage`
Actions: list, search, install, remove, update, remotes.

## systemd and services

### `service_status`
Structured unit status plus bounded recent journal.

### `service_start`
Start unit.

### `service_stop`
Stop unit.

### `service_restart`
Restart unit.

### `service_enable`
Enable unit, optionally start now.

### `service_disable`
Disable unit, optionally stop now.

### `service_list`
List units by state/type/pattern.

### `unit_read`
Return effective unit text, fragment path and drop-ins.

### `daemon_reload`
Run systemd daemon reload.

## Logs and processes

### `journal_query`
Bounded journal query supporting unit, boot, priority, since/until and grep filters.

### `dmesg_read`
Bounded kernel-log retrieval with level/time filtering.

### `failed_units`
List failed systemd units.

### `process_list`
Structured process list with filters.

### `process_tree`
Process hierarchy for PID or system.

### `process_kill`
Send explicit signal to PID after returning target process identity in receipt.

### `socket_list`
Structured listening/connected socket inventory.

## Hardware

### `hardware_summary`
CPU, memory, graphics, storage, network, audio, battery, firmware summary.

### `pci_devices`
PCI devices with IDs, drivers and kernel modules.

### `usb_devices`
USB device inventory.

### `block_devices`
Block-device inventory including model, serial, WWN, size, filesystem, UUID, mountpoint and read-only state.

### `sensors`
Temperature/fan sensor data when available.

### `battery_status`
Capacity, health, charge state and power data.

### `graphics_status`
DRM devices, driver, Mesa/OpenGL/Vulkan state and active outputs where available.

### `audio_status`
ALSA/PipeWire/WirePlumber state and devices.

### `network_devices`
Interfaces, drivers, addresses and link state.

### `bluetooth_status`
Controller state and relevant service/device information.

### `firmware_status`
DMI/UEFI and fwupd data where available.

## Networking

### `network_status`
Interfaces, routes, DNS and connectivity summary.

### `network_ping`
ICMP reachability test with bounded count/timeout.

### `dns_lookup`
Resolve name/address using system resolver tooling.

### `networkmanager_status`
NetworkManager service, devices and connections.

### `wifi_scan`
Scan visible networks without exposing saved secrets.

### `wifi_connect`
Create/activate Wi-Fi connection. PSK/passphrase is treated as secret and omitted from receipts.

### `firewall_status`
Report active firewall implementation and rules summary.

### `firewall_manage`
Perform explicit firewall actions using the configured workstation firewall implementation.

### `vps_connectivity_test`
Verify DNS, route, TCP/SSH reachability and optionally host-key/authentication to the VedaOps VPS.

### `github_connectivity_test`
Verify DNS/TCP and SSH handshake to GitHub without mutating a repository.

## SSH/bootstrap transport

### `ssh_status`
Report temporary bootstrap sshd plus any detected permanent SSH service without conflating them.

### `ssh_keygen`
Generate a key pair at an explicit temporary/permanent path with requested algorithm and comment.

### `ssh_authorized_keys`
List/add/remove exact keys for an explicit user. Secret private-key material is never returned.

### `ssh_known_hosts`
Inspect/add/remove known-host entries with fingerprint evidence.

### `ssh_test`
Test outbound SSH to an explicit destination with bounded command.

### `reverse_tunnel_status`
Report laptop tunnel unit, VPS loopback endpoint availability, reconnect counters and last failure evidence.

### `reverse_tunnel_restart`
Restart the laptop-side tunnel service and verify that the controller path returns.

## Storage and mounts

### `mount_list`
Structured mount inventory.

### `mount`
Mount explicit filesystem/path with options.

### `unmount`
Unmount explicit path/device.

### `filesystem_usage`
Capacity and inode usage.

### `filesystem_info`
Filesystem type, UUID, labels, options and backing block identity.

### `swap_status`
Swap/zram inventory and state.

### `fstab_read`
Parse `/etc/fstab` into structured entries plus raw text.

### `fstab_validate`
Validate entries and optionally perform non-destructive mount resolution checks.

### `protected_storage_status`
Resolve each protected hardware serial to current block path and verify read-only state.

### `protected_storage_enforce`
Re-apply kernel read-only protection for enrolled protected block devices and verify result.

Raw storage commands remain possible through `run_root`, subject to identity checks, the read-only protection layer and obvious protected-device refusal checks.

## Boot, kernel and firmware

### `boot_status`
UEFI/legacy state, current boot manager, mounted ESPs and active boot metadata.

### `efi_entries`
Read EFI boot variables/entries.

### `kernel_status`
Running kernel and installed Arch kernel packages.

### `initramfs_status`
Inspect mkinitcpio configuration and generated images.

### `initramfs_rebuild`
Run explicit supported mkinitcpio rebuild and return result.

### `microcode_status`
Intel/AMD microcode package and running-state evidence.

### `secure_boot_status`
Report Secure Boot firmware state.

## Users and permissions

### `user_list`
Users/groups with filtering.

### `user_create`
Create user with explicit groups, shell and home behavior.

### `user_modify`
Modify explicit user properties/groups.

### `user_remove`
Remove user; home deletion is separate explicit input.

### `sudo_status`
Report sudo installation, relevant drop-ins and noninteractive bootstrap capability without returning unrelated secret content.

### `permissions_set`
Apply chmod/chown to explicit paths.

## Desktop / KDE

### `desktop_status`
Plasma, SDDM, Wayland/Xwayland and active session state.

### `display_status`
Outputs, modes, scaling and compositor-visible display state.

### `kde_config_read`
Read an explicit KDE config file/group/key or bounded file.

### `kde_config_write`
Set explicit KDE configuration through supported KDE tooling where possible.

### `xdg_status`
XDG directories, MIME/default-app state and desktop integration summary.

### `wayland_status`
Wayland compositor/session and relevant environment state.

## Development workstation

### `git_status_global`
Git version, system/global config origins and SSH signing/credential-related configuration with secret redaction.

### `git_config_global`
Set/unset explicit global Git values.

### `github_ssh_test`
Alias/specialization of GitHub SSH connectivity with fingerprint/auth result.

### `python_status`
Python installations and selected interpreters.

### `uv_status`
uv installation/version/config paths.

### `toolchain_status`
Compiler/build-tool inventory.

### `container_status`
Docker/Podman/container runtime service and version state if installed.

## Power and laptop behavior

### `power_status`
Power profile, AC/battery state, relevant services and current policy.

### `suspend_test_prepare`
Capture pre-suspend identity for network/audio/graphics/power devices and return test token.

### `suspend`
Initiate suspend after validating reconnect prerequisites.

### `resume_verify`
Using a prior suspend test token, compare post-resume hardware/network/audio state.

### `hibernate_status`
Report capability and configuration; does not enable hibernation implicitly.

### `lid_status`
Report logind/lid-switch policy and current lid state when available.

### `sleep_configuration`
Read relevant systemd/logind/kernel sleep configuration.

## Reboot and shutdown

### `reboot`
First-class controlled reboot with preflight receipt and expected reconnect workflow.

### `shutdown`
Controlled shutdown. Because no automatic reconnect is possible after a poweroff, output explicitly states that physical intervention may be required.

### `reboot_required`
Evidence-based advisory summary after kernel/firmware/core-service changes.

### `boot_verify`
Compare boot-time expectations, failed units, target identity, protected disk state, tunnel state and selected services after reconnect.

## Receipts and audit

### `receipt_get`
Retrieve one receipt by ID.

### `receipt_list`
List receipts by time/tool/status/job.

### `change_summary`
Summarize mutations recorded during a selected bootstrap window.

## Bootstrap lifecycle

### `bootstrap_status`
Overall controller/target/tunnel/identity/root/job/protected-storage state.

### `bootstrap_self_test`
Exercise connection, identity, user execution, root execution, staging, atomic file operation, durable job operation and receipt persistence using reversible test artifacts.

### `bootstrap_cleanup_preview`
Show exactly which temporary laptop/VPS resources cleanup would remove. Does not mutate.

### `bootstrap_cleanup`
Owner-authorized removal of temporary laptop-side bootstrap account, sudoers entry, temporary sshd, reverse-tunnel unit/keys/state and related temporary artifacts according to the cleanup plan.

### `bootstrap_disable`
Owner-authorized disable of the VPS Archwright MCP/tunnel service after target cleanup/verification.

## Non-goals of semantic tools

Semantic tools do not attempt to make Linux administration impossible to misuse. Archwright intentionally has arbitrary root execution because it is an installer. The semantic surface provides structure, safer defaults, better receipts and easier model interaction; identity verification and protected-storage enforcement provide the primary accidental-target guardrails.
