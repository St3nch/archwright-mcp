# Test Plan

Archwright is allowed broad root authority, so confidence must come from aggressive testing of the complete control path rather than from artificially weak tools.

## Test philosophy

The goal is not to prove that every Linux command is safe. The goal is to prove that Archwright reliably:

- controls the intended target;
- transports scripts/files without corruption or quoting surprises;
- distinguishes user and root execution;
- survives long operations and reboots;
- protects the enrolled Windows disk against accidents;
- records useful receipts;
- fails closed on identity/transport uncertainty;
- cleans up only when explicitly instructed.

## Test layers

### 1. Unit tests

Run on the VPS development environment without a target.

Cover:

- config parsing/validation;
- tool argument validation;
- receipt serialization;
- secret redaction;
- output truncation;
- script artifact hashing;
- SSH argv construction;
- protected-serial matching;
- block-device parsing;
- target identity comparison;
- stable refusal/error codes;
- job ID/unit-name generation;
- file patch hash preconditions;
- cleanup-plan generation;
- command preflight detection of obvious protected-device references.

### 2. Transport integration tests

Use a disposable Linux target reachable through the same reverse-SSH topology.

Cover:

- reverse forward establishes;
- endpoint binds loopback only;
- wrong key refused;
- host-key pinning works;
- controller key reaches temporary sshd;
- temporary sshd refuses password auth/root login;
- tunnel interruption is detected;
- tunnel restart restores reachability;
- stale endpoint/host-key mismatch fails closed.

### 3. Full disposable target tests

Preferred final test target is a disposable Arch VM with two virtual disks so storage identity/protection behavior can be exercised realistically.

Where hardware virtualization is available, use QEMU/KVM. The second virtual disk represents the protected Windows disk.

The VM should be disposable and rebuilt frequently.

## Required capability suites

### Target identity suite

- enroll target;
- verify exact match;
- hostname change does not invalidate hard identity by itself;
- machine-id mismatch blocks mutation;
- DMI/product UUID mismatch blocks mutation when configured hard;
- target root disk serial mismatch blocks mutation;
- protected disk missing blocks mutation when policy requires it;
- SSH host-key change blocks normal operation;
- read-only tools provide enough evidence to diagnose mismatch without mutating.

### User/root execution suite

- user command success;
- user command nonzero exit;
- root command success;
- root command nonzero exit;
- `sudo -n` unavailable -> stable refusal/failure;
- multiline script;
- quotes, apostrophes, exclamation marks, dollar signs, Unicode and heredoc-like content survive transfer exactly;
- binary-ish/non-UTF8 output handled without crashing protocol;
- timeout terminates request-scoped execution;
- large output is bounded and full artifact remains available when configured;
- cwd/env behavior correct;
- secret environment fields redacted.

### File suite

- read normal file;
- bounded read;
- write new file atomically;
- replace file atomically;
- expected-hash success;
- expected-hash mismatch refuses without modification;
- owner/group/mode set correctly;
- secret file content absent from receipt;
- move/copy/remove;
- recursive remove requires explicit flag;
- file upload/download preserves SHA-256;
- interrupted upload does not leave destination partially replaced.

### Job suite

- start user job;
- start root job;
- running status;
- successful exit;
- failed exit;
- incremental output retrieval;
- cancellation;
- runtime timeout;
- MCP request/client interruption does not kill job;
- Archwright process restart can rediscover persisted job state;
- target reboot marks interrupted jobs correctly rather than inventing success.

### Package suite

Inside disposable Arch target:

- repository search/info;
- install package;
- idempotent install;
- remove package;
- full upgrade against disposable snapshot;
- package list modes;
- package file ownership;
- invalid package failure;
- pacman database lock behavior reported cleanly;
- AUR metadata inspection;
- AUR build occurs unprivileged;
- AUR build/install failure preserves evidence;
- Flatpak operations when Flatpak is installed.

### systemd suite

- status/start/stop/restart;
- enable/disable;
- daemon-reload;
- failed unit evidence;
- unit/drop-in read;
- malformed unit is reported and not silently treated as active.

### Logs/process/socket suite

- journal filters;
- dmesg bounded read;
- failed units;
- process listing/tree;
- kill exact disposable process;
- socket listing;
- output bounding on large logs.

### Hardware/inspection suite

Where available in VM/container:

- PCI/USB/block inventory parsers;
- network-device parser;
- firmware/DMI parser;
- battery/sensors gracefully report unsupported rather than fail server;
- graphics/audio tools distinguish unavailable from broken.

Real Sager hardware validation occurs only after Arch install and is not required to prove the MCP transport itself.

### Networking suite

- status/routes/DNS;
- ping success/failure;
- DNS lookup;
- NetworkManager status;
- safe disposable connection operations;
- firewall inspection;
- firewall mutation in disposable target with recovery path;
- VPS connectivity test;
- GitHub SSH connectivity test.

### SSH suite

- key generation;
- authorized key exact add/remove;
- known-host add/remove/fingerprint;
- outbound SSH success/failure;
- reverse-tunnel status;
- reverse-tunnel restart;
- tunnel key cannot be used as controller key and vice versa.

### Storage suite

Use two disposable disks with stable test identities.

- block inventory resolves serials correctly;
- mark protected disk read-only;
- protected state survives Archwright service operations;
- boot protection unit re-applies read-only after VM reboot;
- semantic mount/filesystem operations against non-protected disk work;
- semantic destructive operation against protected disk refuses;
- obvious `run_root` destructive command naming protected path refuses;
- indirect attempt demonstrates documented limitation rather than claiming impossible sandboxing;
- device enumeration order may change but serial mapping remains correct;
- fstab parse/validate;
- swap/zram inspection.

### Boot/kernel suite

- UEFI/boot state graceful in VM;
- EFI entry tool handles unavailable efivarfs cleanly;
- kernel status;
- initramfs status/rebuild in disposable Arch VM;
- microcode status;
- Secure Boot status.

### User/sudo suite

- create/modify/remove disposable user;
- group changes;
- permissions changes;
- sudoers validation;
- malformed sudoers candidate never activated.

### Desktop/KDE suite

In a disposable Plasma-capable VM where practical:

- SDDM/Plasma state;
- Wayland/Xwayland status;
- KDE config read/write;
- XDG status;
- display tool degrades cleanly when no graphical session is active.

Hardware-specific display behavior is validated on the real Sager after handoff.

### Development-tooling suite

- Git global inspection/change in disposable user home;
- GitHub SSH test;
- Python status;
- uv status;
- compiler/build tools;
- Docker/Podman status when installed.

### Power/reboot suite

VM/system capabilities permitting:

- power status;
- suspend preflight token generation;
- unsupported suspend reported cleanly in environments that cannot suspend;
- reboot preflight;
- controller loses target as expected;
- reverse tunnel returns automatically;
- `target_wait` detects return;
- new boot ID observed;
- target identity revalidated;
- protected disk read-only state revalidated;
- `boot_verify` reports failed units and expected service state.

A real Sager suspend/resume suite occurs after Arch install and includes Wi-Fi/audio/graphics recovery.

### Receipt/audit suite

- every mutating tool creates receipt;
- read-only tools follow configured receipt policy;
- receipt IDs unique;
- secret inputs absent;
- stdout/stderr truncation represented honestly;
- command/script hash matches executed artifact;
- reboot chain links pre/post receipts;
- change summary accurately covers test window.

### Lifecycle suite

- bootstrap status;
- self-test creates only reversible artifacts;
- cleanup preview is complete and non-mutating;
- cleanup is idempotent;
- cleanup does not occur because tests pass;
- cleanup requires explicit invocation;
- cleanup leaves receipts by default;
- disable is separate from target cleanup;
- interrupted cleanup can be resumed/reconciled.

## Fault injection

Deliberately test:

- kill reverse SSH process mid-command;
- kill Archwright process while remote job continues;
- reboot target during job;
- corrupt transferred script before hash verification;
- change known-host key;
- change target machine-id in disposable VM;
- remove protected disk;
- clear protected disk read-only flag;
- make staging filesystem full;
- make receipt filesystem unwritable;
- pacman database lock;
- DNS failure;
- NetworkManager restart;
- systemd unit failure;
- malformed tool arguments;
- output exceeding limits.

## Install-day release gate

Before Pop!_OS is wiped, the candidate Archwright release must have:

1. passing unit suite;
2. passing reverse-tunnel integration suite;
3. passing user/root execution and file-transfer suite;
4. passing durable-job suite;
5. passing reboot/reconnect suite in a disposable target;
6. passing wrong-target identity refusal test;
7. passing protected-disk read-only/reboot test;
8. passing cleanup-preview/cleanup idempotence test;
9. a committed dependency lockfile;
10. a known Git commit/tag selected for install day;
11. a tested OpenAI Secure MCP Tunnel profile capable of invoking mutating tools;
12. a written manual fallback procedure for restoring the tunnel from the VPS/phone if automation fails.

The number of tests is not a product goal. Coverage of failure modes is. If that takes 150 tests, fine; if it takes 300, also fine. We are not waiting for permission to graduate from crayons.
