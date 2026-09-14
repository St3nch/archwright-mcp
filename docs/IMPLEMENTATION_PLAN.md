# Implementation Plan

Archwright v1 is one complete bootstrap release. Implementation may be split by subsystem for engineering convenience, but no subsystem is treated as a product-complete baby milestone. The release gate is the complete v1 tool surface and control path.

## Runtime choices

- Python: 3.12+
- Environment/package manager: uv
- MCP SDK: official `mcp==2.2.0` initially, locked before release
- Remote transport: system OpenSSH client invoked by Archwright
- Target service manager/job substrate: systemd
- Target shell: Bash for generated execution scripts unless a tool explicitly uses another executable
- Receipt format: JSON/JSONL plus bounded output artifacts on VPS
- Configuration: TOML
- Tests: pytest
- Lint/format: Ruff
- Type checking: mypy

## Repository layout

```text
archwright-mcp/
  README.md
  AGENTS.md
  pyproject.toml
  uv.lock
  src/
    archwright_mcp/
      __init__.py
      server.py
      config.py
      models.py
      errors.py
      receipts.py
      redaction.py
      transport/
        __init__.py
        ssh.py
        transfer.py
      target/
        __init__.py
        identity.py
        enrollment.py
        verification.py
      policy/
        __init__.py
        mutation.py
        protected_storage.py
        command_preflight.py
      execution/
        __init__.py
        scripts.py
        commands.py
        jobs.py
      files.py
      tools/
        __init__.py
        target.py
        execution.py
        filesystem.py
        packages.py
        services.py
        diagnostics.py
        hardware.py
        network.py
        ssh.py
        storage.py
        boot.py
        users.py
        desktop.py
        development.py
        power.py
        lifecycle.py
  tests/
    unit/
    integration/
    fixtures/
  docs/
    ARCHITECTURE.md
    TOOL_CONTRACT.md
    SECURITY_MODEL.md
    TEST_PLAN.md
    IMPLEMENTATION_PLAN.md
  systemd/
    vps/
    target/
  scripts/
    dev/
    integration/
```

The layout can change when implementation evidence justifies it; avoid speculative abstraction for its own sake.

## Core data models

Define these before tool handlers so every subsystem speaks the same language.

### TargetEndpoint

- host
- port
- user
- controller key path
- known-hosts path

### EnrolledIdentity

- target name
- machine-id
- DMI product UUID
- DMI product/board data
- root filesystem UUID
- root parent serial
- expected target serial
- protected serials
- temporary sshd host-key fingerprints

### VerificationResult

- pass/fail
- checked_at
- evidence
- mismatches
- protected-storage status
- identity digest

### CommandResult

- exit code
- stdout/stderr bounded text
- truncation flags
- duration
- remote script hash
- receipt ID

### JobRecord

- job ID
- unit name
- target identity digest
- privilege
- script hash
- state
- timestamps
- exit code
- receipt IDs

### OperationReceipt

- receipt ID
- tool
- normalized/redacted request
- target identity digest
- timestamps
- state/result
- related artifacts
- related job/reboot IDs

## Transport implementation

### SSH command runner

Use argv arrays, never shell-concatenated local commands.

Baseline OpenSSH behavior:

- BatchMode yes
- IdentitiesOnly yes
- explicit identity file
- explicit known_hosts file
- StrictHostKeyChecking yes after enrollment
- ConnectTimeout bounded
- ServerAliveInterval/CountMax set
- no agent forwarding
- no X11 forwarding
- no local environment leakage beyond intentional values

### Script execution

Even `run` uses a transferred script artifact rather than embedding arbitrary text in the remote SSH command.

Flow:

1. generate receipt/run ID;
2. write local temporary script bytes;
3. SHA-256;
4. transfer to target staging;
5. verify SHA-256 remotely;
6. chmod explicit mode;
7. execute exact absolute path as user or through `sudo -n`;
8. collect bounded output;
9. create receipt;
10. clean target script according to debug retention policy.

### Transfer

Prefer OpenSSH-native SFTP/SCP invocation or stdin streaming to a narrowly controlled helper path. Do not introduce an embedded SSH stack just for file transfer.

Transfer implementation must support binary files and hash verification.

## Target bootstrap components

These are temporary laptop-side assets, installed manually or through the first trusted bootstrap commands:

- `arch-bootstrap` account;
- controller public key in that account;
- temporary sudoers drop-in;
- `/etc/archwright/sshd_config`;
- `archwright-bootstrap-sshd.service`;
- laptop-to-VPS reverse-tunnel key;
- VPS host key pin;
- `archwright-reverse-tunnel.service`;
- `archwright-protect-windows.service`;
- target staging/state directories.

All names are provisional until implementation validates systemd/unit constraints, but the separation of responsibilities is required.

## Temporary sshd

Use a separate `sshd -f /etc/archwright/sshd_config` instance rather than editing the permanent `/etc/ssh/sshd_config` for controller access.

Desired properties:

- loopback-only listen address;
- dedicated port;
- key auth only;
- `AllowUsers arch-bootstrap`;
- no root login;
- no password/KbdInteractive auth;
- no agent/X11/TCP forwarding for the inbound controller session unless required by a tested feature;
- explicit host-key files under `/etc/archwright/` or another temporary bootstrap path;
- config validated with `sshd -t -f` before restart/enable.

## Reverse tunnel

Laptop service initiates an outbound SSH connection to a dedicated VPS tunnel identity.

Required SSH client behavior:

- `-N`;
- `ExitOnForwardFailure=yes`;
- keepalives;
- remote forward bound on VPS loopback only;
- pinned VPS host key;
- dedicated tunnel key;
- automatic restart through systemd.

The tunnel account must be restricted so the laptop key cannot be repurposed for ordinary VPS shell access.

## Mutation gate

Every mutating tool passes through one centralized gate:

1. transport reachable;
2. enrolled target exists;
3. live identity verifies;
4. protected serials resolve as required;
5. protected disks are read-only when policy requires it;
6. tool-specific policy passes;
7. receipt can be persisted or the operation explicitly records degraded audit state according to policy.

Do not duplicate partial versions of this logic across tool handlers.

## Protected storage

Resolve by `/dev/disk/by-id` and independent `lsblk`/sysfs serial evidence where possible.

Apply read-only to the whole protected disk, not merely partitions.

The target protection unit should run early enough that a rebooted target is never declared mutation-ready before the flag is re-established.

Tests must prove device renumbering does not affect serial-based protection.

## Semantic tool implementation

Tool handlers should be thin:

1. validate schema;
2. call centralized verification/mutation gate;
3. invoke reusable subsystem function;
4. normalize result;
5. persist receipt.

Do not put substantial shell-generation logic directly in MCP decorators/handlers.

## Package behavior

Arch supports only full upgrades. `package_upgrade` maps to supported full-system pacman behavior.

AUR behavior:

- fetch/inspect metadata/PKGBUILD source as unprivileged user;
- expose evidence before build in receipts;
- build as unprivileged user;
- install built package with pacman/root;
- never run `makepkg` as root;
- never add an AUR helper as a hidden prerequisite for the first release.

An AUR helper may be installed later as a normal workstation choice, not as Archwright's trust anchor.

## KDE behavior

Prefer supported command-line configuration tools (`kwriteconfig6`, `kreadconfig6`, `kscreen-doctor`, XDG utilities, systemd user services) over blind text editing when available.

Tools must distinguish:

- no graphical session yet;
- graphical package not installed;
- service stopped;
- actual configuration failure.

## Receipts

VPS authoritative directory suggestion:

```text
/var/lib/archwright/
  state/
  receipts/YYYY/MM/DD/
  outputs/
  jobs/
  staging/
```

Receipt writes should be atomic.

If receipt persistence fails, mutating operations should normally fail before effect. Any exception to that rule must be narrowly justified (for example a recovery operation necessary to restore the receipt filesystem itself) and explicitly surfaced.

## Error model

Define stable machine-readable codes early. Initial families:

- `TARGET_UNREACHABLE`
- `TARGET_NOT_ENROLLED`
- `TARGET_IDENTITY_MISMATCH`
- `TARGET_HOSTKEY_MISMATCH`
- `SUDO_UNAVAILABLE`
- `PROTECTED_STORAGE_MISSING`
- `PROTECTED_STORAGE_WRITABLE`
- `PROTECTED_STORAGE_REFUSED`
- `TRANSFER_FAILED`
- `REMOTE_HASH_MISMATCH`
- `COMMAND_TIMEOUT`
- `JOB_NOT_FOUND`
- `JOB_FAILED`
- `FILE_PRECONDITION_FAILED`
- `VALIDATION_FAILED`
- `REBOOT_RECONNECT_TIMEOUT`
- `AUDIT_PERSISTENCE_FAILED`
- `CLEANUP_NOT_AUTHORIZED`

Human-readable messages accompany codes but code behavior must not depend on parsing prose.

## Build order

Engineering order, not product capability staging:

1. common models/config/errors/receipts;
2. OpenSSH transport and verified transfer;
3. target enrollment/verification and protected-storage gate;
4. script execution and durable jobs;
5. filesystem primitives;
6. all semantic tool modules;
7. reboot/reconnect and lifecycle;
8. OpenAI MCP server registration/integration;
9. complete disposable-target integration suite;
10. install-day release freeze.

No release is considered ready merely because steps 1-5 work.

## Release artifact

Before install day produce:

- Git commit SHA/tag;
- `uv.lock`;
- unit/integration test results;
- tested VPS systemd service definition;
- tested OpenAI tunnel profile;
- tested target bootstrap unit/config templates;
- manual emergency reconnect instructions;
- cleanup preview output against the disposable target;
- final Arch install/bootstrap runbook written around the proven implementation.
