# Architecture

## Mission

Archwright is a temporary remote bootstrap control plane. It exists to let ChatGPT configure a fresh Arch Linux installation into the finished VedaOps workstation after the minimum manual installation has established networking and the bootstrap path.

Archwright is not the VedaOps development control plane, a permanent laptop agent, or a general remote-administration product. It is deliberately powerful and deliberately temporary.

## Topology

```text
ChatGPT
   |
   | OpenAI Secure MCP Tunnel
   v
VPS
+---------------------------------------------------+
| OpenAI tunnel profile                            |
|        |                                          |
|        v                                          |
| Archwright MCP                                    |
|        |                                          |
|        | OpenSSH client                           |
|        v                                          |
| 127.0.0.1:<target-port>                           |
+------------------------^--------------------------+
                         |
                         | reverse SSH forward
                         | initiated by laptop
                         |
Arch laptop              |
+------------------------+--------------------------+
| archwright-tunnel systemd unit                    |
|        |                                          |
|        +---- outbound SSH ----> VPS tunnel user   |
|                                                   |
| temporary sshd instance                           |
| 127.0.0.1:<bootstrap-sshd-port> only              |
|        |                                          |
|        v                                          |
| arch-bootstrap user                               |
|        |                                          |
|        +---- sudo -n ----> root                   |
+---------------------------------------------------+
```

The laptop does not host the MCP server and does not expose a public listener.

## Trust boundaries

### ChatGPT to VPS

ChatGPT reaches Archwright through a dedicated OpenAI Secure MCP Tunnel profile. Archwright is separate from VedaOps MCP and uses separate service configuration and credentials.

### VPS to laptop

The laptop creates an outbound reverse SSH tunnel to the VPS. The VPS-side remote-forward listener binds to loopback only. Archwright reaches the laptop by connecting to that loopback port.

### Temporary laptop SSH service

Archwright does not alter the final workstation's permanent SSH design during bootstrap. A dedicated temporary sshd instance is used instead.

Properties:

- binds only to `127.0.0.1` (and optionally `::1` if explicitly configured);
- uses a dedicated config under `/etc/archwright/`;
- accepts key authentication only;
- permits only the temporary `arch-bootstrap` account;
- disables root SSH login;
- disables password authentication;
- disables forwarding, agent forwarding and X11 forwarding for inbound controller sessions unless a tested bootstrap requirement proves otherwise;
- is managed by a dedicated systemd unit;
- is removed during owner-authorized cleanup.

The reverse tunnel targets this loopback-only sshd port.

## SSH identities

Use two separate temporary key pairs.

### Laptop -> VPS tunnel key

Purpose: permit the laptop to establish only the reverse-forward path to a dedicated VPS tunnel identity.

The VPS account should be restricted to the minimum required for remote port forwarding. It does not receive shell access for ordinary work.

### VPS -> laptop controller key

Purpose: permit Archwright on the VPS to authenticate through the reverse-forward endpoint to the temporary laptop sshd as `arch-bootstrap`.

This key is stored only on the VPS and removed when bootstrap is cleaned up.

## Root model

Direct root SSH login is not used.

Archwright logs in as `arch-bootstrap`. During bootstrap, that account has narrowly scoped *identity* but intentionally broad *authority* through a temporary sudoers rule allowing non-interactive root execution (`sudo -n`). The broad authority is necessary because Archwright is an installer.

The account and sudoers rule are temporary and owner-controlled.

## Execution model

Archwright uses the system OpenSSH client on the VPS rather than embedding a Python SSH implementation.

Reasons:

- OpenSSH is already part of the target architecture;
- fewer Python dependencies;
- mature key/host-key behavior;
- easier operator debugging from the VPS;
- the exact same transport can be reproduced manually when diagnosing failures.

### Commands

Commands are not assembled into deeply nested shell strings. Archwright writes an execution script locally, transfers it as data to a target staging directory, verifies its hash, sets permissions, and executes the script by path.

For root execution, the script is invoked with `sudo -n`.

This model avoids quoting bugs and creates an auditable artifact for every execution.

### Staging directory

Default target staging root:

`/var/lib/archwright/`

Suggested layout:

```text
/var/lib/archwright/
  runs/
  jobs/
  uploads/
  receipts/
  state/
```

Files containing secrets must not be copied into receipts or command output.

## Durable jobs

Request lifetime and process lifetime are separate.

Long-running commands are launched as durable jobs. The preferred target primitive is a transient systemd service whose executable is an uploaded Archwright job script.

A job has:

- stable job ID;
- target identity;
- script hash;
- start time;
- systemd unit name;
- running/exited/failed/cancelled state;
- exit code when available;
- stdout/stderr or journal cursor;
- receipt link.

Archwright can query or cancel a job without depending on the original MCP request staying open.

## Reboot model

Reboot is a first-class operation.

Before reboot Archwright:

1. records a reboot receipt;
2. verifies no disallowed critical job is running;
3. verifies the reverse-tunnel unit is enabled;
4. verifies the temporary sshd unit is enabled;
5. issues the reboot.

After connection loss the controller polls the VPS loopback endpoint until the reverse tunnel returns, then verifies target identity again before further mutation.

A reconnect never implicitly resumes a mutating operation.

## Target enrollment and identity

Archwright has exactly one enrolled target at a time in v1.

Enrollment records stable identity evidence such as:

- `/etc/machine-id`;
- DMI product UUID;
- DMI product / board identifiers;
- hostname (informational, not sufficient by itself);
- root filesystem UUID;
- parent block-device serial for the root filesystem;
- NVMe model and serial inventory;
- expected Arch target NVMe serial;
- protected Windows NVMe serial.

Mutation requires the live target to match the enrollment policy.

For the initial Sager deployment:

- protected Windows NVMe serial: `25044DB4D635`;
- Arch target NVMe serial: `25044DB50A3B`.

Linux names such as `/dev/nvme0n1` are never authoritative identity.

## Protected Windows disk

Arbitrary root capability means a command-filtering policy cannot provide absolute storage isolation. Archwright therefore uses a layered accidental-destruction guard.

1. Identify the Windows NVMe by serial.
2. Resolve its current kernel device path.
3. Set the whole block device read-only with the kernel block-device read-only flag during bootstrap.
4. Install a temporary `archwright-protect-windows.service` that re-applies read-only protection on every bootstrap boot before Archwright mutation resumes.
5. Verify read-only state before every storage-affecting semantic tool and during target verification.
6. Refuse semantic destructive storage operations against the protected serial.
7. Flag obvious protected-device references in arbitrary root scripts before execution.

This is an accident guard, not a claim that arbitrary root can be made incapable of undoing the protection. Root is root.

## File operations

File writes are atomic whenever practical:

1. upload to a temporary file on the same filesystem;
2. fsync/close;
3. apply owner/mode;
4. optionally verify expected prior hash;
5. rename into place;
6. return new hash and metadata.

`file_patch` requires an expected prior hash by default so stale assumptions fail closed.

## Receipts

Every mutating tool produces an operation receipt stored on the VPS. A target-side copy may be retained during bootstrap for recovery but the VPS copy is authoritative.

Receipt fields include:

- receipt ID;
- timestamp;
- tool name;
- target identity digest;
- requested privilege;
- normalized arguments with secret fields redacted;
- command/script hash where applicable;
- exit status;
- bounded stdout/stderr references;
- changed path metadata where known;
- related job ID;
- reboot/reconnect outcome where applicable.

Receipts do not store private keys, passwords, tokens, Wi-Fi PSKs, or full contents of files explicitly marked secret.

## MCP runtime

Implementation language: Python 3.12+

MCP SDK: official Python SDK v2, pinned for reproducibility. Initial pin: `mcp==2.2.0`.

Archwright uses standard-library subprocess/async primitives for OpenSSH and local process management where practical.

The current stable MCP Python SDK v2 supports the 2026-07-28 protocol revision and earlier clients. Archwright does not require the MCP Tasks extension for durable jobs; jobs are an explicit Archwright tool surface.

## Configuration

VPS configuration contains no laptop password and no root password.

Suggested configuration fields:

```toml
[target]
name = "sager-arch"
host = "127.0.0.1"
port = 22022
user = "arch-bootstrap"
controller_key = "/etc/archwright/keys/controller_ed25519"
known_hosts = "/etc/archwright/known_hosts"
expected_target_serial = "25044DB50A3B"
protected_serials = ["25044DB4D635"]

[policy]
require_identity_for_mutation = true
require_protected_disks_read_only = true
receipt_dir = "/var/lib/archwright/receipts"
```

Actual ports are deployment values, not protocol constants.

## Lifecycle authority

Archwright never decides that bootstrap is complete.

Passing tests, completing a checklist, or reaching a workstation state does not trigger cleanup. Only an explicit owner instruction authorizes final cleanup/disable.
