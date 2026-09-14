# Security Model

Archwright is intentionally high privilege. Its security model therefore focuses on controlling *where*, *when* and *how* that privilege is exercised rather than pretending arbitrary root can be safely reduced to a toy command set.

## Security goals

1. ChatGPT can administer the enrolled Arch laptop with root authority during bootstrap.
2. The laptop does not expose a public management listener.
3. Archwright cannot silently drift to a different SSH target.
4. The Windows NVMe is strongly protected against accidental mutation during bootstrap.
5. Temporary credentials and services are isolated from permanent workstation credentials.
6. Operations are auditable without storing secrets.
7. Cleanup happens only when explicitly authorized by the owner.

## Explicit non-goals

- Archwright does not claim to sandbox a malicious root command.
- Archwright does not make arbitrary root incapable of disabling its own guardrails.
- Archwright does not protect against a compromised VPS root account.
- Archwright does not provide multi-tenant isolation in v1.
- Archwright does not automatically decide that the bootstrap is finished.

## Principal trust assumptions

Trusted during bootstrap:

- Chaz as Product Owner/operator;
- the VPS operating system and root administration boundary;
- the dedicated OpenAI MCP connection profile;
- the Archwright process and pinned source/dependencies;
- OpenSSH host-key and key-authentication mechanisms;
- the manually installed base Arch system after identity enrollment.

## Network exposure

### MCP side

Archwright is private. ChatGPT reaches it through a dedicated OpenAI Secure MCP Tunnel profile. No general public HTTP listener is required.

### Laptop side

The controller SSH daemon binds to loopback only. The laptop originates the reverse SSH tunnel outbound to the VPS.

The VPS reverse-forward listener binds to loopback only.

Result: no inbound router/NAT/firewall opening is required for the laptop.

## Credential separation

Use dedicated ephemeral credentials for each leg:

- OpenAI tunnel profile for Archwright;
- laptop-to-VPS reverse-forward key;
- VPS-to-laptop controller key;
- temporary `arch-bootstrap` account;
- temporary sudoers entry.

Do not reuse the user's normal GitHub key, VedaOps deployment keys or personal workstation SSH key for bootstrap transport.

## SSH host verification

Strict host-key verification is required after initial enrollment.

The VPS controller uses a dedicated Archwright `known_hosts` file. First enrollment records the temporary laptop sshd host key fingerprint. Unexpected host-key changes cause target verification failure until explicitly reconciled.

The laptop likewise pins the VPS host key for the reverse-tunnel connection.

## Target identity policy

Mutation requires all configured hard identity conditions to pass.

Hard evidence should include:

- expected `/etc/machine-id` after enrollment;
- expected DMI product UUID where stable and available;
- expected Arch target root parent disk serial;
- presence of expected protected Windows disk serial;
- root filesystem UUID after final root filesystem creation.

Hostname is advisory only.

If a required hard identity value changes unexpectedly, mutating tools refuse with a stable identity-mismatch result.

Read-only diagnostic tools may still run only if transport identity is trustworthy enough to explain the mismatch; mutation remains blocked.

## Sager disk policy

Known initial hardware serials:

- Windows / protected: `25044DB4D635`
- Pop!_OS -> Arch target: `25044DB50A3B`

Never encode `/dev/nvme0n1` or `/dev/nvme1n1` as authoritative policy because enumeration can change.

### Read-only enforcement

During bootstrap the Windows NVMe is resolved by serial and marked read-only using the kernel block-device read-only mechanism.

A temporary systemd unit re-applies this at boot before the bootstrap path is considered mutation-ready.

`target_verify` and `protected_storage_status` verify the flag.

If a protected disk cannot be resolved or is not read-only when policy requires it, mutating tools fail closed.

### Semantic storage refusal

Storage semantic tools compare resolved parent device serials against the protected list. Operations targeting protected devices are refused.

### Arbitrary root script preflight

`run_root`, `run_script` and root jobs perform a best-effort preflight for explicit references to protected block paths and known destructive storage commands.

This is an accident detector, not a security boundary. A sufficiently indirect root program can bypass lexical inspection; the block-device read-only state is the stronger accidental-write guard.

## Root authority

`arch-bootstrap` uses non-interactive sudo during bootstrap.

The sudoers drop-in should:

- be owned by root;
- mode 0440;
- pass `visudo -c` validation before activation;
- be removed during owner-authorized cleanup.

No root password is transmitted to Archwright.

## Script transfer and execution

Archwright does not place untrusted model text directly inside nested SSH shell quoting.

Execution flow:

1. create a local script artifact on VPS;
2. hash it;
3. transfer to target staging as data;
4. verify remote hash;
5. set explicit ownership/mode;
6. execute by absolute path;
7. capture result;
8. record receipt;
9. clean or retain artifact according to receipt/debug policy.

This improves correctness and auditability.

## File mutation safety

Atomic replace is preferred.

For important existing files, `file_patch` requires expected SHA-256 unless the caller explicitly chooses replacement semantics.

System configuration writes should be followed by the subsystem's native validation where one exists, for example:

- `visudo -c` for sudoers;
- `sshd -t -f <config>` for sshd;
- systemd unit verification/daemon-reload;
- config-specific parsers where available.

## Secret handling

Secret-class inputs include:

- private SSH keys;
- Wi-Fi PSKs;
- tokens;
- passwords if ever temporarily required;
- OpenAI tunnel credentials;
- other provider credentials.

Rules:

- never echo secrets into receipts;
- never include secret input values in exception messages;
- avoid process arguments when stdin/file-descriptor/file mode can be used;
- temporary secret files use restrictive mode and explicit cleanup;
- hashes may be logged when useful, but not reversible content;
- file-read tools require explicit secret-read intent for known secret paths.

## Output bounding

All tool output is bounded to prevent accidental huge journal/package dumps from exhausting the MCP response path.

Full logs may be stored in VPS-side operation directories with a tool returning a receipt/reference and bounded excerpts.

## Jobs

Jobs have unique unguessable IDs plus deterministic systemd unit naming derived from the ID.

Root jobs use transferred scripts. Job status is derived from systemd state and persisted receipt state rather than model prose.

Cancellation targets the exact recorded unit and verifies identity before action.

## Reboot safety

Before reboot:

- verify target identity;
- verify reverse-tunnel service enabled;
- verify temporary sshd enabled;
- verify protected-disk boot guard enabled;
- record the reboot intent and current boot ID.

After reconnect:

- require a new boot ID;
- re-run target verification;
- re-check protected storage read-only state;
- do not assume any pre-reboot command completed unless its receipt/job evidence proves it.

## Cleanup safety

Cleanup is destructive to the bootstrap control path, so it is two-stage:

1. `bootstrap_cleanup_preview` enumerates temporary accounts, units, keys, sudoers entries, staging and VPS-side tunnel assets.
2. `bootstrap_cleanup` performs only the recorded plan after explicit owner authorization.

Cleanup must be idempotent and should preserve audit receipts unless the owner separately requests deletion.

`bootstrap_disable` is separate from laptop cleanup so the owner can inspect/repair cleanup if needed before losing the VPS MCP path.

## Dependency and release policy

- Python dependency lockfile committed.
- MCP SDK pinned to a tested stable version for the bootstrap release.
- No auto-update in the bootstrap service.
- Release candidate used for install day is identified by Git commit SHA/tag.
- Code is not edited live during the Arch install unless the owner explicitly chooses emergency repair.

## Logging policy

Every mutation is auditable, but logs are not surveillance dumps.

Store:

- operation metadata;
- normalized action;
- target identity digest;
- script/file hashes;
- exit status;
- bounded output or references;
- state transitions.

Do not store:

- private key content;
- passwords/PSKs/tokens;
- unrelated user files;
- arbitrary shell history outside Archwright operations.
