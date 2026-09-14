# Archwright MCP

Archwright is a temporary, root-capable MCP control plane for bootstrapping a fresh Linux workstation from a remote controller.

Its first target is a Sager/Clevo laptop being migrated from Pop!_OS to Arch Linux. Archwright runs on a trusted VPS and reaches the target laptop through a temporary reverse-SSH path. The laptop does not host the MCP server and does not expose a public listener.

## Purpose

Archwright exists to take over after the minimum manual Arch installation is complete and finish workstation provisioning: packages, KDE Plasma, networking, SSH, development tooling, hardware validation, power management, logs, reboots, recovery checks, and final cleanup.

It is intentionally temporary. The Product Owner decides when bootstrap is complete and when Archwright is disabled or removed.

## Architecture

```text
ChatGPT
   |
   | OpenAI Secure MCP Tunnel
   v
Trusted VPS
   |
   | Archwright MCP
   |
   | OpenSSH -> localhost reverse-forward endpoint
   v
Arch laptop
   |
   | temporary bootstrap account + sudo -n
   v
root
```

## Design principles

- Full bootstrap capability from v1; no toy read-only phase.
- Arbitrary user/root execution is available because this is an installer.
- Target identity is verified before mutation.
- The protected Windows NVMe is identified by hardware serial, not Linux device numbering.
- The protected Windows block device is made read-only during bootstrap when possible.
- Long-running commands are durable jobs, not fragile request-bound subprocesses.
- File contents and scripts are transferred as data rather than assembled through shell quoting.
- Every mutating operation produces an audit receipt.
- No public listener is required on the laptop.
- No automatic shutdown: only the Product Owner decides when bootstrap is finished.

## Status

Initial architecture and tool-contract design in progress.
