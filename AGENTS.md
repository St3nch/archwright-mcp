# AGENTS.md

## Authority

Chaz is Product Owner and final authority for Archwright.

No agent decides that bootstrap is complete. No agent permanently disables or removes Archwright without explicit Product Owner authorization.

## Purpose

Archwright is a temporary, root-capable MCP control plane used to bootstrap a fresh Arch Linux workstation. It is not a permanent remote-administration platform and is not VedaOps MCP.

## Engineering rules

- Build against live repository truth.
- Keep the VPS-resident MCP / reverse-SSH architecture unless an evidence-backed design review changes it.
- Preserve arbitrary root execution capability; do not replace it with a toy allowlist.
- Preserve centralized target identity verification before mutation.
- Preserve protected Windows-disk handling by hardware serial, never Linux device numbering.
- Preserve the separate temporary loopback-only laptop sshd design.
- Preserve separate tunnel and controller SSH identities.
- Transfer scripts/file content as data; avoid nested shell-quoting constructions.
- Long-running work must use durable jobs.
- Mutations must produce receipts unless an explicitly documented recovery exception applies.
- Do not log secrets.
- Do not introduce a public laptop listener.
- Do not add provider/API calls to the bootstrap target.
- Keep dependencies minimal and justified.
- Do not auto-update the install-day release.

## Git policy

Do not push/merge product changes without explicit Product Owner authorization.

Use focused branches and reviewable commits. Do not rewrite accepted history without explicit authorization.

## Testing

Do not declare readiness from unit tests alone. The release must prove the reverse-tunnel path, root execution, file transfer, durable jobs, reboot/reconnect, target mismatch refusal, protected-disk behavior, receipts, and lifecycle cleanup against a disposable target.

Tests may be numerous; coverage of dangerous failure modes matters more than an arbitrary test count.

## Safety model

Archwright intentionally has root authority. Do not claim arbitrary root can be perfectly sandboxed. Safety comes from target identity, network isolation, temporary credentials, read-only protected storage, receipts, tested failure behavior, and owner-controlled lifecycle.
