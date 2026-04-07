# Governance Bootstrap Toolkit

This folder contains a reusable scaffolder for the 7-file governance framework.

The framework is intended to keep engineering execution deterministic, auditable,
and safe across sessions.

## What it creates

1. `active_context.md`
2. `docs/contracts.md`
3. `docs/agent_core.md`
4. `docs/agent_project.md`
5. `docs/decisions.md`
6. `docs/build_plan.md`
7. `docs/state.md`

## Why this framework exists

The 7-file model separates responsibilities so teams can move quickly without
architecture drift:

1. `active_context.md` controls each session and points to authoritative docs.
2. `docs/contracts.md` defines immutable contracts and invariants.
3. `docs/agent_project.md` captures project-specific boundaries and risks.
4. `docs/agent_core.md` captures reusable execution behavior.
5. `docs/build_plan.md` enforces module-by-module execution and gates.
6. `docs/decisions.md` keeps architecture decision records (ADR-style).
7. `docs/state.md` tracks current progress, blockers, and session log.

## Quick start

From this repository root:

```powershell
python governance/bootstrap_governance.py \
  --target "C:\path\to\your-project" \
  --project "My Project" \
  --module "Module 0" \
  --task "Set initial scope"
```

## PowerShell wrapper

```powershell
.\governance\init-governance.ps1 \
  -TargetPath "C:\path\to\your-project" \
  -ProjectName "My Project" \
  -CurrentModule "Module 0" \
  -CurrentTask "Set initial scope"
```

## Useful flags

- `--dry-run` prints planned actions only.
- `--force` overwrites existing files.

## Recommended usage pattern

1. Run the scaffolder at project start.
2. Update `active_context.md` before each session.
3. Update `docs/state.md` after each session.
4. Add entries to `docs/decisions.md` when making non-obvious decisions.
5. Treat `docs/contracts.md` as the highest authority for behavior changes.

## Legacy migration checklist

When replacing older governance files:

1. Map old "contract" content into `docs/contracts.md`.
2. Map old "agent behavior" content into `docs/agent_core.md`.
3. Map old phased execution instructions into `docs/build_plan.md`.
4. Move project-specific constraints into `docs/agent_project.md`.
5. Add migration note in `docs/decisions.md`.
6. Update references in repository docs/comments.
7. Remove superseded legacy governance files.

## External practice references

This governance kit is compatible with:

- NIST SSDF (SP 800-218) risk-based secure development practices
- SLSA consistent build and provenance discipline
- ADR-style decision capture for architectural traceability
