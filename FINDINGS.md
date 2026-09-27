# FINDINGS

Open bugs, security issues and correctness problems.

Use the **ID** when commenting or assigning work. Update **Status** in the
same change as the code or decision, and update `PLAN.md` at the same time
when it is present, including when it is ignored by Git. When a finding is
fixed, remove it from this file and `PLAN.md`, and summarize it in the
release notes of the next version (`Documentation/RELEASE_NOTES_<version>.md`).
A finding spanning several packages stays here until every portion is fixed.
IDs are never reused; gaps are fixed or removed findings. The next free ID is
**XPKI-126**. Findings fixed in v1.0 are listed in
[`Documentation/RELEASE_NOTES_1.0.md`](Documentation/RELEASE_NOTES_1.0.md);
their full records are in git history.

## Status

| Status         | Meaning                                                |
| -------------- | ------------------------------------------------------ |
| Open           | Not started                                            |
| In Progress    | Being fixed                                            |
| Needs Approval | Behavior or compatibility change that needs a decision |

Type: **security** > **bug** > **race** > **correctness** > **performance** > **docs**.

Severity: **CRITICAL** > **HIGH** > **MEDIUM** > **LOW**.

Line numbers refer to the tree at the time of the audit and may drift; the
symbol name is the stable reference.

## Index

| ID  | Package | Location | Title | Severity | Status |
| --- | ------- | -------- | ----- | -------- | ------ |

No open findings. Every finding of the 2026-09-20 audit (XPKI-001..125) is
fixed and summarized in
[`Documentation/RELEASE_NOTES_1.0.md`](Documentation/RELEASE_NOTES_1.0.md).
Larger follow-up work is in [ROADMAP.md](ROADMAP.md).

## Notes on items needing approval

None. Decisions taken while closing the last batch without a prior approval
are called out in the v1.0 release notes ("Breaking changes") and should be
reviewed: SHA-256 for 3072-bit RSA keys (XPKI-114), rejection of invalid SANs
by `csr.Provider.SignRequest` and `authority.Issuer.Sign` (XPKI-059), the
`code-cov-skipped` status for documentation-only pull requests (XPKI-094),
and `make lint` in CI (XPKI-095).
