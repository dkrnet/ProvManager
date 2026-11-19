# AGENTS.md — ProvManager Development Guardrails

> This document governs AI-assisted and automated changes to the ProvManager repository. It is self-contained and does not depend on any other project's implementation or documentation.

## 1. Read before making nontrivial changes

Before making a nontrivial application, test, build, deployment, or configuration change, read the current versions of these repository files:

1. `requirements.md` — authoritative functional and operational requirements.
2. `regression_testing_requirements.md` — authoritative regression-test design and coverage requirements.
3. `AGENTS.md` — mandatory editing and maintenance rules.

Read relevant source and tests as well; do not assume behavior from filenames or previous conversations. A short summary or an earlier version of a required file is not a substitute for the current file.

If a required document is missing or inaccessible, identify it and stop before nontrivial implementation changes, unless the project owner explicitly authorizes proceeding without it. **Bootstrap exception:** when establishing a new repository, an agent may create or revise the missing requirements, testing specification, agent instructions, and initial nonfunctional scaffolding under an explicit request. This exception does not authorize implementing provisioning behavior before reviewing the available requirements.

Nontrivial changes include feature additions or removals, CGI dispatch or form behavior, access-control changes, YAML schema or persistence changes, boot-file generation, external command execution, deployment or rollback logic, configuration changes, and refactoring with potential runtime effects. Pure formatting, comment typo corrections, and other proven behavior-neutral edits are trivial.

## 2. Sources of authority and conflicts

- `requirements.md` defines what ProvManager must do, including behavior, data schemas, role capabilities, UI, security, paths, configuration, and error handling.
- `regression_testing_requirements.md` defines how those requirements are verified, including fixtures, isolation, coverage, and test conventions. It must not weaken or override application behavior in `requirements.md`.
- This file defines how automated contributors inspect, edit, test, and propose changes.
- Current implementation and existing tests are evidence of behavior, **not** permission to contradict requirements.
- If documents, tests, and implementation disagree, report the conflict; do not silently rewrite requirements or tests to make an implementation pass.
- When a requested behavior change is approved, update the affected functional requirements and regression cases in the same change where practical.
- Do not invent defaults, executable paths, service names, network topology, data migration policy, or operational permissions when they are not defined; ask or document the unresolved requirement.

## 3. Preserve architecture and compatibility

- Preserve the `provmanager.cgi` CGI entry point and documented `action` routing contract.
- Maintain Python 3.9–3.12 compatibility. Do not introduce syntax or standard-library APIs unavailable in Python 3.9; for example use `datetime.timezone.utc`, not `datetime.UTC`.
- Do not assume Python 3.13 compatibility while depending on the removed standard-library `cgi` module.
- Keep runtime dependencies minimal and explicitly documented. Do not introduce a framework, database service, cloud dependency, or background daemon without approval.
- Do not print debug content to CGI standard output before response headers.
- Use `SPDX-License-Identifier: AGPL-3.0-only` on project-owned Python source, test, and helper files; preserve the repository's AGPLv3-only licensing policy.
- Preserve the intended distinction between canonical YAML records, generated/staged artifacts, and deployed operating-system service files.

## 4. Authentication and authorization are mandatory backend checks

- Authentication is delegated to the configured HTTP layer. Protected actions obtain the acting username from `REMOTE_USER`; the CGI application must not authenticate passwords, record them, or expose them in logs or pages.
- Use NSS-aware operating-system user/group resolution, not manual parsing of `/etc/passwd` or `/etc/group`.
- Enforce the five documented role mappings and capabilities: `pm_admins`, `pm_auditors`, `pm_prvadmins`, `pm_prvusers`, and `pm_viewers`.
- Check permission on **every** protected action, including direct requests to submission endpoints, downloads, preview, generation, apply, execute, settings, and audit pages.
- Hiding navigation links or form buttons is not authorization. Crafting a direct CGI request must not bypass restrictions.
- Keep public authentication-support and favicon actions separate from protected actions, as specified in `requirements.md`.
- Apply CSRF protection to state-changing POST actions. GET requests must never mutate records, apply configuration, or launch provisioning.
- Preserve validated same-origin redirects and safe post-login destinations. Never construct open redirects from untrusted request input.
- Never leak internal authentication mechanism details in public-facing login/error pages.

## 5. Treat provisioning operations as high risk

- **Never run against production resources during development or tests** without explicit authorization. This includes DHCP configuration, TFTP trees, Kickstart content, Ansible inventory/playbooks, real machines, and service-management commands.
- Keep default executable and service-reload capabilities disabled unless the specification authorizes enabling them and the required configuration is present.
- Do not introduce subprocess calls that interpolate untrusted input into a shell command. Use validated argument arrays and administrator-configured absolute executable paths; avoid `shell=True`.
- Validate every filesystem target against configured allowed roots. Guard against `..` traversal, unexpected symlinks, unsafe filenames, and overwriting unmanaged files.
- Keep read-only previews pure: showing a preview must not write managed files, stage artifacts, restart services, or perform provisioning.
- Keep **validate**, **preview**, **generate/stage**, **apply**, and **execute** as distinct operations with explicit authorization boundaries and user confirmation where required.
- Check source revisions and staging manifests immediately before applying, so stale generated content cannot overwrite newer changes.
- Validate generated syntax and target safety before deployment. Preserve a backup and attempt the documented rollback on partial failure; report incomplete recovery clearly.
- A failed operation must not claim success or mark a host provisioned unless supported by verifiable execution results.

## 6. Protect file integrity and concurrent updates

- Treat `/data/provisioning/hosts.yaml` and the installer, role, and template YAML catalogs as canonical state. Preserve schema versions, stable record IDs, cross-record references, unknown compatible fields, and immutable metadata as specified.
- Parse untrusted YAML with a safe loader. Never permit YAML object construction, arbitrary code execution, or unsafe template evaluation.
- Before modifying a shared data file, acquire an `fcntl` lock on a **stable lock file**, reload current content, validate the revision, apply the change, and write atomically using a same-filesystem temporary file, flush/`fsync`, atomic replacement, and appropriate directory synchronization.
- Never assume locking the target inode is sufficient after an atomic rename.
- Preserve documented timeout and conflict behavior; never silently overwrite a concurrent user's edit.
- For coordinated multi-file changes, stage/validate first and preserve backups, manifests, and recovery information. Do not leave undocumented partially applied configurations.
- Avoid destructive YAML reformatting or dropping fields while updating one record. Keep output deterministic where practical.
- Do not change file ownership, permissions, or configured data paths without an explicit requirement and review.

## 7. Preserve validation, safe rendering, and auditability

- Validate hostnames, MAC/IP addresses, identifiers, references, variables, installer paths, template inputs, and all allowed enums server-side.
- Never trust hidden form fields, client-side validation, or authorization decisions transmitted by the browser.
- Escape HTML and sanitize Markdown output, links, and unsafe URL schemes. Store raw Markdown and render it only for display.
- Protect configuration and audit files from untrusted path and content injection. Never print secrets, unredacted sensitive command output, or credentials in HTML, generated previews, or audit details.
- Record required actor, time, action, target, result, and safe summary data in the audit log. Do not bypass fail-closed audit behavior for high-risk changes.
- Preserve CGI status codes, content types, response headers, redirect safety, and user-facing error semantics for invalid, missing, unauthorized, or failed operations.

## 8. Keep UI and workflows consistent

- Use shared page chrome, navigation, spacing, forms, table styles, pagination, and role-aware action controls across Hosts, Installers, Ansible Roles, Templates, Operations, Settings, and Audit.
- Keep `Welcome, [Full Name] (Logout)`, the optional banner/fallback header, footer version, embedded favicon, and browser-facing terminology consistent with `requirements.md`.
- Preserve safe cancel/return destinations, field-level validation, form focus behavior, filter persistence, and the rule that mutations are submitted only via POST.
- Do not add controls that imply an operation succeeded before the backend confirms it.
- Prefer understandable, small changes over duplicating page-specific validation or security logic.

## 9. Regression tests are part of the change

- Follow `regression_testing_requirements.md` for test structure, fixture behavior, traceability, and coverage; create/update focused tests with behavioral changes.
- Run tests against **temporary** YAML, configuration, staging, backup, audit, Kickstart, DHCP, TFTP, and Ansible paths. Mock NSS, `REMOTE_USER`, system commands, subprocess execution, time, and relevant filesystem failures.
- Test denial of unauthorized direct POSTs as well as role-aware presentation.
- Test malicious/invalid inputs, duplicate identifiers, stale revisions, concurrent writers, atomic-write failures, lock timeouts, partial apply failures, rollback, and safe error handling.
- Test preview purity, deterministic generation, manifest integrity, and strict separation of source, staged, and deployed state.
- Do not require Apache, root, real host provisioning, live network services, or production group membership for regression tests.
- Use the documented commands where applicable:

```sh
python3 -m py_compile provmanager.cgi
python3 -m pytest -q
```

- Do not report tests as passing unless they were actually executed. If testing is unavailable, say exactly what was not run and why.
- Do not change test expectations solely to make newly modified code pass when those expectations correctly reflect the requirements.

## 10. Bug fixes and regression-guard comments

- When fixing a behavioral bug, add a short, nearby comment explaining the underlying failure and the reason for the protective behavior where it would not otherwise be obvious.
- Use consistent markers when useful: `BUGFIX:`, `REGRESSION GUARD:`, and `REQUIREMENTS:`.
- Preserve existing bug-fix and regression-guard comments. Remove or replace them only with explicit approval or when replacing the implementation with an equivalent or stronger protection, updating the comment accordingly.
- Add a regression test that would have detected the reported defect whenever practical.

## 11. Patch and repository workflow

- Prefer minimal, reviewable changes. Avoid unrelated cleanup, wholesale reformatting, or speculative feature work.
- Do not commit ordinary development changes directly to `main`; use a development branch, consistent with the repository requirements.
- Preserve the source-default `PROVMANAGER_VERSION` value before ordinary source commits. Generated development/release stamping belongs to the documented build process.
- **For patch-only responses**, unless the project owner requests another format, output a valid unified diff: include `---` and `+++` file headers, `@@` hunks, and at least three unchanged context lines where available; do not substitute snippets or ellipses for unchanged source. Do not wrap a patch-only response in Markdown fences or surrounding prose.
- **When editing files directly in an authorized workspace**, make the edits in place and provide a concise summary and actual test results instead of duplicating the entire patch; supply a diff if requested.
- Do not claim a build, deployment, backup, rollback, or commit was performed unless it actually was.

## 12. Pre-change and completion checklist

Before editing, confirm:

1. Current `requirements.md`, `regression_testing_requirements.md`, and `AGENTS.md` have been reviewed, subject only to the explicit bootstrap/owner exception.
2. Affected code paths, authorized roles, and external filesystem/service boundaries have been identified.
3. Production data, tools, and services will not be changed accidentally.
4. Any ambiguity or conflict with authoritative requirements has been surfaced.

Before reporting completion, confirm:

1. No unrelated behavior, security guard, or regression comment was removed.
2. Relevant requirements and tests were updated together.
3. CGI routing, POST/CSRF enforcement, RBAC, path validation, YAML locking/atomicity, and audit behavior remain correct.
4. Generated/staged/deployed state is still clearly separated.
5. Syntax checking and relevant regression tests were run where possible, and results are stated accurately.
6. Changes are reviewable and use the expected patch or direct-edit reporting format.

**When in doubt, preserve existing protections, avoid touching operational provisioning resources, and explicitly report unresolved requirements rather than guessing.**
