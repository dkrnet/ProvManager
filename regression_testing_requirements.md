# ProvManager — Regression Testing Requirements

**Specification status:** Authoritative testing specification for initial development  
**Companion document:** `requirements.md`  
**Purpose:** Define repeatable, production-safe verification of ProvManager behavior.

# 1. Authority, Scope, and Test Philosophy

- `requirements.md` is the authoritative specification of application behavior. This document specifies how to test that behavior, not a competing behavior definition.
- Every implemented feature and security boundary described in `requirements.md` shall have proportionate automated verification. Tests shall not merely reproduce observed implementation behavior when it differs from the specification.
- When implementation, test expectations, and requirements disagree, identify the discrepancy and resolve it against the documented requirements; do not silently rewrite tests or requirements to conceal it.
- Tests shall cover successful requests, invalid requests, forbidden requests, missing records, stale state, malformed stored files, and injected operational failures.
- Security and integrity checks shall be exercised through direct CGI requests, not only by verifying that the UI hides a button.
- The suite shall be deterministic, repeatable, independent of execution order, and suitable for continuous integration in an isolated environment.
- The suite shall never require or operate on production hosts, boot services, real inventory targets, privileged system files, or external network services.
- Existing tests shall not be weakened or deleted solely to make a new implementation pass. Fix implementation defects or obtain an approved requirements change.

# 2. Supported Python and Test Commands

- Tests shall work with the application-supported Python range, 3.9 through 3.12, without using newer syntax or APIs.
- The tests shall not claim Python 3.13 compatibility while the application depends on the removed standard-library `cgi` module.
- `pytest` is the primary test framework; additional test dependencies shall be documented and minimized.
- Syntax check the entry point with `python3 -m py_compile provmanager.cgi` and any extracted application modules or scripts.
- Run the regression suite with `python3 -m pytest -q`; a specific supported interpreter may be substituted, such as `python3.9 -m pytest -q`.
- A release-validation command shall run the complete suite; targeted tests may be run during development but do not replace release coverage.
- A test run shall exit nonzero when any required test fails. Skips and expected failures shall be explicit, justified, and summarized in release reports.
- Verify package compatibility, where interpreters are available, on every supported minor Python version; an environment with only one interpreter shall report the others as untested.

# 3. Suite Organization and Traceability

A suggested initial structure is:

```text
provmanager.cgi
requirements.md
regression_testing_requirements.md
AGENTS.md
tests/
  conftest.py
  test_import_and_configuration.py
  test_authentication.py
  test_permissions.py
  test_routing_and_http.py
  test_presentation.py
  test_preferences_and_search.py
  test_records_and_validation.py
  test_catalog_dependencies.py
  test_yaml_persistence.py
  test_hosts.py
  test_installers.py
  test_roles.py
  test_templates.py
  test_provisioning_validation.py
  test_preview_and_generation.py
  test_inventory.py
  test_apply_and_rollback.py
  test_execution.py
  test_settings.py
  test_audit.py
  test_security.py
```

- Files may be combined early in development, but coverage shall remain identifiable and focused.
- Tests should name the behavior protected and reference the applicable `requirements.md` heading, using a marker, docstring, comment, or coverage mapping.
- Shared fixture logic belongs in `tests/conftest.py` and helpers, not duplicated in every test module.
- Each external-effect boundary (filesystem writes, NSS lookups, subprocess execution, external authentication, clock, service reload) shall have a replaceable test seam.
- Prefer parameterized cases for input validity and role/action matrices, rather than long sets of repetitive nearly identical tests.

## 3.1 Requirement-to-test mapping

| Application requirements section | Primary test area |
| --- | --- |
| Implementation Language and Runtime; Architecture and Execution Model | Import, syntax, dispatch, request isolation |
| Global Settings and Default Values; Site Configuration File | Defaults, parsing, validation, optional configuration |
| Identity, Roles, and Authorization | NSS/group resolution, role/capability matrix, direct-action denial |
| Authentication and Public Pages | Login support, destinations, missing/invalid users, favicon |
| Presentation and Interaction Requirements | Shared chrome, forms, filtering, search, Markdown, preferences |
| Data Model and Storage Requirements | Schema, field validation, uniqueness, references, metadata |
| Persistence, Locking, and Recovery | Interprocess locking, atomic writes, backups, recovery, conflict detection |
| Pages, Forms, and Actions | Every list/detail/form/submit action, workflow, and result |
| Audit and Operational History | Events, actor, outcomes, redaction, log access, write failure |
| Security Requirements | CSRF, escaping, path/symlink protection, command safety, confidentiality |
| Routing, HTTP Responses, and Error Handling | Content types, statuses, redirects, failures, POST/redirect/GET |
| Deployment, Build, and Repository Workflow | Packaging, version stamping, sample configuration, documentation checks |
| Acceptance Criteria for Initial Complete Release | End-to-end isolated acceptance scenarios |

# 4. Test Isolation and Side-effect Prohibition

- During the initial read-only milestone, assert that application requests never modify DHCP, TFTP, Kickstart, Ansible, service configuration, or any other system-managed target and never invoke validators, provisioning commands, service commands, playbooks, mounts, or background workers. Enabling a parsed feature-gate setting must not make an unimplemented operation available.

- All test-created canonical catalogs, preference files, generated artifacts, backups, manifests, audit logs, lock files, and simulated deployed output shall live under a per-test temporary directory.
- Use a fixture such as `tmp_path` to construct a fully isolated `/data/provisioning/` equivalent without writing to the actual `/data/provisioning/` tree.
- Remap `HOSTS_FILE`, `INSTALLERS_FILE`, `ROLES_FILE`, `TEMPLATES_FILE`, `PER_USER_CONFIG_DIR`, `LOCK_DIR`, `BACKUP_DIR`, `GENERATED_OUTPUT_DIR`, `KICKSTART_ROOT`, `ANSIBLE_ROOT`, `INVENTORY_OUTPUT_FILE`, `TFTP_ROOT`, `DHCP_CONFIG_FILE`, `AUDIT_LOG_FILE`, and `SITE_CONFIG_FILE` to test-only paths.
- Ensure the default Kickstart root is verified as `/data/provisioning/kickstart/`, while actual test Kickstart operations target the isolated equivalent.
- No test may assume writable `/etc`, `/var/lib/tftp`, `/var/log`, `/data`, or other production paths; use a deliberate failure guard if an operation attempts to touch an unremapped path.
- Block real network connections and real service-management, Ansible, mount, or provisioning executables. The default test harness shall fail rather than execute any unexpected subprocess.
- Tests shall not depend on Apache, an authentication backend, real LDAP/SSSD/FreeIPA, installed system groups, actual DHCP/TFTP services, root privileges, or real network-bootable hardware.
- Each test shall cleanly restore patched environment variables, globals, umask, working directory, and any installed test doubles.
- Tests that create child processes for contention checks shall pass only temporary paths and shall have bounded timeouts and cleanup.
- Tests shall not rely on the host's local timezone, locale, username, current date, group membership, or environmental service state.

# 5. Shared Fixtures and Test Model

## 5.1 Recommended fixtures

- `app_module`: imports application logic without running a live CGI request, either from `provmanager.cgi` or an extracted testable module.
- `isolated_paths`: replaces every configured data, staging, deployment, settings, audit, backup, and lock path with test paths.
- `sample_catalogs`: builds valid, versioned YAML files with consistent host/installer/template/role references.
- `fake_nss`: replaces OS user and group lookup operations, including primary and supplementary group membership and full-name resolution.
- `acting_user`: controls `REMOTE_USER` and associated account/group attributes for the current request.
- `cgi_request`: constructs GET and POST CGI environment/input, including the `action` parameter, content length, form encoding, and CSRF context.
- `capture_response`: captures CGI standard output and byte output and parses headers, status, location, content type, and body.
- `fixed_clock`: sets deterministic UTC times and allows advancing time where timestamps or expiry matter.
- `mock_commands`: captures allowed executable paths, argument arrays, working directories, timeouts, return statuses, and bounded output; fails on unexpected commands.
- `filesystem_failures`: injects access errors, short/failed writes, rename failures, lock timeouts, and failed backup or reload operations.
- `staged_revision`: creates a valid generated manifest and files using temporary roots, suitable for apply tests.

Fixtures may use equivalent names, but shall provide these capabilities.

## 5.2 Mocked user/group cases

Use test users representing:

- An Application Admin in `pm_admins`.
- An Application Auditor in `pm_auditors`.
- A Provisioning Admin in `pm_prvadmins`.
- A Provisioning User in `pm_prvusers`.
- A Provisioning Viewer in `pm_viewers`.
- A user with two or more mapped groups.
- A valid NSS user with no mapped application group.
- A user whose login name does not resolve through NSS.
- A user whose full-name attribute is blank or does not represent a meaningful full name.

Ensure group enumeration covers a user's primary group and supplementary membership, and does not assume `/etc/group` contains all directory-backed members.

## 5.3 Sample provisioning records

- Use at least two independent hosts, one disabled host, an incomplete host, and a ready host with valid installer/template/role links.
- Include different IPv4/IPv6 values, normalized and non-normalized MAC input, ordered roles, tags, variables, and a Markdown description.
- Include referenced and unreferenced installers, roles, and templates; one deliberately invalid path and one missing required variable for negative testing.
- Include a versioned YAML document, immutable IDs, creator/editor metadata, UTC timestamps, and an otherwise harmless unknown field to test lossless editing.
- Include a simulated generated manifest, staged files, preexisting deployed targets, and a controlled DHCP managed section.
- Tests shall distinguish corrupt YAML from legitimately empty catalogs; a corrupt file must never be silently replaced with an empty one.

# 6. Imports, Configuration, and Versioning

- Import application logic without printing headers, mutating catalogs, launching jobs, or requiring an active Apache request.
- Verify Python 3.9-compatible imports, syntax, UTC handling, and valid CGI header emission on actual request execution.
- Verify that source defaults match the `Global Settings and Default Values` table in `requirements.md`, including `/data/provisioning/kickstart/`.
- Missing site configuration shall retain defaults. Missing supported keys shall retain their respective defaults.
- Parse valid `KEY=value` lines, blank lines, full-line and allowed inline comments, and permitted quoted values.
- Unknown keys shall be ignored without altering other settings; the config file must never be executed as Python or shell input.
- Malformed booleans, nonpositive size limits, invalid dimensions, and invalid/relative executable or filesystem paths shall yield the specified safe defaults or fail-closed behavior.
- Verify sensitive or unsafe path/executable overrides cannot silently enable privileged operations.
- Verify sample configuration contains every supported site key and the documented values or explanatory defaults.
- Check that `PROVMANAGER_VERSION` appears as intended on authenticated pages, is absent from public auth pages, and is preserved as the base version in ordinary source.
- Test `build.sh` in a temporary Git repository with development and release modes, missing/multiple version assignments, absent release tag, and existing metadata suffixes; ensure no unintended source edits.
- Verify project-owned Python files carry `SPDX-License-Identifier: AGPL-3.0-only`; do not replace the repository's `LICENSE` content.

# 7. Authentication, Login, and Routing

- Without `action`, a request without `REMOTE_USER` shall display the login page; a valid mapped user shall reach the host list.
- Every public action (`login`, `login_failed`, `logged_out`, `auth_error`, `favicon`) shall be reachable without `REMOTE_USER`.
- Protected actions requested without `REMOTE_USER` shall redirect to login with a safe intended destination; invalid or unmapped users shall receive the required `403` response.
- Authentication pages shall be complete HTML documents, with concise messages and no disclosure of authentication backend names, server internals, or credentials.
- The login form shall POST to `AUTH_FORM_ACTION` and include correctly named username, password, and destination fields without accepting or validating passwords in CGI logic.
- Test all supported destination aliases: the configured destination name, `next`, `return_to`, `return`, `redirect_to`, `redirect`, `url`, and split `next_path`/`next_query`.
- Test safe local destinations with queries and original URLs from trusted CGI redirect metadata; test a validated same-origin referer fallback.
- Reject absolute external URLs, `//` or encoded scheme-relative destinations, explicit schemes, control characters, userinfo, malformed encodings, and destinations pointing to public authentication pages.
- Invalid/missing destinations shall fall back to `AUTH_FORM_DEFAULT_LOCATION` without cross-origin navigation.
- `favicon` shall return nonempty binary image content, with configured MIME type and correct headers, without requiring a separate favicon file.
- Reject unknown actions consistently and enforce a real method boundary: GET never mutates state, starts jobs, or applies artifacts.
- Verify a direct POST to each state-changing endpoint cannot bypass authentication, authorization, CSRF, or validation.

# 8. Role and Capability Matrix

- Build a parameterized matrix covering each documented role, each relevant action, and permitted versus forbidden behavior.
- Verify host read/write, catalog read/write, settings read/write, non-sensitive operational views, generate, apply, execute, and audit access as documented.
- Verify the Provisioning User can modify hosts but cannot edit installer/role/template catalogs or apply/execute provisioning.
- Verify the Viewer can access only authorized read-only views and non-sensitive previews.
- Verify the Auditor can inspect authorized settings and audit data but cannot mutate records or generate/apply/execute.
- Verify the Provisioning Admin can manage catalogs and use permitted operations, but not change sensitive settings or browse audit logs.
- Verify the Application Admin can perform enabled administrative operations and access audit records.
- Verify users in multiple mapped groups gain the documented union without implying extra sensitive privileges from ordinary host edits.
- Verify users with no mapped role are denied access; role/group changes take effect on the next request rather than via a stale cache.
- Verify denial causes no file mutation, audit-data disclosure, stage creation, service reload, or external command execution.
- Verify both UI visibility and direct backend enforcement; do not treat hidden controls as a substitute for direct-request tests.
- Verify cross-resource links, search results, exports, and preview data are filtered to authorized information.

# 9. HTTP Responses, Rendering, and Forms

- Parse and assert CGI `Status`, `Content-Type`, `Location` (when redirecting), and header/body boundaries.
- Cover `400` for invalid fields/requests, `403` for forbidden requests, `404` for missing records, `409` for stale revisions, `413` for excessive payloads, and sanitized `500` for unexpected failures.
- Ensure ordinary malformed requests do not report `500`; internal failures must not expose tracebacks or sensitive paths to browsers.
- Successful state-changing submissions shall use `303 See Other` to an authorized list/detail/status page; refreshing the resulting GET shall not repeat the mutation.
- Every HTML page shall include consistent header, title, favicon reference, navigation where appropriate, and shared styles.
- When configured, banner dimensions shall be respected; without the banner, assert the specified fallback header presentation values and ProvManager labeling.
- Authenticated pages shall show `Welcome, [Full Name] (Logout)`, with fallback login-name behavior and correct logout destination; public auth pages shall not show that link or version footer.
- Verify shared table headings, compact styles, semantically associated labels, visible focus rules, and accessible keyboard controls using rendered markup assertions where practical.
- Dedicated entry forms shall focus the first eligible text input/textarea; list/detail views shall not steal focus.
- Required fields and validation errors shall be indicated; safe submitted values shall be retained on failed submissions.
- Cancel controls shall be nonmutating and use validated same-site destinations with documented fallbacks.
- Reject reflected/stored HTML injection in field values, titles, attributes, Markdown, errors, generated links, and operational output.
- Markdown descriptions and help shall render common headings, lists, emphasis, code, links, and strikethrough safely; the fallback path shall escape untrusted HTML.
- Template source text shall display as escaped plaintext, never as interpreted Markdown or HTML.
- The Markdown Help page shall show supported examples only to authorized users and be linked from relevant editing pages.
- Store UTC timestamps, render local-time capable markup where appropriate, and safely display malformed legacy timestamps without exceptions.

# 10. Lists, Search, Pagination, and Preferences

- Exercise host, installer, role, template, and audit list pages with empty, small, exact-page, and multi-page data sets.
- Assert the Host List columns are `Hostname`, `IP`, `MAC`, `Installer`, `Template`, `Roles`, `State`, `Enabled`, `Updated` in documented order; verify corresponding detail links.
- Verify the Host List defaults to ascending hostname and respects authorized user-selected sorts with stable tie behavior.
- Verify filters for provisioning state, enabled flag, installer, template, role, and case-insensitive search over hostname, description, IP, MAC, and tags.
- Verify each catalog list's documented filters/columns and audit list date/actor/action/resource/outcome filters.
- Verify combined filters, matching counts, reset behavior, paging persistence, and that inaccessible records never appear in counts or results.
- Page size shall default to `LIST_PAGE_SIZE`; invalid/out-of-range pages shall resolve to a valid page without exceptions or leaks.
- Verify empty-state messages and creation links appear only for permitted roles.
- Per-user preferences shall persist documented filters, sorting, optional columns, and auto-refresh independently for two test users.
- Missing or malformed preference files shall fall back safely; user names must not permit unsafe preference filenames.
- Search history shall retain at most `SEARCH_HISTORY_LIMIT` distinct, nonempty, newest-first terms and never leak between users.
- Search-history control markup shall safely escape malicious terms and remain usable without unsafe inline code.
- Auto-refresh shall preserve current filters and apply only to read-only list/dashboard views; form edits and POST requests shall never be refreshed or resubmitted.

# 11. YAML Schemas, Identity, and Relationships

- Verify every catalog's required schema version, structure, stable IDs, unique canonical names, UTC timestamps, creator, and last-editor metadata.
- Reject invalid YAML, unsupported/ambiguous versions, duplicate IDs/names, missing required fields, invalid references, and unsafe object constructors before any write.
- Ensure record edits preserve immutable IDs and creator metadata, harmless unknown existing fields, supported role order, and unrelated records.
- Verify hostnames are normalized for case-insensitive uniqueness and validated as DNS names; validate MAC normalization/uniqueness, IPv4/IPv6 parsing, and managed-network active-address uniqueness.
- Verify host state values and enabled status obey the documented readiness/dependency rules; a record may be incomplete without incorrectly being marked `ready`.
- Verify installer `source_type` enumeration (`iso`, `tree`, `network`), architecture, boot modes, required source paths and boot files, enabled flag, and allowlist controls.
- Verify role catalog paths, version/metadata, enabled flag, role variable constraints, and host/template role order.
- Verify template types (`kickstart`, `boot`, `ansible`, supported additional types), source path/content fields, content size limit, approved variable names, referenced roles/installer, and allowed renderers.
- Check inherited references when record names change: dependent resources must continue referencing stable IDs.
- Verify invalidated dependencies lower readiness, mark affected staging stale, and are shown on resource detail pages.
- Verify referenced installer, role, and template deletion is blocked until dependencies are resolved, including references from templates as well as hosts.
- Ensure corrupted catalogs are never treated as legitimately empty catalogs and are not destroyed by a subsequent save.

# 12. Persistence, Locks, Atomic Writes, and Recovery

- Verify writes occur only while holding the stable lock-file `fcntl` lock, not merely a lock on an inode that will be replaced by rename.
- Use independent processes (not only threads) to exercise competing writers. Assert both changes survive when compatible, and conflicts are rejected rather than lost.
- Verify each write reloads data under lock and checks expected revisions. Stale edits shall return `409 Conflict` without changing the shared file.
- Force lock contention and timeout; the application shall return a bounded, retryable failure instead of hanging.
- Inject failures while writing temporary files, flushing, `fsync`-ing, renaming, synchronizing directories, and updating metadata where supported.
- Assert that interrupted/failed writes preserve either the previous complete file or a new validated complete file, never a truncated or partially serialized YAML file.
- Verify temporary files are created on the target filesystem with safe permissions and cleaned up or recoverably reported after failure.
- Verify permitted ownership, mode, and SELinux handling is preserved as documented, without making sensitive files world-writable.
- Verify coordinated multi-file operations stage/validate first, maintain manifests/backups, and report partial failure with recovery context rather than hiding it.
- Verify read-only pages and preview requests do not silently create or change data files.
- Verify backups are made before affected active files are changed, and restoration information permits unambiguous recovery.

# 13. Host Workflows

- `hosts`: verify list behavior, counts, sorting, state/installer/role/template filters, action controls, and no side effects.
- `host_view`: verify metadata, normalized identifiers, ordered linked roles, safe Markdown, validation findings, and appropriate audit summary visibility.
- `host_create`: verify blank, labeled entry form and authorized choices; `host_create_submit`: verify valid creation, server-side checks, immutable ID, creator/timestamps, audit, and redirect.
- Invalid create submissions shall not persist partial records and shall retain safe form values with field-specific feedback.
- `host_edit` shall prepopulate the current record and revision; `host_update` shall preserve identity, detect stale revisions, invalidate derived output as necessary, and redirect on success.
- Host changes to installer, template, roles, MAC/IP, or hostname shall mark generated output stale or identify regeneration needs, not silently apply changes.
- `host_clone` and `host_clone_submit` shall preserve reusable selections, require a distinct hostname/hardware ID, allocate a new stable ID, clear execution history, and default the clone to `unconfigured`.
- Verify enable/disable, retire/restore where implemented, and permanent-delete flows require POST, permission, confirmation, and dependency/active-job checks.
- Disabling shall exclude a host from new active outputs while leaving already-deployed output unchanged until authorized apply.
- Permanent deletion shall require admin permission and host-name confirmation; history/active-work retention checks shall block unsafe deletion.
- Verify no host operation implies successful OS provisioning absent a verifiable successful execution record.

# 14. Installer, Role, and Template Workflows

## 14.1 Installers

- Verify `installers` list headings, filters, sorting, pagination, validation state, referencing-host counts, and role-aware `Add Installer` control.
- Verify `installer_view`, `installer_create`, `installer_create_submit`, `installer_edit`, and `installer_update` render/validate the documented data and adhere to form/redirect conventions.
- Verify source paths, ISO/tree/network behavior, kernel/initrd/EFI paths, readability, architecture/boot mode, allowed roots, unique names, and dependency checks.
- Saving installer catalog metadata shall not automatically copy, mount, publish, or deploy content.
- Publishing/staging operations, where supported, shall require the proper capability and completed validation/preview.

## 14.2 Ansible roles

- Verify `roles`, `role_view`, `role_create`, `role_create_submit`, `role_edit`, and `role_update` flows.
- Role file paths must remain under approved roots; browser requests may not enumerate arbitrary filesystem locations.
- Catalog reads and metadata edits shall not execute role code, edit unrelated role source files, or launch playbooks.
- Verify accessible ordering controls retain role order and reject duplicate role IDs.
- Verify deletion/disable operations report referencing hosts/templates and preserve integrity.

## 14.3 Templates

- Verify `templates`, `template_view`, `template_create`, `template_create_submit`, `template_edit`, and `template_update` flows and authorized UI.
- Assert template detail displays sanitized Markdown description, escaped source content, documented variables, last validation result, and dependencies.
- Verify editor content is represented as escaped monospace plaintext and accepts only bounded, validated sources.
- `template_preview` shall render a selected authorized host/template pair without file writes or execution.
- Missing required variables, unsafe renderer expressions, unsupported types, duplicate output targets, and invalid references shall prevent staging/apply.
- Template updates shall mark related generated artifacts stale without touching deployed files.

# 15. Validation, Preview, and Generation

## 15.1 Operations and validation

- `operations` shall show the documented readiness, staged/stale, last generation/apply, and job summaries to appropriately authorized users.
- Verify `Validate`, `Preview`, `Generate`, `Apply`, and `Execute` remain clearly distinct operations with separate authorizations.
- `validate` shall render scope selection without modification; `validate_submit` may persist permitted validation/audit summaries but shall not install boot, DHCP, Kickstart, or inventory output.
- Validate host, selected-host and catalog scopes against YAML/schema, references, duplicates, boot-path availability, allowed roots, template variables, renderer errors, and dependencies.
- Results shall distinguish blocking errors, warning/acknowledgement conditions, and informational findings.
- Failure and validation messages shall not disclose secrets or privileged paths to unauthorized users.

## 15.2 Preview purity

- `preview` and `template_preview` shall produce expected bounded diffs or artifact views and list affected hosts/target paths for authorized readers.
- Snapshot all canonical, staged, deployed, backup, and audit resources before a pure preview and verify no unexpected modification or command invocation afterward.
- Verify previews redact sensitive values and never expose configuration beyond the user's authorized scope.
- Verify disabled/ineligible hosts are identified with exclusion reasons where a preview shows inventory membership.

## 15.3 Staging and generation

- `generate_submit` shall be POST-only and require Provisioning Admin or Application Admin permission.
- Staging shall write only to `GENERATED_OUTPUT_DIR` under unique revision/manifest metadata; target DHCP/TFTP/Kickstart/inventory deployment paths shall remain unchanged.
- Manifest tests shall assert source revisions, target paths, source/target hashes as specified, filenames, actor, validation outcomes, and UTC timestamps.
- Two generations from identical inputs shall produce deterministic artifact bytes, except for explicitly documented timestamps/version identifiers.
- Missing variables, invalid paths, target path collisions, conflicting network data, invalid rendered content, or stale source revisions shall block generation.
- Verify authorization failure, validation failure, and interrupted generation do not claim a complete staged revision or expose partial artifacts as eligible for apply.

# 16. Ansible Inventory

- Verify inventory preview includes only eligible enabled hosts and explains exclusion of disabled, incomplete, or otherwise disallowed hosts.
- Assert stable host/group ordering, variables, correct quoting/YAML escaping, and preservation of ordered role relationships where needed.
- Parse generated inventory with a safe YAML parser and verify structural validity and absence of unsafe object tags.
- Verify unauthorized previews redact sensitive values, while staged output contains only data required by the authorized provisioning workflow.
- No inventory generation or preview shall run roles/playbooks, reload services, or write `INVENTORY_OUTPUT_FILE` before authorized apply.
- On authorized apply, inventory shall go only to the configured intended target and retain the documented backup/rollback protections.

# 17. Apply, Configuration Safety, and Rollback

- `apply` shall render the selected stage/revision, source revisions, target paths, diff/summary, validations, backup plan, and expected service effects without mutating deployed state.
- `apply_submit` shall require POST, a valid CSRF token, proper role, documented confirmation, and current staging manifest.
- If the apply requires a service reload, verify `ENABLE_SERVICE_RELOAD=False` blocks it; `True` does not itself bypass capability or command allowlists.
- File-only installation shall still require explicit permission and confirmation; the feature gate must not silently turn on operations.
- Immediately before write, recheck source revisions and target hashes. Modified sources or externally changed targets shall yield `409` rather than overwriting changes.
- Assert preflight non-destructive validators run on staged candidates before any active replacement, and validation failure causes no deployment.
- Verify backups precede mutation, active changes use atomic replacement, and configured service actions run only after successful validation and installation.
- Simulate failure at each boundary: backup, validation, first file replace, later file replace, service reload, final manifest/audit write, and rollback.
- Confirm rollback restores prior contents wherever possible, marks outcome accurately, reports incomplete recovery, and never claims success after partial failure.
- Verify shared DHCP files change only inside a documented managed section or by a supported include mechanism; unmanaged contents remain byte-for-byte intact.
- Reject unsafe target paths, symlink escapes, unexpected file ownership, missing manifests, corrupted staged files, and staged/target hash mismatches.
- Refreshing an apply confirmation or result page shall never repeat deployment.

# 18. Execution and Provisioning Jobs

- With `ENABLE_PROVISIONING_EXECUTION=False`, neither direct CGI requests nor UI controls may launch a provisioning command.
- With the gate enabled, only authorized Provisioning Admin/Application Admin requests may execute configured allowed operations.
- `execute` shall display explicit host/operation scope, relevant installer/template/roles, controlled environment, expected changes, and confirmations.
- `execute_submit` shall reject arbitrary executable, script, playbook, shell text, target path, argument injection, or unapproved working-directory values supplied by clients.
- Assert subprocess invocation uses configured absolute executables and argument lists, no interpolated shell execution, controlled working directory, timeouts, and bounded/sanitized output.
- Verify operation idempotency token prevents duplicate submissions, including browser refresh, replay, and concurrent duplicate POST attempts.
- Verify job IDs, actors, host IDs, lifecycle status (`queued`, `running`, `succeeded`, `failed`, `canceled`), exit codes, UTC times, and sanitized output references.
- Test failed launch, timeout, nonzero exit, interrupted worker, and cancellation (if supported) without claiming provisioned success.
- A successful accepted launch shall not be reported as successful OS installation; status shall reflect verified job completion only.
- Mock a worker/service integration for long-running tasks; the CGI handler must not pretend an untracked detached process succeeded.
- Verify output view and cancellation controls are authorized and all job actions are audited.

# 19. Settings and Audit

## 19.1 Settings

- `settings` shall show effective values, default/override provenance, and safe descriptions to permitted roles, withholding sensitive internals from other users.
- Only Application Admin may `settings_update`; verify denial for every other role, including direct POST.
- Only documented editable keys shall be accepted; test type validation, absolute paths, directory access, permission limits, cross-setting consistency, and operation feature gates.
- Writes shall be locked, backed up, atomic, and audited. Preserve unrelated comments and unknown configuration lines where the application supports such preservation.
- Verify setting changes requiring a new request, restart, or operational step are explained and do not silently reload a service.

## 19.2 Audit and operational records

- Verify required audited operations: create/edit/clone/enable/disable/retire/delete, configuration changes, validation, stage, apply, execute, and material failures/denials where safe.
- Audit records shall include stable event ID, UTC timestamp, acting login, effective role/capability, action, affected resource IDs, outcome, and bounded redacted summary.
- Assert append-only operational behavior, bounded size, safe concurrency, rotation/retention protection, and no ordinary-user modification or deletion.
- `audit` list and detail actions shall require Application Admin or Application Auditor; other roles shall receive `403` even for guessed record URLs.
- Verify date/actor/action/resource/outcome filters, newest-first ordering, and pagination with isolated test records.
- Inject audit write failures; verify documented fail-closed behavior before high-risk mutations and an accurate, recoverable outcome if failure occurs after a partial operation.
- Audit entries and web pages shall never include passwords, secrets, raw environment dumps, full template bodies, or unredacted command output.
- Operational manifests/job records shall be distinguishable from audit summaries and correlate using stable IDs.

# 20. Security and Adversarial Tests

- Exercise server-side CSRF protection on every mutating POST: valid tokens, missing tokens, malformed tokens, replay where constrained by contract, and tokens associated with another authenticated context.
- Attempt direct unauthenticated/unauthorized access to every read/write/preview/export/download endpoint.
- Submit hostile HTML and Markdown including script tags, event-handler attributes, `javascript:` links, malformed entities, and markup in filenames, metadata, errors, and command output.
- Exercise traversal and escape attempts using `../`, absolute paths, URL encoding, null/control bytes, symlinks, and names resembling legitimate paths.
- Confirm all file-backed installer, role, template, artifact, backup, and deployment targets stay inside the configured allowlists after canonical path resolution.
- Verify no YAML object construction or Python code execution occurs during parsing; renderers must not evaluate unrestricted Python/shell/Jinja expressions.
- Verify configured executables are absolute, approved, and invoked with arrays (never untrusted `shell=True` content).
- Verify request size and field-length limits are enforced before unsafe parsing; oversized input shall return the appropriate `413` or bounded `400`.
- Verify `Cache-Control: no-store` on authentication/sensitive operational pages, and safe error messages without tracebacks, credentials, or private filesystem details.
- Verify no privilege escalation occurs through role overlap, forged hidden form fields, stale UI state, impersonated record creators, or guessed IDs.
- Ensure logging and displayed generated diffs redact credentials and other sensitive variables.

# 21. Fault Injection and Concurrent Scenarios

- Run concurrent host create/update operations from at least two independent processes, including contention for the same record and distinct records.
- Include concurrent catalog changes during validation/staging and concurrent target changes immediately before apply.
- Test process termination or I/O failure at critical points in atomic file replacement, staged generation, multi-file apply, and rollback.
- Test missing/unreadable catalogs, unavailable lock directories, lack of disk space (simulated), invalid configuration, and partial/corrupt backups.
- Ensure failed operations do not silently replace malformed catalogs with empty documents or leave incorrect ready/staged/provisioned claims.
- Verify retryable contention/conflict failures are appropriately bounded, user-facing, and observable in audit/operational status where specified.
- Ensure cleanup and recovery test code cannot escape the temporary test filesystem root.

# 22. Isolated End-to-End Acceptance Scenarios

The following scenarios shall be executable against temporary storage and fake external systems:

1. An authorized Provisioning User logs in, creates a valid host, links existing installer/role/template records, updates it, and sees readiness findings without deploying anything.
2. An Application Admin or Provisioning Admin validates a set of eligible hosts, previews deterministic artifacts, stages a revision, inspects the manifest, confirms apply, and observes a simulated successful installation plus audit evidence.
3. A Viewer and Auditor browse only authorized information; attempted direct POSTs, restricted previews, and execution/apply paths fail without side effects.
4. Two independent users edit overlapping host data; a stale update receives `409` and current data remains intact.
5. A malformed template, missing installer path, or unsafe renderer variable prevents staging and leaves deployment untouched.
6. Active deployed configuration changes after stage creation; apply detects mismatch, returns conflict, and preserves the changed target.
7. Simulated service reload fails after validated file installation; rollback restores backups (or accurately reports incomplete recovery) with an audit trail.
8. A simulated provisioning job is accepted once, cannot be replayed with the same idempotency token, and reports final success or failure based only on confirmed job outcome.
9. An invalid YAML catalog, malicious input, or unauthorized direct action produces a safe error and no unintended data mutation or disclosure.
10. A complete test run uses `/data/provisioning/kickstart/` as the configured default while making no writes to that production path or other live provisioning resources.

# 23. Test Maintenance and Release Gates

- Any change affecting CGI dispatch, form fields, role permissions, catalog schemas, validation, generated paths/content, locking, apply, execution, or audit shall include corresponding test updates.
- Bug fixes shall add a regression test reproducing the failure whenever practicable; preserve relevant `BUGFIX:`, `REGRESSION GUARD:`, and `REQUIREMENTS:` comments as directed by `AGENTS.md`.
- Test cases shall use bounded waits and controlled clocks rather than unbounded sleeps or real network/service events.
- Test failures shall report the affected behavior and enough sanitized context to diagnose the cause without printing secrets.
- Syntax checks and the full required regression suite must pass before considering a release complete. Report not-run, skipped, or environment-limited suites rather than asserting unverified success.
- New tests shall remain isolated from production data and should be runnable repeatedly, locally and in CI, with the same behavior.
- No test shall require implementing non-specified features merely to satisfy a fixture. When the functional contract is unclear, report the ambiguity for a requirements decision.
