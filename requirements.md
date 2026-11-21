# ProvManager — Application Requirements

**Specification status:** Authoritative target behavior for initial development  
**Purpose:** Host and network provisioning management

# Application Overview

**ProvManager** is a lightweight, single-file Python CGI application for administering hosts, network-bootable operating-system installers, Ansible roles, and provisioning templates in small or isolated computing environments. It presents a consistent web interface for viewing and editing provisioning records, preparing boot and deployment configuration, inspecting generated artifacts, and initiating explicitly authorized provisioning operations.

ProvManager shall provide Apache-delegated authentication, an authenticated page header, role-aware navigation and controls, consistent list/detail/form pages, compact filterable tables, predictable post-action redirects, Markdown descriptions, optional site configuration, an embedded favicon, plain HTML/CSS with limited JavaScript, and a comprehensive regression suite. These behaviors are required parts of ProvManager itself and shall be implemented as specified in this document without relying on any external application as a behavioral reference.

The application is intended for controlled internal networks, including disconnected environments. It shall not require an external API, cloud account, JavaScript framework, application server, or database service. Provisioning changes may affect external systems; such operations must be explicit, validated, auditable, and reversible where practical.

## Initial Read-Only Milestone

The initial implementation milestone shall limit operating-system integration to reading configured files, catalogs, directories, account records, and group records for display and validation. It shall not modify DHCP, TFTP, Kickstart, Ansible, service configuration, or any other system-managed target; run validators, provisioning tools, service commands, or playbooks; mount or publish installer media; or launch background jobs. Apply, execution, service reload, and settings-mutation actions shall remain unavailable even if a feature-gate value is enabled. Test-only files may be created only under isolated temporary paths, and the build process may write only to its selected application build-output directory. Later implementation of system mutation requires an approved privileged integration contract and corresponding requirements and regression-test updates.

# Implementation Language and Runtime

- All application code shall be Python; the CGI entry point shall be `provmanager.cgi`.
- The supported interpreter range is Python 3.9 through 3.12. Python 3.13 is unsupported until any dependency on the removed standard-library `cgi` module is replaced.
- Code shall not rely on syntax or standard-library APIs added after Python 3.9. UTC handling shall use `datetime.timezone.utc` rather than `datetime.UTC`.
- Prefer Python's standard library. Third-party YAML and Markdown dependencies shall be explicitly documented; their absence must produce a clear configuration/error response rather than silently corrupting data or treating untrusted HTML as safe.
- Every project-owned Python source file, helper, and test shall carry `SPDX-License-Identifier: AGPL-3.0-only` near its beginning.
- The repository shall include the unmodified GNU Affero General Public License version 3 in `LICENSE`; no project-owned license notice shall imply “or later.”
- The CGI script shall emit valid CGI headers and must write no debug text to standard output before those headers.
- The source shall remain a single CGI entry point initially. Extracting testable helpers into a Python module is permitted without changing the browser-facing CGI contract.

# Architecture and Execution Model

- `provmanager.cgi` shall dispatch all application pages and actions using an `action` query/form parameter.
- GET requests shall retrieve pages or previews and shall not commit configuration changes or launch provisioning.
- Mutating operations shall require POST, server-side permission checks, input validation, and CSRF protection appropriate to the application's authentication model.
- The CGI process shall authenticate nobody directly. An external HTTP authentication layer supplies `REMOTE_USER` and performs password validation, session establishment, and logout.
- User and group information shall be resolved through the operating system/NSS APIs, supporting directory-backed accounts without directly parsing `/etc/passwd` or `/etc/group`.
- The application shall use file-backed records and configuration files; no database server is required.
- The host YAML file shall be the canonical host record store. Installer, role, and template catalogs shall be represented by configured YAML metadata files; actual ISOs, boot files, Ansible content, and Kickstart content remain on disk at configured locations.
- Generated network service artifacts shall be distinct from editable source records. Previewing a change shall not alter deployed service configuration.
- Integration with DHCP, TFTP, Kickstart, and Ansible shall occur through documented local paths and explicitly configured executables. No user-supplied command string shall be passed to a shell.
- A failed write or deployment shall leave the previous valid configuration intact wherever the underlying filesystem permits.

# Global Settings and Default Values

The following names define the application's configuration and defaults. Constants used exclusively for HTML rendering or internal implementation need not be externally configurable.

| Name | Default | Meaning |
| --- | --- | --- |
| `PROVMANAGER_VERSION` | `1.0.0` | Display/build version |
| `SITE_CONFIG_FILE` | `/etc/provmanager.conf` | Optional settings file |
| `HOSTS_FILE` | `/data/provisioning/hosts.yaml` | Canonical host records |
| `INSTALLERS_FILE` | `/data/provisioning/installers.yaml` | Installer catalog |
| `ROLES_FILE` | `/data/provisioning/roles.yaml` | Ansible role catalog/metadata |
| `TEMPLATES_FILE` | `/data/provisioning/templates.yaml` | Provisioning template catalog |
| `AUDIT_LOG_FILE` | `/var/log/provmanager/audit.log` | Persistent audit log |
| `INSTALLER_ROOTS` | empty | Comma-separated approved roots for file-backed installer sources |
| `TFTP_ROOT` | `/var/lib/tftpboot/efi/` | EFI/TFTP boot root |
| `DHCP_CONFIG_FILE` | `/etc/dhcp/dhcpd.conf` | Managed DHCP configuration target |
| `KICKSTART_ROOT` | `/data/provisioning/kickstart/` | Kickstart source/generated files |
| `ANSIBLE_ROOT` | `/data/provisioning/ansible/` | Approved Ansible content root |
| `INVENTORY_OUTPUT_FILE` | `/data/provisioning/ansible/inventory/hosts.yml` | Generated inventory |
| `GENERATED_OUTPUT_DIR` | `/data/provisioning/generated/` | Staging and preview artifacts |
| `LOCK_DIR` | `/data/provisioning/locks/` | Stable lock files |
| `BACKUP_DIR` | `/data/provisioning/backups/` | Pre-change backups |
| `PM_ADMINS_GROUP` | `pm_admins` | Application administrators |
| `PM_AUDITORS_GROUP` | `pm_auditors` | Auditors |
| `PM_PRVADMINS_GROUP` | `pm_prvadmins` | Provisioning administrators |
| `PM_PRVUSERS_GROUP` | `pm_prvusers` | Host managers |
| `PM_VIEWERS_GROUP` | `pm_viewers` | Read-only provisioning viewers |
| `BANNER_FILE` | empty | Optional banner image URL/path |
| `BANNER_DIMENSIONS` | empty | Optional `WIDTHxHEIGHT` |
| `FAVICON_MIME_TYPE` | `image/x-icon` | Embedded multi-size favicon type |
| `AUTH_FORM_ACTION` | `/provmanager-login` | External form-auth endpoint |
| `AUTH_FORM_USERNAME_FIELD` | `httpd_username` | Login username input |
| `AUTH_FORM_PASSWORD_FIELD` | `httpd_password` | Login password input |
| `AUTH_FORM_LOCATION_FIELD` | `httpd_location` | Return-destination input |
| `AUTH_FORM_DEFAULT_LOCATION` | `/cgi-bin/provmanager.cgi` | Safe login return target |
| `LOGOUT_URL` | `/provmanager-logout` | External logout endpoint |
| `LIST_PAGE_SIZE` | `50` | Records shown on one page |
| `SEARCH_HISTORY_LIMIT` | `10` | Per-user remembered search terms |
| `PER_USER_CONFIG_DIR` | `/data/provisioning/user-config/` | Per-user view preferences |
| `MAX_DESCRIPTION_CHARS` | `65536` | Maximum record description size |
| `MAX_TEMPLATE_BYTES` | `1048576` | Maximum editable template content |
| `ENABLE_PROVISIONING_EXECUTION` | `False` | Allow launching configured provisioning jobs |
| `ENABLE_SERVICE_RELOAD` | `False` | Allow applying/reloading external service configuration |

- Executable paths for optional validators, Ansible commands, and service reloads shall be explicit configuration keys with administrator-controlled absolute paths; no built-in default shall run a service-management operation.
- Command arguments that identify targets, inventories, or templates shall be assembled as validated argument arrays; never interpolated into shell commands.
- Installer root allowlists, mount roots, permitted image extensions, network interfaces, managed DHCP section boundaries, and provisioning job locations shall be declared in configuration before related operations can execute.
- `INSTALLER_ROOTS` shall accept a comma-separated list of absolute directory paths. Empty means no installer root is approved for operational use; read-only validation may inspect an existing absolute source path but shall report the missing allowlist as a warning.

# Site Configuration File

- The optional `/etc/provmanager.conf` shall contain plain `KEY=value` entries. Missing files and missing supported keys use documented defaults.
- Ignore blank lines, full-line `#` comments, inline comments outside quoted values, and unknown keys.
- Read only documented supported keys. Do not execute, evaluate, or source the configuration file as Python or shell.
- Invalid values shall not replace defaults and shall generate a safe administrative diagnostic. Unsafe filesystem targets or executable settings shall fail closed rather than falling back to a dangerous write location.
- Validate booleans (`true/false`, `yes/no`, `1/0`, `on/off`), positive integer limits, `WIDTHxHEIGHT` banner dimensions, and absolute filesystem paths.
- All writable directories shall be explicitly created/provisioned by an administrator; CGI requests shall not silently make arbitrary privileged directories.
- Authentication field names, defaults, version, page size, and exposed settings shall be documented separately as code constants or site keys. A sample `provmanager.conf.example` shall enumerate each supported site key and its default.
- Secrets, if integration ever requires them, shall not be written to browser pages, debug logs, audit details, or generated previews. The default design shall avoid storing secrets entirely.

# Identity, Roles, and Authorization

Membership in the following OS groups determines effective permissions. The application shall resolve group membership using NSS, including primary and supplementary groups. An authenticated user with no mapped role is denied application access.

| Role | OS group | Hosts | Installers / roles / templates | Operational settings | Generate / apply / execute | Audit log |
| --- | --- | --- | --- | --- | --- | --- |
| Application Admin | `pm_admins` | Read/write | Read/write | Read/write | All enabled operations | Read |
| Application Auditor | `pm_auditors` | Read | Read | Read | None | Read |
| Provisioning Admin | `pm_prvadmins` | Read/write | Read/write | Read | Generate / apply / execute, subject to enabled feature gates | No access |
| Provisioning User | `pm_prvusers` | Read/write | Read | Read of non-sensitive operational state | Generate preview and inventory preview; no apply/execute | No access |
| Provisioning Viewer | `pm_viewers` | Read | Read | None | Preview of non-sensitive configurations only | No access |

- If a user belongs to multiple groups, the union of granted capabilities applies; explicitly sensitive audit, settings-write, and execution privileges shall never be inferred from ordinary host edit access.
- `pm_admins` governs settings changes and permission-sensitive maintenance. `pm_prvadmins` may operate the provisioning system without changing application security settings.
- Merely hiding UI controls is insufficient: each protected GET and POST handler shall re-check the required permission.
- All list, detail, export, and preview operations shall authorize the requested resource and exclude secrets or restricted operational details.
- Creation, modification, deletion, artifact generation, service apply, and execution shall be recorded in the audit log, including failures when safe and feasible.
- Permission failure shall not modify a record, write generated output, or launch an external command.
- Changes in OS group membership shall take effect on the next CGI request; no persistent role cache may extend prior authorization.
- User full names shall be used for display only. Account names shall be used for security checks, file identity, and audit records.

# Authentication and Public Pages

- Public actions shall be `login`, `login_failed`, `logged_out`, `auth_error`, and `favicon` only.
- A request without `action` shall show `login` if `REMOTE_USER` is empty and the host list if a valid authenticated user is present.
- Protected actions requested without `REMOTE_USER` shall redirect to the login page and carry the intended safe application URL.
- A protected action with an invalid or unmapped user shall return a suitable `403 Forbidden` response.
- The `login` page shall POST to `AUTH_FORM_ACTION`, supply configured username/password/destination fields, and never authenticate or inspect the password itself.
- A login destination may be supplied by the configured destination field; accepted compatibility aliases shall include `next`, `return_to`, `return`, `redirect_to`, `redirect`, and `url` and the split `next_path` / `next_query` form.
- Safe destinations shall be local relative application paths with optional query strings. Reject schemes, scheme-relative URLs, control characters, embedded credentials, malformed encoding, and redirects to public auth pages. Fall back to `AUTH_FORM_DEFAULT_LOCATION`.
- Login may recover an original requested URL from trusted CGI internal-redirect metadata; same-origin referer fallback is permitted only after validation.
- The application must not store, log, echo, or process passwords. Login support pages shall not name Apache, PAM, NSS, or authentication middleware in user-facing text.
- `login_failed`, `logged_out`, and `auth_error` shall be complete, public HTML pages with concise explanations and a link to login.
- `favicon` shall be public, return actual nonempty decoded icon bytes, and use the configured icon MIME type.

# Presentation and Interaction Requirements

## Shared Page Structure

- Every HTML page shall have a consistent document title, content margins, typography, navigation, header, and favicon link.
- A configured `BANNER_FILE` shall display as a banner; valid `BANNER_DIMENSIONS` shall be respected. Without a banner, show a 35px CSS fallback header with a light `#E6E9EF`-to-transparent horizontal gradient, `ProvManager` text in `#BFC5D0`, and a half-body-margin buffer.
- Authenticated pages shall present the page title and right-aligned `Welcome, [Full Name] (Logout)` in the same row. Look up the full name via system account information; fall back to the login name when blank or not a meaningful full name.
- The displayed name shall be bold, and `Logout` shall be a distinct underlined link in parentheses pointing at `LOGOUT_URL`.
- Authenticated pages shall display `ProvManager VERSION` in a centered, unobtrusive footer when the version is nonempty. Public authentication pages shall show neither a logout link nor a version footer.
- A consistent navigation bar shall provide `Hosts`, `Installers`, `Ansible Roles`, `Templates`, and permitted `Operations`, `Settings`, and `Audit Log` destinations.
- Navigation and action links shall only appear where the user has the required capability; denied direct requests still require backend enforcement.
- All visible timestamps shall be stored in UTC and rendered in the browser's local timezone; unparseable legacy values shall display safely without breaking a page.
- Status and result messages shall be clear, concise, and avoid disclosing paths/command output to users without permission.

## Tables, Forms, and Controls

- Tables shall be compact (approximately `0.9rem`), with consistent column headings, padding, alignment, zebra/hover behavior, and empty-state messages.
- Tables shall use clickable record names/identifiers to open the corresponding detail page; no destructive operation shall be triggered by a row click.
- Sort controls shall identify the current sort field and direction. All sorting, filtering, and paging shall take place after access filtering.
- Related controls shall use uniform row gaps near `0.6rem–0.75rem`; tightly coupled pagination controls may use approximately `0.4rem`.
- Page actions, form action rows, inline editors, filter controls, and pagination shall use shared spacing and font-sizing classes.
- Forms shall consistently mark required fields, provide field-level validation feedback, retain safe submitted values after validation failures, and contain `Save`/`Create` plus a nonmutating `Cancel` control.
- Cancel shall return to a validated same-site destination or the corresponding list/detail page. Cancel must never submit a partially edited record.
- On dedicated entry forms, focus the first eligible text input or textarea on load; do not steal focus on list or detail pages. Skip hidden, file, disabled, and read-only inputs.
- Avoid duplicating read-only and edit forms when a compact authorized inline edit is clearer; all inline writes must use POST and the same checks as full forms.
- A change that could invalidate provisioning shall offer an explicit warning/confirmation step; errors shall not discard unsaved form input unnecessarily.
- Controls shall be keyboard-accessible with associated labels, visible focus indicators, and table headers semantically bound to data.

## Filtering, Search, Pagination, and Preferences

- Host, installer, role, template, and audit lists shall support appropriate search, filtering, sorting, and pagination; no collection shall need to be fully rendered to browse it.
- The default list size shall be `LIST_PAGE_SIZE`; page numbers outside the valid range shall resolve safely to an appropriate valid page.
- Host list filters shall include provisioning state, OS/installer, template, role, and a free-text search. Installers, roles, and templates shall offer a name/status/search filter as appropriate.
- Host search shall cover hostname, description, IP address, MAC address, and stored identifying tags; matching shall be case-insensitive unless an administrator configures otherwise.
- Search shall not expose content that the user cannot view. Filters shall be combined predictably, preserved across paging, and easy to reset.
- Per-user filter and view preferences shall be stored under `PER_USER_CONFIG_DIR` using safely mapped per-account file names and atomic writes.
- Per-user preferences shall remember applicable filters, sort direction, display columns where supported, and auto-refresh preference. Malformed or missing preference files shall safely revert to defaults.
- Search history shall store at most `SEARCH_HISTORY_LIMIT` distinct nonempty terms newest-first. Search history controls shall be keyboard-accessible and must never render unescaped input.
- Auto-refresh, when enabled, shall apply only to read-only list/dashboard views, shall retain the current filter state, and shall never resubmit a POST or interrupt an edit form.
- Pagination controls shall appear consistently at the same place above or below tables and preserve current filters.

## Markdown Rendering

- Human-readable descriptions, instructions, and template explanatory text may contain Markdown. Store the original raw Markdown; render only for display.
- Support basic headings, paragraphs, lists, emphasis, links, code blocks, and `~~strikethrough~~` with consistent application CSS.
- Markdown shall never permit executable HTML, scripts, unsafe URL schemes, or event handlers. HTML escaping and URL sanitization shall apply even when a Markdown package is installed.
- If a safe fallback Markdown renderer is provided, it shall escape content and preserve ordinary bullet/numbered lists and strikethrough; otherwise show escaped plaintext.
- A `Markdown Help` page shall document supported syntax and be reachable from relevant edit forms; help links shall open in a new tab/window.

# Data Model and Storage Requirements

## Common Record Rules

- Data files shall contain a documented schema version, stable record identifiers, and a list or mapping of records; the schema shall be documented with examples in the repository.
- Every managed record shall have an immutable identifier, a unique name within its resource type, optional Markdown description, creation timestamp, update timestamp, creator username, and last-editor username.
- Record timestamps shall be ISO 8601 UTC. A logical user-facing name may change without breaking references because cross-record references shall use stable IDs.
- Reject duplicate IDs, duplicate canonical names, invalid reference IDs, malformed document structures, and ambiguous schema versions before writing.
- Unknown fields in existing YAML shall be preserved on updates when harmless, and a schema migration shall be required before a destructive conversion.
- All YAML input shall be parsed using a safe loader; never deserialize Python objects, instantiate arbitrary classes, or execute templating code during storage parsing.
- All record files shall use UTF-8 and deterministic formatting/order where practical to make review and backups intelligible.
- User edits must never replace an entire shared file with an older copy without conflict detection.

## Hosts (`HOSTS_FILE`)

Each host record shall support:

| Field | Semantics |
| --- | --- |
| `id` | Immutable stable host ID |
| `hostname` | Unique canonical DNS hostname; required |
| `description` | Markdown text |
| `mac_addresses` | One or more normalized hardware MAC addresses |
| `ipv4_address` | Optional valid IPv4 address |
| `ipv6_address` | Optional valid IPv6 address |
| `network` | Optional network/subnet identifier or network metadata |
| `installer_id` | Optional reference to an installer |
| `template_id` | Optional reference to a provisioning template |
| `role_ids` | Ordered, deduplicated references to Ansible roles |
| `enabled` | Whether included in active provisioning output |
| `provisioning_state` | `unconfigured`, `ready`, `staged`, `provisioning`, `completed`, `failed`, or `disabled` |
| `variables` | Validated host-specific provisioning variables |
| `tags` | Search/filter tags |
| `created_at`, `updated_at`, `created_by`, `updated_by` | Metadata |

- Hostnames shall be validated as DNS names, normalized case-insensitively for uniqueness, and kept distinct from display descriptions.
- MAC addresses shall use a normalized colon-delimited form; duplicate MAC addresses across active hosts shall be rejected unless an explicit documented shared-identifier model exists.
- IP addresses shall be validated by `ipaddress`; uniqueness conflicts among active hosts shall be rejected in a managed network unless explicitly permitted by configuration.
- A host may be recorded without having all boot requirements configured; it shall not be considered `ready` unless its selected installer/template and required network settings pass readiness checks.
- A change that makes a ready/staged host unprovisionable shall recalculate or invalidate its readiness and alert the user.
- Host record `provisioning_state` describes configuration/workflow status, not a claim that an OS installation succeeded unless an authorized execution record confirms it.
- Deleting a host shall require confirmation and must check for active jobs and generated/deployed artifacts that reference it; default behavior shall disable/retire instead of irreversibly deleting operational history.

## Installers (`INSTALLERS_FILE`)

An installer record shall support `id`, `name`, `description`, `os_family`, `os_version`, `architecture`, `source_type`, `source_path`, optional kernel/initrd/EFI boot paths, optional ISO path, supported boot modes, enabled flag, and common metadata.

- Supported `source_type` values shall include `iso`, `tree`, and `network`; additional types require an explicit adapter.
- File-backed paths shall resolve within configured allowlisted installer or TFTP roots; forbid `..` traversal and symlink escapes outside those roots.
- Installer readiness validation shall check required paths, readable sources, architecture/boot-mode metadata, and referenced boot files without altering files.
- An installer that is referenced by hosts/templates shall not be deleted without an explicit dependency resolution flow.
- A catalog record shall not copy, mount, or publish an ISO merely because it was saved; those are separate authorized operations.

## Ansible Roles (`ROLES_FILE`)

Each catalog entry shall support `id`, `name`, `description`, `role_path`, optional version/metadata, enabled flag, defaults/allowed variables, and common metadata.

- Role paths shall remain under `ANSIBLE_ROOT` or configured allowlisted role roots.
- The application shall discover/display role metadata without executing role code during a list/detail request.
- Changes to role metadata shall not silently modify arbitrary role source files. Source updates shall be a distinct, explicitly authorized operation if implemented.
- Host role order shall be preserved in generated inventory/playbook data wherever role ordering is relevant.
- Referenced roles cannot be deleted without resolving dependent hosts/templates.

## Provisioning Templates (`TEMPLATES_FILE`)

Each template record shall support `id`, `name`, `description`, `template_type`, `content_path` or managed content, optional `installer_id`, ordered `role_ids`, allowed variable names, enabled flag, and common metadata.

- `template_type` shall distinguish `kickstart`, `boot`, `ansible`, and other explicitly supported renderer types.
- Template bodies are source content, not Markdown descriptions; they must be displayed/edited as escaped plaintext with monospace formatting.
- Rendering shall substitute only an allowlisted set of variables and shall never execute arbitrary Python, shell, Jinja expressions with unsafe functions, or filesystem access.
- Missing required variables, invalid references, duplicate generated target paths, and malformed rendered output shall block staging/apply.
- Editing a template shall not automatically overwrite previously deployed files. A preview and explicit apply are required.

## Relationships and Integrity

- Hosts may reference one installer, one provisioning template, and multiple roles. Templates may reference an installer and multiple roles.
- Record detail pages shall display inbound and outbound dependencies with links where authorized.
- Deletion or disabling of a referenced installer, role, or template shall warn about impacted hosts and block generation for those hosts until fixed.
- On every mutation, validate the full set of changed records and their relationships before persisting.
- A malformed/corrupt catalog shall be reported as an administrative error; it shall not be overwritten with an empty default file.

# Persistence, Locking, and Recovery

- All writes to host YAML, catalog YAML, per-user preferences, generated artifact manifests, and managed configuration files shall use `fcntl` advisory locks on stable lock files, not only on a data inode that an atomic rename may replace.
- Shared readers shall observe either the complete previous version or complete new version of a file, never a partial write.
- For updates: acquire a lock, reload the latest file, validate current revision, perform the change, write a same-filesystem temporary file, flush and `fsync`, atomically replace, and `fsync` the containing directory as supported.
- Changes to multiple related files shall be staged and validated as a coherent operation, with recovery metadata/backups and rollback on partial failure; they shall never leave an undocumented half-applied state.
- Preserve file owner, group, permissions, and SELinux context where feasible and required. Do not make sensitive files world-writable.
- Before changing active boot/DHCP/Kickstart files, create timestamped backups with bounded retention and a manifest identifying the originating user, record IDs, and configuration revisions.
- Reject stale concurrent edits with a visible conflict message and an opportunity to reload; do not use last-writer-wins for administrative changes.
- Lock acquisition shall use a documented timeout; timeouts shall produce a clear retryable error, not indefinite CGI hangs.
- A read-only request shall not create or mutate application data merely by viewing it.

# Pages, Forms, and Actions

All pages described below shall share the presentation, authorization, error, cancellation, validation, and redirect behavior defined in this document. For each action, a direct crafted request shall be subject to the same rules as a browser-generated request.

## Host List — `action=hosts`

**Purpose:** Browse host records and understand provisioning readiness at a glance.

- Display columns: Hostname, IP, MAC, Installer, Template, Roles, State, Enabled, Updated.
- Sort by hostname ascending by default; allow user-selected sortable columns and persistent sort preference.
- Provide filters for state, enabled/disabled, installer, template, role, and search, in compact grouped rows.
- Display a total matching-record count and paginate at `LIST_PAGE_SIZE`.
- Hostname links open Host Detail; installer/template/role names link to details where available.
- Show `Create Host` for host-write roles; show `Generate Inventory` only to authorized roles.
- Show an informative empty state with a create link where permitted.
- Refresh does not change filters or trigger provisioning.

## Host Detail — `action=host_view&id=...`

- Display hostname, normalized network identifiers, installer, template, roles in order, description rendered as Markdown, state, enabled flag, metadata, and validation findings.
- Show hyperlinks to referenced installer, template, and roles.
- Show controls as permitted: `Edit`, `Clone`, `Enable/Disable`, `Validate`, `Preview`, `Stage`, and `Retire/Delete`.
- Show recent related audit events only to roles with audit permission; ordinary users may see a non-sensitive last-modified summary.
- Do not claim an unverified host was provisioned successfully.
- Unknown host ID returns `404`; an unpermitted operation returns `403`.

## Create Host — `action=host_create` / `action=host_create_submit`

- GET renders an empty, labeled form with hostname, description, MAC address(es), optional IP/network data, installer, template, roles, variables, tags, enabled checkbox, and cancel.
- Installer/template/role choices shall show only valid catalog entries; invalid stored references must be reported and not silently discarded during edit.
- POST validates all input, duplicate identifiers, referenced records, size limits, and host readiness implications.
- On success, create the record with an immutable ID, UTC metadata, and audit entry; redirect to its detail page using POST/redirect/GET.
- On error, return `400` with safe retained form values and specific field errors, without writing a partial record.

## Edit Host — `action=host_edit` / `action=host_update`

- GET prepopulates the same logical fields as Create Host and includes the record revision.
- POST shall validate the record and its current revision under lock, preserve immutable ID/creator, update edit metadata, and log changed field names with safe old/new values where permitted.
- A hostname change shall preserve references using the immutable ID and shall flag generated artifacts that need regeneration.
- Changing installer, template, roles, MAC, or IP shall mark existing generated output stale, not silently deploy it.
- A stale revision returns `409 Conflict` with an explanation and a reload link.
- On success, redirect to Host Detail.

## Clone Host — `action=host_clone` / `action=host_clone_submit`

- Clone starts from an existing readable host, copies reusable selections and variables, and requires a new unique hostname and hardware identifiers.
- The new record shall have a new ID, new creator/timestamps, no inherited execution history, and default `unconfigured` state until validated.
- The clone must not alter the original.

## Enable, Disable, Retire, and Delete Host

- State-changing requests use POST, require host-write permission, and validate dependencies/active jobs.
- Disabling excludes the host from newly generated active provisioning outputs. Previously deployed configuration remains until an authorized apply reconciles it.
- Retiring retains the record and audit trail but prevents future provisioning until explicitly restored.
- Permanent deletion is admin-only, requires a confirmation naming the host, and is blocked if active work or required audit/reference retention would be violated.
- Each successful change redirects to the relevant detail/list with a result message.

## Installer List — `action=installers`

- Display Name, OS family/version, Architecture, Source type, Enabled, Validation, Referencing Hosts, Updated.
- Support search, enabled filter, architecture/OS filter, sorting, and pagination.
- Catalog write roles shall see `Add Installer`; other roles shall only see read/preview controls.

## Installer Detail / Create / Edit / Disable / Delete

- `installer_view`, `installer_create`, `installer_create_submit`, `installer_edit`, and `installer_update` shall follow the corresponding Host page conventions.
- Display source paths, boot-mode requirements, boot files, metadata, impacted hosts/templates, and validation findings.
- Validate path allowlists, file existence/readability, supported architecture, and unique names.
- Only authorized provisioning/admin roles may stage/publish an installer, and only after preview/validation.
- Disabling an installer shall identify downstream readiness impact. Deleting a referenced installer shall be blocked until dependencies are resolved.

## Ansible Role List and Detail

- `roles`, `role_view`, `role_create`, `role_create_submit`, `role_edit`, and `role_update` shall provide compact list/detail/form flows.
- Show role name, path, description, enabled state, referencing hosts/templates, and validation status.
- New/edited role paths must be validated against the configured allowed roots; the browser shall not offer arbitrary filesystem browsing.
- Template/host role ordering shall be visible and adjustable with accessible controls.
- Role metadata deletion shall be dependency-checked; catalog changes do not execute playbooks.

## Template List and Detail

- `templates`, `template_view`, `template_create`, `template_create_submit`, `template_edit`, and `template_update` shall provide list/detail/form flows.
- The list shall show name, type, installer, roles, enabled, affected hosts, and updated time.
- Template Detail shall display Markdown description, escaped source preview, variable documentation, dependencies, and last validation status.
- The template editor shall use a monospace multiline source field and shall not interpret template content as application HTML.
- Saving a template shall validate type, size, variables, path targets, and reference integrity without applying output.
- `template_preview` shall render an explicit selected host/template pairing with variables and identify missing values/errors without writing target files.
- Disabled or referenced templates shall follow the same dependency and edit-conflict rules as other catalogs.

## Operations Dashboard — `action=operations`

- Provisioning Admin and Application Admin shall have a dashboard summarizing invalid/ready/staged hosts, stale generated outputs, last successful generation/apply, and recent job statuses.
- A Provisioning User may view non-sensitive previews and readiness information but shall not see privileged execution controls.
- Display operations as separate `Validate`, `Preview`, `Generate`, `Apply`, and `Execute` stages, never as one ambiguous button.
- Each operation shall identify affected hosts, target artifacts, last-change time, requesting user, and result.

## Validate — `action=validate` / `action=validate_submit`

- GET shall display the selected validation scope (one host, selected hosts, or whole catalog) without modifying data.
- Validation shall check YAML/schema/reference integrity, duplicate identifiers, boot source availability, required template variables, allowed paths, rendering errors, and dependencies.
- Results shall distinguish Errors (block stage/apply), Warnings (require acknowledgement if operationally significant), and Information.
- An authorized POST may persist a validation summary/audit event, but shall not write active boot/service configurations.

## Preview and Generate — `action=preview`, `action=generate_submit`

- Preview shall display the exact proposed generated inventory/boot/Kickstart/DHCP-managed output, or a bounded diff against current deployed artifacts, with sensitive values redacted.
- Preview shall name target paths and list affected hosts, without applying any external change.
- Generate shall require provisioning-admin/admin permission; it writes only into `GENERATED_OUTPUT_DIR` under a unique revision/manifest.
- A generated manifest shall list source record revisions, filenames, hashes, target paths, validation results, requesting user, and timestamps.
- Generated artifacts shall be deterministic for identical inputs, subject to explicitly documented timestamp/version fields.
- Generation shall be blocked on readiness errors, unsafe paths, conflicting target paths, or stale edited input.
- A generated revision remains staged until explicitly applied.

## Inventory Generation

- The generated Ansible inventory shall include only eligible enabled hosts and their intended groups/variables in stable order.
- A preview shall show included/excluded hosts and the reason for each exclusion.
- Sensitive data shall never be exposed to unauthorized viewers or included in browser previews.
- The output shall be validated as YAML and written atomically; avoid unsafe string concatenation and quoting errors.
- The inventory target shall be `INVENTORY_OUTPUT_FILE` when explicitly applied, not when merely previewed.
- Ansible roles shall not execute merely because an inventory was generated.

## Apply Generated Configuration — `action=apply` / `action=apply_submit`

- Apply shall require provisioning-admin/admin permission and `ENABLE_SERVICE_RELOAD=True` if it entails service reload/restart. File installation without service reload still requires the appropriate explicit capability and confirmation.
- The confirmation page shall show staged revision, source revision, target paths, a diff/summary, validation results, backup plan, and expected service effects.
- Before applying, recheck current input revisions and target hashes; reject stale previews/configurations with `409 Conflict`.
- Back up affected files, validate the candidate with configured non-destructive validators, install atomically, and run only explicitly configured allowlisted reload commands.
- A failed validation must prevent deployment. A failed deployment or reload shall attempt rollback and prominently report whether recovery was complete.
- Never rewrite unrelated portions of a shared DHCP configuration; use a documented managed section or generated included file, and reject ambiguous unmanaged edits.
- Apply must not be exposed as a GET link or executed by page refresh.

## Execute Provisioning / Ansible — `action=execute`, `action=execute_submit`

- Execution shall be unavailable unless `ENABLE_PROVISIONING_EXECUTION=True`, and shall require provisioning-admin/admin permission.
- The request shall identify an explicit target scope and a configured, allowlisted operation; no arbitrary script, shell fragment, or playbook path shall be accepted from the client.
- Show a pre-execution summary of hosts, installer/template/roles, environment, expected changes, and confirmations.
- Execution shall use argument-array subprocess invocation with fixed executable paths, controlled working directory, timeouts, and bounded captured output.
- A job shall have a unique ID, requesting user, start/end timestamps, target host IDs, status (`queued`, `running`, `succeeded`, `failed`, `canceled`), exit status, and sanitized output location.
- Launching shall not be repeated by browser refresh; duplicate requests shall be guarded by a one-time operation token/idempotency key.
- Output must be escaped and access-controlled. Job cancellation, if available, shall be explicitly authorized and logged.
- The CGI request shall not pretend a detached process succeeded; show whether launch was accepted and link to job status. A documented worker/service integration is required for reliable long-running tasks.

## Settings — `action=settings`, `action=settings_update`

- Application Admin alone may edit operational settings. Provisioning Admin and Auditor may view settings; viewer/user visibility is limited to harmless status when appropriate.
- Settings shall show effective value, whether default or overridden, and a safe explanation; sensitive command internals and secrets shall be withheld from unauthorized readers.
- Only explicitly editable keys shall be offered. Validation shall include path safety, value types, directory access, cross-setting consistency, and known feature gates.
- Changes shall write the supported site configuration safely with locking, backup, and audit; preserve comments/unknown lines where possible rather than deleting unrelated configuration.
- Settings updates that require a new request/process or service action shall say so explicitly and shall not silently reload services.

## Audit Log — `action=audit`

- Only Application Admin and Application Auditor may browse the audit log.
- Display timestamp, actor, action, resource type/ID, outcome, and a concise sanitized description; allow filters for date, actor, action, resource, and success/failure.
- Show newest first, with pagination and read-only detail views where appropriate.
- The log shall be append-only under normal application operations, with timestamps in UTC and sufficient record identity to correlate a change to a user.
- Do not record passwords, secrets, full template contents, environment dumps, unredacted subprocess output, or unnecessary personally identifying information.
- Unauthorized access to audit details shall return `403` even if the user guesses a URL.

## Markdown Help — `action=markdown_help`

- Display safely rendered Markdown examples and examples of supported syntax.
- This page is available only to authenticated users with access to a Markdown-capable edit/view interface.

# Audit and Operational History

- Audit entries shall cover create/edit/clone/enable/disable/retire/delete, settings changes, validation, generation, apply, execution, failures, and access-sensitive operational actions.
- Each entry shall include a stable event ID, UTC time, acting login, role/capability at time of action, action name, target record IDs, outcome, and a bounded redacted summary.
- The audit writer shall use appropriate locking or atomic append semantics. Audit failure during a high-risk configuration mutation shall block the mutation or produce an explicitly configured fail-closed response.
- Job status and artifact manifests are operational records separate from human-readable audit summaries.
- Audit logs shall be subject to administrator-managed rotation and retention without allowing routine users to delete records.

# Security Requirements

- Perform authorization in every action handler, including previews, downloads, exports, validation, and mutation endpoints.
- Escape untrusted text in HTML, HTML attributes, textarea content, titles, logs, and generated links; apply safe Markdown rendering.
- Never construct file paths by directly concatenating untrusted hostnames, record IDs, template names, or filenames.
- Reject absolute path injection, traversal (`..`), null/control bytes, symlink escapes, and non-allowlisted target paths.
- Reject unsafe URL schemes and cross-origin login/cancel destinations; encode/escape output URLs correctly.
- Use CSRF tokens for all state-changing POST requests, bound to the authenticated context without requiring the CGI process to handle passwords.
- Impose input size limits before parsing; reject malformed or overly large YAML/HTTP input with `400` or `413` as applicable.
- Use safe YAML loading and content rendering; template variable evaluation must not permit arbitrary code execution.
- Use absolute allowlisted executable paths and argument lists; never use `shell=True` with external input.
- Use least-privilege filesystem permissions and separately controlled privilege boundaries for any system-service action.
- The CGI application shall not directly run as root merely to manage DHCP/TFTP; privileged operations shall use a narrow, audited, administrator-configured helper if required.
- Avoid leaking raw stack traces, full filesystem paths, configuration secrets, or internal shell output in public error pages.
- Server-side checks must remain in force even if JavaScript is disabled or form fields are modified by a client.
- Use `Cache-Control: no-store` for authentication pages and pages containing sensitive operational data.

# Routing, HTTP Responses, and Error Handling

- Browser-facing actions shall use the shared `provmanager.cgi?action=...` dispatch convention.
- Unknown action names shall return `400 Bad Request` or `404 Not Found` consistently, without falling through to privileged behavior.
- Invalid input, malformed data, missing required fields, invalid IP/MAC/hostname, unsafe paths, and invalid enum values shall return `400 Bad Request` with field-level explanation where safe.
- Authentication and authorization failures shall return `403 Forbidden`; missing `REMOTE_USER` on a protected page shall normally redirect to login first.
- Missing host/installer/role/template/job records shall return `404 Not Found`.
- Stale edits/apply requests shall return `409 Conflict`; oversized request bodies shall return `413 Payload Too Large`.
- Unexpected internal errors shall return `500 Internal Server Error`, logged with correlation ID and without exposing a traceback to the browser.
- CGI responses shall always include `Content-Type` and proper `Status` where needed; redirects shall include a valid `Location` and use `303 See Other` after a successful POST.
- Public auth pages shall be complete HTML pages. Plaintext errors shall advertise `text/plain`; HTML pages shall advertise `text/html; charset=utf-8`.
- After a successful create/update/disable/generate/apply action, redirect to the appropriate list/detail/status page. Refreshing that page shall never repeat the mutation.
- The application shall only accept same-site validated return locations and shall fall back to the relevant list/detail page when an unsafe return is requested.

# Deployment, Build, and Repository Workflow

- The repository shall include `provmanager.cgi`, `requirements.md`, `regression_testing_requirements.md`, `AGENTS.md`, `README.md`, `provmanager.conf.example`, `LICENSE`, `build.sh`, and a `tests/` directory.
- `README.md` shall document intended use, package dependencies, Python compatibility, service/configuration prerequisites, example catalog schemas, installation, filesystem ownership, permissions, first-run setup, backup/restore, and test execution.
- The deployment guide shall explain how to configure HTTP form authentication externally without requiring ProvManager to know the password backend.
- Provide a validation command for catalog schemas and staged output without contacting production DHCP, TFTP, or Ansible targets.
- `build.sh` shall stamp `PROVMANAGER_VERSION` from the base semantic version and abbreviated Git commit ID, using `x.y.z-dev.N+GITID` by default and `x.y.z+GITID` with `--release`.
- The build script shall refuse to modify a file without exactly one recognizable `PROVMANAGER_VERSION` assignment and shall never alter the documented base version inadvertently.
- Commit ordinary source changes on a development branch, not directly on `main`; keep the source default `PROVMANAGER_VERSION` at the documented base version except in intentional build-output commits.
- `AGENTS.md` shall instruct automated code editors to consult the current application requirements, regression requirements, and agent instructions before nontrivial changes, preserve security checks and bugfix comments, and produce reviewable minimal diffs.
- Bugfix regression-protection comments should use consistent `BUGFIX:`, `REGRESSION GUARD:`, and `REQUIREMENTS:` markers where useful.

# Regression Testing Requirements

- ProvManager shall include an automated regression suite covering its functional, security, presentation, data-integrity, and operational requirements.
- The suite shall run under supported Python versions without Apache, root privileges, production OS accounts or groups, live network or provisioning services, or access to production data.
- Regression tests shall never modify real hosts, production configuration, DHCP/TFTP/Kickstart/Ansible resources, or external services.
- The separate `regression_testing_requirements.md` shall define test cases, fixture and mocking conventions, test isolation, expected CGI responses, failure injection, and requirement-to-test traceability.
- `requirements.md` is authoritative for application behavior; `regression_testing_requirements.md` is authoritative for verification procedures and shall not override the functional requirements.
- Functional changes shall be accompanied by corresponding regression tests where applicable. Failed or unexecuted required tests shall be reported accurately; a release shall not be considered complete unless its required regression suite passes.

# Acceptance Criteria for Initial Complete Release

An initial complete release shall be accepted when an authorized user can log in, navigate uniform list/detail/form pages, create and edit valid hosts, link installer/role/template records, see accurate readiness validation, preview generated boot and inventory artifacts, and have an authorized administrator explicitly stage and apply an audited configuration without unintended writes. Read-only roles must be incapable of mutation even with crafted requests. All file writes must be concurrency-safe, all advertised security boundaries must be regression-tested, and the application must deploy in a disconnected internal environment using Python 3.9–3.12 and the documented dependencies.

# Default Filesystem Paths Summary

| Component | Path |
| --- | --- |
| Site configuration | `/etc/provmanager.conf` |
| Host data | `/data/provisioning/hosts.yaml` |
| Installer catalog | `/data/provisioning/installers.yaml` |
| Ansible role catalog | `/data/provisioning/roles.yaml` |
| Template catalog | `/data/provisioning/templates.yaml` |
| Per-user preferences | `/data/provisioning/user-config/` |
| Lock directory | `/data/provisioning/locks/` |
| Backups | `/data/provisioning/backups/` |
| Staged generated output | `/data/provisioning/generated/` |
| Audit log | `/var/log/provmanager/audit.log` |
| TFTP boot files | `/var/lib/tftpboot/efi/` |
| DHCP configuration | `/etc/dhcp/dhcpd.conf` |
| Kickstart files | `/data/provisioning/kickstart/` |
| Ansible content | `/data/provisioning/ansible/` |
| Generated Ansible inventory | `/data/provisioning/ansible/inventory/hosts.yml` |

# Specification Authority and Completeness

This document is the authoritative functional and operational specification for ProvManager. Implementers shall derive required application behavior, user workflows, authorization decisions, validation rules, rendering, configuration, and error handling from this document rather than from any outside application. `regression_testing_requirements.md` shall elaborate test cases and fixtures but shall not override application behavior specified here. If a required behavior is ambiguous or missing, the implementation shall surface the question for resolution rather than silently importing assumptions from another product. Any approved behavioral change shall update this specification and the relevant regression tests together.
