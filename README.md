# ProvManager

**ProvManager** is a lightweight, Python-based web application for managing Linux host and network provisioning. Designed for small, internal, and isolated computing environments, it provides a centralized interface for maintaining host definitions, operating-system installers, Ansible roles, and provisioning templates.

> **Project status: Early development.** This README describes the intended application. Features and workflows documented below are requirements, not a claim that the application is already implemented or ready for production.

## Goals

ProvManager is designed to make host provisioning easier to administer without requiring a large provisioning platform, a database server, or a cloud service. Its design emphasizes:

- A straightforward browser interface deployed as a Python CGI application.
- Canonical, human-inspectable YAML records.
- Operating-system group–based permissions.
- Clear separation between editing records, previewing changes, staging output, applying configuration, and executing provisioning.
- Auditable changes, safe file updates, and recovery from failed operations.
- Compatibility with controlled or air-gapped environments.

## Planned capabilities

### Host management

Create, edit, clone, enable, disable, and retire host records. Host definitions include hostnames, MAC and IP addresses, installer and template references, ordered Ansible roles, variables, tags, and provisioning status. Lists will support searching, filtering, sorting, and pagination.

### Operating-system installers

Maintain a catalog of network-bootable OS installers, including ISO, installation-tree, and network sources. Validate boot files, architecture, supported boot modes, and allowed filesystem paths before generating provisioning output.

### Ansible role management

Catalog approved Ansible roles, reference them from hosts and templates, preserve role order, and generate Ansible inventory. Browsing a role or generating inventory will not execute a playbook.

### Provisioning templates

Manage boot, Kickstart, and Ansible-related templates with controlled variable substitution, dependency checking, and safe content preview. Saving a template will not silently overwrite deployed files.

### Controlled provisioning workflow

Provisioning is organized into separate stages:

1. **Validate** host and catalog data, references, boot sources, and template inputs.
2. **Preview** the proposed inventory, DHCP, boot, and Kickstart content without applying changes.
3. **Generate/stage** validated artifacts with a revision manifest.
4. **Apply** a selected staged revision after confirmation, backups, and revalidation.
5. **Execute** an explicitly authorized provisioning or Ansible operation, if execution is enabled.

Apply and execution are separate, permission-controlled operations. Service reloads and provisioning execution are disabled by default. Failures are to be reported accurately, with rollback attempted where practical.

## Access control

Authentication is delegated to the HTTP authentication layer, which passes the authenticated username through `REMOTE_USER`. ProvManager does not validate or store passwords. Authorization uses operating-system/NSS group membership.

| OS group | Role | Principal permissions |
| --- | --- | --- |
| `pm_admins` | Application Admin | Full record and operational settings management; authorized provisioning operations; audit access |
| `pm_auditors` | Application Auditor | Read-only access to records, operational settings, and audit data |
| `pm_prvadmins` | Provisioning Admin | Manage records and run authorized generation, apply, and execution workflows; read settings |
| `pm_prvusers` | Provisioning User | Manage hosts; view catalogs; preview configurations and inventory |
| `pm_viewers` | Provisioning Viewer | Read-only access to provisioning records and permitted non-sensitive previews |

Every protected action must enforce permissions on the server, including requests made directly to CGI endpoints.

## Architecture

- **Runtime:** Python 3.9–3.12.
- **Web model:** Single CGI entry point, `provmanager.cgi`, with `action`-based routing.
- **Web server:** Intended for deployment behind an HTTP authentication layer such as Apache.
- **Storage:** YAML catalogs and filesystem-based provisioning artifacts; no database service.
- **Integrations:** DHCP, EFI/TFTP, Kickstart, and Ansible through configured local paths and approved executables.
- **Interface:** Server-rendered HTML/CSS with limited JavaScript.
- **License:** GNU Affero General Public License version 3 only (`AGPL-3.0-only`).

Python 3.13 is not part of the initial supported runtime range because the standard-library `cgi` module was removed in that version. Dependencies for YAML and optional Markdown rendering will be documented with the implementation.

## Default filesystem layout

| Purpose | Default path |
| --- | --- |
| Site configuration | `/etc/provmanager.conf` |
| Hosts | `/data/provisioning/hosts.yaml` |
| Installer catalog | `/data/provisioning/installers.yaml` |
| Ansible role catalog | `/data/provisioning/roles.yaml` |
| Template catalog | `/data/provisioning/templates.yaml` |
| Kickstart content | `/data/provisioning/kickstart/` |
| Ansible content | `/data/provisioning/ansible/` |
| Generated inventory | `/data/provisioning/ansible/inventory/hosts.yml` |
| Generated/staged artifacts | `/data/provisioning/generated/` |
| Lock files | `/data/provisioning/locks/` |
| Backups | `/data/provisioning/backups/` |
| Per-user preferences | `/data/provisioning/user-config/` |
| Audit log | `/var/log/provmanager/audit.log` |
| EFI/TFTP root | `/var/lib/tftp/efi/` |
| Managed DHCP configuration target | `/etc/dhcp/dhcpd.conf` |

Paths and supported settings are governed by the application requirements and optional `KEY=value` site configuration. Writable directories and privileged integration paths must be provisioned by an administrator; browser requests must not silently create arbitrary privileged directories.

## Safety and reliability

The design requires:

- Safe YAML parsing, input validation, and constrained filesystem paths.
- Stable `fcntl` lock files, atomic replacement, and stale-edit detection for shared records.
- Read-only previews that never modify deployed service files.
- Source-revision checks and manifests for generated content.
- Backups before active configuration changes, with documented rollback handling.
- Explicit confirmation and role checks for apply and execution actions.
- Allowlisted executables and argument-array subprocess invocation rather than shell-interpolated commands.
- Persistent audit events without passwords, secrets, or unnecessary sensitive output.
- Automated regression tests that use isolated temporary files and simulated system integrations—not production provisioning resources.

## Configuration and deployment

ProvManager is intended to run on an existing Python-capable web server with external authentication and suitable access to its configured provisioning directories.

The optional `/etc/provmanager.conf` will use documented `KEY=value` entries. Missing settings use built-in defaults where safe. Operational capabilities that affect system services or execute provisioning jobs are disabled unless explicitly configured.

**Installation is not yet documented as a tested, production-ready procedure.** Refer to the requirements for the intended configuration model; deployment steps will be added as the implementation matures.

## Development and testing

The project maintains three complementary documents:

- [`requirements.md`](requirements.md) — authoritative application behavior, schemas, permissions, routes, and operational workflows.
- [`regression_testing_requirements.md`](regression_testing_requirements.md) — required test isolation, cases, and requirement-to-test traceability.
- [`AGENTS.md`](AGENTS.md) — guidance and guardrails for automated coding contributors.

The planned regression suite uses `pytest` and must run without Apache, root privileges, real provisioning operations, or production accounts and services. Test expectations are defined by the requirements rather than inferred solely from current code.

## Intended audience and scope

ProvManager is intended for administrators who need a practical, self-hosted interface for provisioning in small networks, labs, internal workgroups, or disconnected environments.

It is **not** intended to be an unrestricted remote shell, a general-purpose infrastructure orchestration platform, or a replacement for security controls already provided by the operating system and network.

## License

ProvManager is planned to be distributed under the **GNU Affero General Public License version 3 only (AGPL-3.0-only)**. See [`LICENSE`](LICENSE) when that file is present in the repository.
