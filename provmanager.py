# SPDX-License-Identifier: AGPL-3.0-only
"""Core request and configuration support for ProvManager."""

import base64
import grp
import html
import ipaddress
import os
import pwd
import re
from dataclasses import dataclass, fields, replace
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, FrozenSet, List, Mapping, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urlsplit

try:
    import yaml
except ImportError:  # pragma: no cover - exercised by deployments without dependencies
    yaml = None

try:
    import bleach
    import markdown
except ImportError:  # pragma: no cover - safe plaintext fallback is tested directly
    bleach = None
    markdown = None


PROVMANAGER_VERSION = "1.0.0"
PUBLIC_ACTIONS = frozenset({"login", "login_failed", "logged_out", "auth_error", "favicon"})

ROLE_CAPABILITIES = {
    "application_admin": frozenset({"hosts_read", "hosts_write", "catalogs_read", "catalogs_write", "settings_read", "settings_write", "operations_read", "preview", "generate", "apply", "execute", "audit_read"}),
    "application_auditor": frozenset({"hosts_read", "catalogs_read", "settings_read", "audit_read"}),
    "provisioning_admin": frozenset({"hosts_read", "hosts_write", "catalogs_read", "catalogs_write", "settings_read", "operations_read", "preview", "generate", "apply", "execute"}),
    "provisioning_user": frozenset({"hosts_read", "hosts_write", "catalogs_read", "settings_read", "operations_read", "preview"}),
    "provisioning_viewer": frozenset({"hosts_read", "catalogs_read", "preview"}),
}

ACTION_CAPABILITIES = {
    "hosts": "hosts_read",
    "host_view": "hosts_read",
    "installers": "catalogs_read",
    "installer_view": "catalogs_read",
    "roles": "catalogs_read",
    "role_view": "catalogs_read",
    "templates": "catalogs_read",
    "template_view": "catalogs_read",
    "operations": "operations_read",
    "preview": "preview",
    "validate": "preview",
    "generate_submit": "generate",
    "apply": "apply",
    "apply_submit": "apply",
    "execute": "execute",
    "execute_submit": "execute",
    "settings": "settings_read",
    "settings_update": "settings_write",
    "audit": "audit_read",
    "markdown_help": "hosts_read",
}

CATALOG_ACTIONS = {
    "hosts": ("Hosts", "hosts_file", "hostname", ("hostname", "ipv4_address", "mac_addresses", "provisioning_state", "enabled", "updated_at")),
    "installers": ("Installers", "installers_file", "name", ("name", "os_family", "os_version", "architecture", "source_type", "enabled")),
    "roles": ("Ansible Roles", "roles_file", "name", ("name", "role_path", "enabled", "updated_at")),
    "templates": ("Templates", "templates_file", "name", ("name", "template_type", "installer_id", "role_ids", "enabled", "updated_at")),
}

DETAIL_ACTIONS = {
    "host_view": ("hosts", "Host"),
    "installer_view": ("installers", "Installer"),
    "role_view": ("roles", "Ansible Role"),
    "template_view": ("templates", "Template"),
}

SEARCH_FIELDS = {
    "hosts": ("hostname", "description", "ipv4_address", "ipv6_address", "mac_addresses", "tags"),
    "installers": ("name", "description", "os_family", "os_version", "architecture", "source_type"),
    "roles": ("name", "description", "role_path"),
    "templates": ("name", "description", "template_type"),
}


@dataclass(frozen=True)
class Config:
    site_config_file: str = "/etc/provmanager.conf"
    hosts_file: str = "/data/provisioning/hosts.yaml"
    installers_file: str = "/data/provisioning/installers.yaml"
    roles_file: str = "/data/provisioning/roles.yaml"
    templates_file: str = "/data/provisioning/templates.yaml"
    audit_log_file: str = "/var/log/provmanager/audit.log"
    installer_roots: Tuple[str, ...] = ()
    tftp_root: str = "/var/lib/tftpboot/efi/"
    dhcp_config_file: str = "/etc/dhcp/dhcpd.conf"
    kickstart_root: str = "/data/provisioning/kickstart/"
    ansible_root: str = "/data/provisioning/ansible/"
    inventory_output_file: str = "/data/provisioning/ansible/inventory/hosts.yml"
    generated_output_dir: str = "/data/provisioning/generated/"
    lock_dir: str = "/data/provisioning/locks/"
    backup_dir: str = "/data/provisioning/backups/"
    per_user_config_dir: str = "/data/provisioning/user-config/"
    pm_admins_group: str = "pm_admins"
    pm_auditors_group: str = "pm_auditors"
    pm_prvadmins_group: str = "pm_prvadmins"
    pm_prvusers_group: str = "pm_prvusers"
    pm_viewers_group: str = "pm_viewers"
    banner_file: str = ""
    banner_dimensions: str = ""
    favicon_mime_type: str = "image/x-icon"
    auth_form_action: str = "/provmanager-login"
    auth_form_username_field: str = "httpd_username"
    auth_form_password_field: str = "httpd_password"
    auth_form_location_field: str = "httpd_location"
    auth_form_default_location: str = "/cgi-bin/provmanager.cgi"
    logout_url: str = "/provmanager-logout"
    list_page_size: int = 50
    search_history_limit: int = 10
    max_description_chars: int = 65536
    max_template_bytes: int = 1048576
    enable_provisioning_execution: bool = False
    enable_service_reload: bool = False


@dataclass(frozen=True)
class Identity:
    username: str
    full_name: str
    roles: FrozenSet[str]
    capabilities: FrozenSet[str]


class CatalogError(Exception):
    """A safe, browser-displayable catalog loading failure."""


@dataclass(frozen=True)
class Finding:
    severity: str
    resource: str
    message: str
    location: str = ""


def _yaml_fields(node):
    if isinstance(node, yaml.MappingNode):
        return {key.value: value for key, value in node.value if isinstance(key, yaml.ScalarNode)}
    return {}


def _source_position(mark):
    return f"line {mark.line + 1}, column {mark.column + 1}"


def load_catalog(path: str, locations: Optional[dict] = None) -> List[Dict[str, Any]]:
    """Read a version-1 catalog using PyYAML's non-constructing safe loader."""
    if yaml is None:
        raise CatalogError("YAML support is unavailable; install the documented PyYAML dependency.")
    try:
        with open(path, "r", encoding="utf-8") as stream:
            loader = yaml.SafeLoader(stream)
            try:
                node = loader.get_single_node()
                document = loader.construct_document(node) if node is not None else None
            finally:
                loader.dispose()
    except FileNotFoundError:
        raise CatalogError("The catalog file is not available.")
    except OSError:
        raise CatalogError("The catalog file could not be read.")
    except yaml.YAMLError as error:
        message = "The catalog contains invalid YAML and was not loaded."
        # Parser messages can quote catalog data. Show only the location.
        mark = getattr(error, "problem_mark", None)
        if mark is not None:
            message += f" The parser stopped at line {mark.line + 1}, column {mark.column + 1}."
        raise CatalogError(message) from None
    def schema_error(message, source):
        return CatalogError(f"{message} ({_source_position(source.start_mark)})" if source is not None else message)

    if not isinstance(document, dict):
        raise schema_error("The catalog must be a versioned mapping.", node)
    fields_by_name = _yaml_fields(node)
    if document.get("schema_version") != 1:
        raise schema_error("The catalog schema version is missing or unsupported.", fields_by_name.get("schema_version", node))
    records = document.get("records")
    records_node = fields_by_name.get("records")
    if not isinstance(records, list) or any(not isinstance(record, dict) for record in records):
        source = records_node or node
        if isinstance(records_node, yaml.SequenceNode) and isinstance(records, list):
            source = next(child for record, child in zip(records, records_node.value) if not isinstance(record, dict))
        raise schema_error("The catalog records value must be a list of mappings.", source)
    identifiers = [record.get("id") for record in records]
    seen_ids = set()
    for index, identifier in enumerate(identifiers):
        record_node = records_node.value[index] if isinstance(records_node, yaml.SequenceNode) else None
        source = _yaml_fields(record_node).get("id", record_node)
        if not isinstance(identifier, str) or not identifier:
            raise schema_error("Every catalog record must have a nonempty string ID.", source)
        if identifier in seen_ids:
            raise schema_error("The catalog contains duplicate record IDs.", source)
        seen_ids.add(identifier)
    if locations is not None and isinstance(records_node, yaml.SequenceNode):
        for identifier, record_node in zip(identifiers, records_node.value):
            locations[identifier] = {key: value.start_mark for key, value in _yaml_fields(record_node).items()}
            locations[identifier][None] = record_node.start_mark
    return records


def _inside(path: str, root: str) -> bool:
    if not path or not root or not os.path.isabs(path) or not os.path.isabs(root):
        return False
    try:
        return os.path.commonpath((os.path.realpath(path), os.path.realpath(root))) == os.path.realpath(root)
    except ValueError:
        return False


def _valid_hostname(value: Any) -> bool:
    if not isinstance(value, str) or len(value) > 253:
        return False
    labels = value.rstrip(".").split(".")
    return bool(labels) and all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label) for label in labels)


def _normalize_mac(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    compact = re.sub(r"[:-]", "", value).lower()
    if not re.fullmatch(r"[0-9a-f]{12}", compact):
        return None
    return ":".join(compact[index:index + 2] for index in range(0, 12, 2))


def _installer_path_findings(resource: str, path: Any, config: Config, expected: str) -> List[Finding]:
    if not isinstance(path, str) or not os.path.isabs(path):
        return [Finding("error", resource, "Installer {} path must be absolute.".format(expected))]
    if ".." in path.split(os.sep) or any(ord(character) < 32 or ord(character) == 127 for character in path):
        return [Finding("error", resource, "Installer {} path contains traversal or control characters.".format(expected))]
    if expected == "tree" and not os.path.isdir(path):
        return [Finding("error", resource, "Installer tree path is not a readable directory.")]
    if expected == "ISO" and (not os.path.isfile(path) or not path.casefold().endswith(".iso")):
        return [Finding("error", resource, "Installer ISO path must be a readable .iso file.")]
    access_mode = os.R_OK | os.X_OK if expected == "tree" else os.R_OK
    if not os.access(path, access_mode):
        return [Finding("error", resource, "Installer {} path is not readable.".format(expected))]
    if not config.installer_roots:
        return [Finding("warning", resource, "Installer path is readable, but no installer-root allowlist is specified yet.")]
    if not any(_inside(path, root) for root in config.installer_roots):
        return [Finding("error", resource, "Installer source path is outside the approved installer roots.")]
    return []


def _network_source_findings(resource: str, value: Any) -> List[Finding]:
    if not isinstance(value, str) or not value or any(character.isspace() or ord(character) == 127 for character in value):
        return [Finding("error", resource, "Network installer source must be a valid HTTP or HTTPS URL.")]
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return [Finding("error", resource, "Network installer source must be a valid HTTP or HTTPS URL.")]
    valid_hostname = False
    if hostname:
        try:
            ipaddress.ip_address(hostname)
            valid_hostname = True
        except ValueError:
            valid_hostname = _valid_hostname(hostname)
    if (
        parsed.scheme.casefold() not in {"http", "https"}
        or not valid_hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or port is not None and not 1 <= port <= 65535
    ):
        return [Finding("error", resource, "Network installer source must be a credential-free HTTP or HTTPS URL without a fragment.")]
    return []


def _installer_source_findings(installer: Dict[str, Any], config: Config) -> List[Finding]:
    resource = str(installer.get("name") or installer["id"])
    source_type = installer.get("source_type")
    if source_type == "tree":
        return _installer_path_findings(resource, installer.get("source_path"), config, "tree")
    if source_type == "iso":
        return _installer_path_findings(resource, installer.get("iso_path"), config, "ISO")
    if source_type == "network":
        return _network_source_findings(resource, installer.get("source_path"))
    return [Finding("error", resource, "Installer source type must be iso, tree, or network.")]


def _installer_boot_file_findings(resource: str, field: str, value: Any, config: Config) -> List[Finding]:
    label = {"kernel_path": "kernel", "initrd_path": "initrd", "efi_path": "EFI executable"}[field]
    if (
        not isinstance(value, str)
        or not value
        or os.path.isabs(value)
        or ".." in value.split(os.sep)
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        return [Finding("error", resource, "Installer {} path must be relative to the TFTP root.".format(label))]
    path = os.path.join(config.tftp_root, value)
    if not _inside(path, config.tftp_root):
        return [Finding("error", resource, "Installer {} path is outside the TFTP root.".format(label))]
    if not os.path.isfile(path) or not os.access(path, os.R_OK):
        return [Finding("error", resource, "Installer {} is not a readable file beneath the TFTP root.".format(label))]
    return []


def _installer_readiness_findings(installer: Dict[str, Any], config: Config) -> List[Finding]:
    resource = str(installer.get("name") or installer["id"])
    findings = _installer_source_findings(installer, config)
    if installer.get("architecture") != "x86_64":
        findings.append(Finding("error", resource, "Installer architecture must be x86_64."))
    if installer.get("boot_modes") != ["uefi"]:
        findings.append(Finding("error", resource, "Installer boot modes must be an ordered list containing only uefi."))
    for field in ("kernel_path", "initrd_path", "efi_path"):
        findings.extend(_installer_boot_file_findings(resource, field, installer.get(field), config))
    return findings


def _is_utc_timestamp(value: Any) -> bool:
    try:
        if isinstance(value, str):
            value = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
        return isinstance(value, datetime) and value.utcoffset() == timedelta(0)
    except (ValueError, OverflowError):
        return False


def validate_catalogs(config: Config) -> List[Finding]:
    """Inspect canonical catalogs and referenced paths without modifying them."""
    catalogs = {}
    locations = {}

    def report(action, record, finding, field=None):
        marks = locations[action].get(record["id"], {})
        mark = marks.get(field) or marks.get(None)
        if mark is not None:
            finding = replace(finding, location=f"{CATALOG_ACTIONS[action][0]}, line {mark.line + 1}, column {mark.column + 1}")
        findings.append(finding)

    findings = []
    for action, (title, path_field, _sort, _columns) in CATALOG_ACTIONS.items():
        locations[action] = {}
        try:
            catalogs[action] = load_catalog(getattr(config, path_field), locations[action])
        except CatalogError as error:
            catalogs[action] = []
            findings.append(Finding("error", title, str(error)))

    for action, records in catalogs.items():
        seen = {}
        name_field = "hostname" if action == "hosts" else "name"
        for record in records:
            value = record.get(name_field)
            canonical = value.strip().casefold() if isinstance(value, str) else ""
            if not canonical:
                report(action, record, Finding("error", str(record.get("id")), "A required {} is missing.".format(name_field)), name_field)
            elif canonical in seen:
                report(action, record, Finding("error", str(record.get("id")), "The {} duplicates another record.".format(name_field)), name_field)
            else:
                seen[canonical] = record.get("id")
            resource = value if isinstance(value, str) and value else record["id"]
            description = record.get("description")
            if "description" in record and not isinstance(description, str):
                report(action, record, Finding("error", resource, "Description must be text."), "description")
            elif isinstance(description, str) and len(description) > config.max_description_chars:
                report(action, record, Finding("error", resource, "Description exceeds the configured character limit."), "description")
            if not isinstance(record.get("enabled", True), bool):
                report(action, record, Finding("error", resource, "Enabled must be true or false."), "enabled")
            for field in ("created_at", "updated_at"):
                if field in record and not _is_utc_timestamp(record[field]):
                    report(action, record, Finding("error", resource, f"{field} must be an ISO 8601 UTC timestamp."), field)
            for field in ("created_by", "updated_by"):
                if field in record and (not isinstance(record[field], str) or not record[field].strip()):
                    report(action, record, Finding("error", resource, f"{field} must be nonempty text."), field)

    installers = {record["id"]: record for record in catalogs["installers"]}
    roles = {record["id"]: record for record in catalogs["roles"]}
    templates = {record["id"]: record for record in catalogs["templates"]}
    used_macs = {}
    used_ips = {}
    for host in catalogs["hosts"]:
        resource = str(host.get("hostname") or host["id"])
        if not _valid_hostname(host.get("hostname")):
            report("hosts", host, Finding("error", resource, "Hostname is not a valid DNS name."), "hostname")
        macs = host.get("mac_addresses", [])
        if not isinstance(macs, list) or not macs:
            report("hosts", host, Finding("error", resource, "At least one MAC address is required."), "mac_addresses")
        else:
            for mac in macs:
                normalized = _normalize_mac(mac)
                if normalized is None:
                    report("hosts", host, Finding("error", resource, "A MAC address is invalid."), "mac_addresses")
                elif host.get("enabled", True) and normalized in used_macs:
                    report("hosts", host, Finding("error", resource, "A MAC address is already used by another enabled host."), "mac_addresses")
                elif host.get("enabled", True):
                    used_macs[normalized] = host["id"]
        for field in ("ipv4_address", "ipv6_address"):
            value = host.get(field)
            if not value:
                continue
            try:
                parsed = str(ipaddress.ip_address(value))
            except ValueError:
                report("hosts", host, Finding("error", resource, "{} is invalid.".format(field.replace("_", " ").upper())), field)
                continue
            if host.get("enabled", True) and parsed in used_ips:
                report("hosts", host, Finding("error", resource, "An IP address is already used by another enabled host."), None)
            elif host.get("enabled", True):
                used_ips[parsed] = host["id"]
        for field, index, label in (("installer_id", installers, "installer"), ("template_id", templates, "template")):
            reference = host.get(field)
            if reference and reference not in index:
                report("hosts", host, Finding("error", resource, "Referenced {} does not exist.".format(label)), field)
        role_ids = host.get("role_ids", [])
        if not isinstance(role_ids, list) or any(not isinstance(role_id, str) for role_id in role_ids) or len(role_ids) != len(set(role_ids)):
            report("hosts", host, Finding("error", resource, "Role references must be an ordered list without duplicates."), "role_ids")
        elif any(role_id not in roles for role_id in role_ids):
            report("hosts", host, Finding("error", resource, "A referenced role does not exist."), "role_ids")

    for role in catalogs["roles"]:
        path = role.get("role_path")
        resource = str(role.get("name") or role["id"])
        if not isinstance(path, str) or not _inside(path, config.ansible_root):
            report("roles", role, Finding("error", resource, "Role path is outside the approved Ansible root."), "role_path")
        elif not os.path.isdir(path) or not os.access(path, os.R_OK):
            report("roles", role, Finding("error", resource, "Role path is not a readable directory."), "role_path")

    template_roots = {"kickstart": config.kickstart_root, "ansible": config.ansible_root, "boot": config.tftp_root}
    for template in catalogs["templates"]:
        resource = str(template.get("name") or template["id"])
        template_type = template.get("template_type")
        path = template.get("content_path")
        root = template_roots.get(template_type)
        if root is None:
            report("templates", template, Finding("error", resource, "Template type is unsupported."), "template_type")
        elif not isinstance(path, str) or not _inside(path, root):
            report("templates", template, Finding("error", resource, "Template content path is outside its approved root."), "content_path")
        elif not os.path.isfile(path) or not os.access(path, os.R_OK):
            report("templates", template, Finding("error", resource, "Template content is not a readable file."), "content_path")

        installer_id = template.get("installer_id")
        if installer_id and installer_id not in installers:
            report("templates", template, Finding("error", resource, "Referenced installer does not exist."), "installer_id")
        role_ids = template.get("role_ids", [])
        if not isinstance(role_ids, list) or any(not isinstance(role_id, str) for role_id in role_ids) or len(role_ids) != len(set(role_ids)):
            report("templates", template, Finding("error", resource, "Role references must be an ordered list without duplicates."), "role_ids")
        # REGRESSION GUARD: Duplicate references must not hide a separate
        # missing-role finding in the same stored list.
        if isinstance(role_ids, list) and any(isinstance(role_id, str) and role_id not in roles for role_id in role_ids):
            report("templates", template, Finding("error", resource, "A referenced role does not exist."), "role_ids")

    for installer in catalogs["installers"]:
        for finding in _installer_readiness_findings(installer, config):
            report("installers", installer, finding)
    if not findings:
        findings.append(Finding("information", "Catalogs", "No validation findings were reported."))
    return findings


def resolve_identity(username: str, config: Config) -> Optional[Identity]:
    """Resolve the current account through NSS on every protected request."""
    try:
        account = pwd.getpwnam(username)
        group_ids = os.getgrouplist(username, account.pw_gid)
        group_names = frozenset(grp.getgrgid(group_id).gr_name for group_id in group_ids)
    except (KeyError, OSError):
        return None
    role_groups = {
        "application_admin": config.pm_admins_group,
        "application_auditor": config.pm_auditors_group,
        "provisioning_admin": config.pm_prvadmins_group,
        "provisioning_user": config.pm_prvusers_group,
        "provisioning_viewer": config.pm_viewers_group,
    }
    roles = frozenset(role for role, group in role_groups.items() if group in group_names)
    if not roles:
        return None
    capabilities = frozenset(
        capability for role in roles for capability in ROLE_CAPABILITIES[role]
    )
    gecos_name = account.pw_gecos.split(",", 1)[0].strip()
    full_name = gecos_name if gecos_name and gecos_name != username else username
    return Identity(username, full_name, roles, capabilities)


_CONFIG_KEYS = {field.name.upper(): field.name for field in fields(Config)}
_PATH_FIELDS = frozenset(
    name for name in _CONFIG_KEYS.values() if name.endswith(("_file", "_dir", "_root"))
)
_BOOL_FIELDS = frozenset({"enable_provisioning_execution", "enable_service_reload"})
_PATH_LIST_FIELDS = frozenset({"installer_roots"})
_INT_FIELDS = frozenset(
    {"list_page_size", "search_history_limit", "max_description_chars", "max_template_bytes"}
)
_TRUE = frozenset({"true", "yes", "1", "on"})
_FALSE = frozenset({"false", "no", "0", "off"})


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value.split(" #", 1)[0].strip()


def load_config(path: Optional[str] = None, defaults: Optional[Config] = None) -> Tuple[Config, Tuple[str, ...]]:
    """Load supported KEY=value settings without evaluating file content."""
    config = defaults or Config()
    config_path = path if path is not None else config.site_config_file
    diagnostics = []
    try:
        with open(config_path, "r", encoding="utf-8") as stream:
            lines = stream.readlines()
    except FileNotFoundError:
        return config, tuple()
    except OSError:
        return config, ("Site configuration could not be read; safe defaults are active.",)

    updates = {}
    for number, raw_line in enumerate(lines, 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            diagnostics.append("Ignored malformed configuration line {}.".format(number))
            continue
        key, raw_value = line.split("=", 1)
        field_name = _CONFIG_KEYS.get(key.strip())
        if field_name is None:
            continue
        value = _unquote(raw_value)
        try:
            if field_name in _BOOL_FIELDS:
                normalized = value.lower()
                if normalized not in _TRUE | _FALSE:
                    raise ValueError
                parsed = normalized in _TRUE
            elif field_name in _PATH_LIST_FIELDS:
                entries = tuple(item.strip() for item in value.split(",") if item.strip())
                if any(not os.path.isabs(item) for item in entries):
                    raise ValueError
                parsed = entries
            elif field_name in _INT_FIELDS:
                parsed = int(value)
                if parsed <= 0:
                    raise ValueError
            elif field_name == "banner_dimensions":
                if value and not re.fullmatch(r"[1-9][0-9]*x[1-9][0-9]*", value):
                    raise ValueError
                parsed = value
            elif field_name in _PATH_FIELDS and value and not os.path.isabs(value):
                raise ValueError
            else:
                parsed = value
        except ValueError:
            diagnostics.append("Ignored invalid value for {}.".format(key.strip()))
            continue
        updates[field_name] = parsed
    return replace(config, **updates), tuple(diagnostics)


@dataclass(frozen=True)
class Response:
    status: str
    headers: Tuple[Tuple[str, str], ...]
    body: bytes

    def to_cgi(self) -> bytes:
        lines = ["Status: {}".format(self.status)]
        lines.extend("{}: {}".format(name, value) for name, value in self.headers)
        return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + self.body


def _navigation(identity: Identity) -> str:
    links = []
    for capability, label, action in (
        ("hosts_read", "Hosts", "hosts"),
        ("catalogs_read", "Installers", "installers"),
        ("catalogs_read", "Ansible Roles", "roles"),
        ("catalogs_read", "Templates", "templates"),
        ("preview", "Validate", "validate"),
        ("operations_read", "Operations", "operations"),
        ("settings_read", "Settings", "settings"),
        ("audit_read", "Audit Log", "audit"),
    ):
        if capability in identity.capabilities:
            links.append('<a href="?action={}">{}</a>'.format(action, label))
    return "<nav>{}</nav>".format(" | ".join(links))


def _html_page(title: str, content: str, public: bool = True, identity: Optional[Identity] = None, config: Optional[Config] = None, top_controls: str = "") -> bytes:
    footer = "" if public else '<footer>ProvManager {}</footer>'.format(html.escape(PROVMANAGER_VERSION))
    welcome = ""
    navigation = ""
    if identity is not None:
        logout_url = config.logout_url if config is not None else Config().logout_url
        welcome = '<p class="welcome">Welcome, <strong>{}</strong> (<a href="{}">Logout</a>)</p>'.format(
            html.escape(identity.full_name), html.escape(logout_url, quote=True)
        )
        navigation = _navigation(identity)
    document = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{0} · ProvManager</title><link rel="icon" href="?action=favicon">
<style>body{{font-family:system-ui,sans-serif;margin:2rem;line-height:1.45}}header{{height:35px;background:linear-gradient(90deg,#E6E9EF,transparent);color:#7b8290;padding:.5rem 1rem}}main{{max-width:70rem;margin:1.5rem auto}}.utility-row{{display:flex;justify-content:space-between;align-items:center;gap:1rem;flex-wrap:wrap}}.welcome{{margin:.5rem 0}}.catalog-search{{display:flex;justify-content:flex-end;align-items:center;font-size:.9rem}}.visually-hidden{{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}}.status-filter label,.validation-filter label{{display:inline;margin:0}}.status-filter,.validation-filter{{display:flex;justify-content:flex-start;align-items:center;gap:.4rem;font-size:.9rem;margin-bottom:.6rem}}nav{{display:flex;gap:.8rem;flex-wrap:wrap}}table{{border-collapse:collapse;width:100%;font-size:.9rem}}th,td{{padding:.4rem;text-align:left;border-bottom:1px solid #ddd;vertical-align:top}}.list-summary{{display:flex;justify-content:space-between;align-items:center;gap:1rem;font-size:.82rem}}.pagination{{font-size:.82rem;text-align:right;margin:.5rem 0}}.pagination select{{font-size:inherit;padding:.1rem .25rem}}.finding-summary{{display:flex;gap:.75rem;flex-wrap:wrap;margin:.75rem 0}}.severity{{display:inline-block;padding:.1rem .4rem;border-radius:.25rem;font-size:.78rem;font-weight:600}}.severity-error{{background:#f8d7da;color:#842029}}.severity-warning{{background:#fff3cd;color:#664d03}}.severity-information{{background:#cff4fc;color:#055160}}label{{display:block;margin-top:.8rem}}input{{padding:.4rem}}footer{{text-align:center;color:#667;margin-top:3rem}}</style></head>
<body><header>ProvManager</header><main><div class="utility-row">{3}{5}</div>{4}<h1>{0}</h1>{1}</main>{2}</body></html>""".format(
        html.escape(title), content, footer, welcome, navigation, top_controls
    )
    return document.encode("utf-8")


def _html_response(title: str, content: str, status: str = "200 OK", public: bool = True, identity: Optional[Identity] = None, config: Optional[Config] = None, top_controls: str = "") -> Response:
    return Response(
        status,
        (("Content-Type", "text/html; charset=utf-8"), ("Cache-Control", "no-store")),
        _html_page(title, content, public, identity, config, top_controls),
    )


def _sensitive_key(key: str) -> bool:
    normalized = key.casefold().replace("-", "_")
    return any(fragment in normalized for fragment in ("password", "secret", "token", "credential", "private_key"))


def _display_value(value: Any, key: str = "") -> str:
    if _sensitive_key(key):
        return "[redacted]"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, list):
        return ", ".join(_display_value(item, key) for item in value)
    if isinstance(value, dict):
        return ", ".join("{}={}".format(item_key, _display_value(item_value, str(item_key))) for item_key, item_value in sorted(value.items()))
    if value is None or value == "":
        return "—"
    return str(value)


def _query_value(params: Mapping[str, List[str]], name: str) -> str:
    return params.get(name, [""])[0].strip()


def _search_text(record: Dict[str, Any], fields_to_search: Tuple[str, ...]) -> str:
    return " ".join(_display_value(record.get(field), field) for field in fields_to_search).casefold()


def _page_number(raw_value: str, page_count: int) -> int:
    try:
        requested = int(raw_value)
    except (TypeError, ValueError):
        requested = 1
    return min(max(requested, 1), max(page_count, 1))


def _catalog_search_controls(action: str, params: Mapping[str, List[str]]) -> str:
    query = _query_value(params, "q")
    enabled_filter = _query_value(params, "enabled").casefold()
    enabled_input = '<input type="hidden" name="enabled" value="{}">'.format(html.escape(enabled_filter, quote=True)) if enabled_filter else ""
    return """<form class="catalog-search" method="get"><input type="hidden" name="action" value="{action}">{enabled_input}
<label class="visually-hidden" for="catalog-search">Search</label><input id="catalog-search" name="q" value="{query}" placeholder="Search" type="search"></form>""".format(
        action=action, enabled_input=enabled_input, query=html.escape(query, quote=True)
    )


def _catalog_status_controls(action: str, params: Mapping[str, List[str]]) -> str:
    query = _query_value(params, "q")
    enabled_filter = _query_value(params, "enabled").casefold()
    query_input = '<input type="hidden" name="q" value="{}">'.format(html.escape(query, quote=True)) if query else ""
    return """<form class="status-filter" method="get"><input type="hidden" name="action" value="{action}">{query_input}
<label for="enabled-filter">Status</label><select id="enabled-filter" name="enabled">
<option value="">All</option><option value="true"{true_selected}>Enabled</option><option value="false"{false_selected}>Disabled</option>
</select><button type="submit">Filter</button><a href="?action={action}">Reset</a></form>""".format(
        action=action,
        query_input=query_input,
        true_selected=" selected" if enabled_filter == "true" else "",
        false_selected=" selected" if enabled_filter == "false" else "",
    )


def _catalog_table(action: str, records: List[Dict[str, Any]], params: Mapping[str, List[str]], config: Config) -> str:
    title, _path_field, sort_field, columns = CATALOG_ACTIONS[action]
    query = _query_value(params, "q")
    enabled_filter = _query_value(params, "enabled").casefold()
    selected_sort = _query_value(params, "sort")
    if selected_sort not in columns:
        selected_sort = sort_field
    direction = "desc" if _query_value(params, "direction").casefold() == "desc" else "asc"
    filtered = records
    if query:
        needle = query.casefold()
        filtered = [record for record in filtered if needle in _search_text(record, SEARCH_FIELDS[action])]
    if enabled_filter in {"true", "false"}:
        desired = enabled_filter == "true"
        filtered = [record for record in filtered if record.get("enabled") is desired]
    sorted_records = sorted(
        filtered,
        key=lambda record: (str(record.get(selected_sort, "")).casefold(), str(record.get("id", ""))),
        reverse=direction == "desc",
    )
    page_count = max(1, (len(sorted_records) + config.list_page_size - 1) // config.list_page_size)
    page = _page_number(_query_value(params, "page"), page_count)
    start = (page - 1) * config.list_page_size
    page_records = sorted_records[start:start + config.list_page_size]
    heading_cells = []
    for column in columns:
        next_direction = "desc" if selected_sort == column and direction == "asc" else "asc"
        heading_query = {"action": action, "sort": column, "direction": next_direction}
        if query:
            heading_query["q"] = query
        if enabled_filter:
            heading_query["enabled"] = enabled_filter
        heading_cells.append('<th scope="col"><a href="?{}">{}</a></th>'.format(
            html.escape(urlencode(heading_query), quote=True), html.escape(column.replace("_", " ").title())
        ))
    headings = "".join(heading_cells)
    if not page_records:
        rows = '<tr><td colspan="{}">No {} are configured.</td></tr>'.format(len(columns), html.escape(title.lower()))
    else:
        detail_action = {"hosts": "host_view", "installers": "installer_view", "roles": "role_view", "templates": "template_view"}[action]
        rendered_rows = []
        for record in page_records:
            cells = []
            for index, column in enumerate(columns):
                value = html.escape(_display_value(record.get(column), column))
                if index == 0:
                    value = '<a href="?action={}&amp;id={}">{}</a>'.format(
                        detail_action, html.escape(str(record["id"]), quote=True), value
                    )
                cells.append("<td>{}</td>".format(value))
            rendered_rows.append("<tr>{}</tr>".format("".join(cells)))
        rows = "".join(rendered_rows)
    pagination = []
    for target, label in ((page - 1, "Previous"), (page + 1, "Next")):
        if 1 <= target <= page_count:
            page_query = {"action": action, "page": str(target), "sort": selected_sort, "direction": direction}
            if query:
                page_query["q"] = query
            if enabled_filter:
                page_query["enabled"] = enabled_filter
            pagination.append('<a href="?{}">{}</a>'.format(html.escape(urlencode(page_query), quote=True), label))
    preserved = {"action": action, "sort": selected_sort, "direction": direction}
    if query:
        preserved["q"] = query
    if enabled_filter:
        preserved["enabled"] = enabled_filter
    hidden_inputs = "".join(
        '<input type="hidden" name="{}" value="{}">'.format(html.escape(name, quote=True), html.escape(value, quote=True))
        for name, value in preserved.items()
    )
    page_options = "".join(
        '<option value="{}"{}>{}</option>'.format(number, " selected" if number == page else "", number)
        for number in range(1, page_count + 1)
    )
    page_controls = '<form class="pagination" method="get">{}<label class="visually-hidden">Page</label><select name="page" aria-label="Page" onchange="this.form.submit()">{}</select> of {}{}<noscript> <button type="submit">Go</button></noscript></form>'.format(
        hidden_inputs, page_options, page_count, " · " + " · ".join(pagination) if pagination else ""
    )
    summary = '<div class="list-summary"><span>{} matching record(s)</span>{}</div>'.format(len(sorted_records), page_controls)
    return '{}{}<table><thead><tr>{}</tr></thead><tbody>{}</tbody></table>{}'.format(
        _catalog_status_controls(action, params), summary, headings, rows, page_controls
    )


def _record_link(action: str, record: Dict[str, Any]) -> str:
    label = record.get("hostname") or record.get("name") or record["id"]
    detail_action = {"hosts": "host_view", "installers": "installer_view", "roles": "role_view", "templates": "template_view"}[action]
    return '<a href="?action={}&amp;id={}">{}</a>'.format(
        detail_action, html.escape(str(record["id"]), quote=True), html.escape(str(label))
    )


def _reference_value(key: str, value: Any, catalogs: Mapping[str, List[Dict[str, Any]]]) -> Optional[str]:
    reference_types = {"installer_id": "installers", "template_id": "templates"}
    if key in reference_types and isinstance(value, str):
        action = reference_types[key]
        target = next((record for record in catalogs[action] if record["id"] == value), None)
        return _record_link(action, target) if target is not None else '{} <strong>(missing)</strong>'.format(html.escape(value))
    if key == "role_ids" and isinstance(value, list):
        roles = {record["id"]: record for record in catalogs["roles"]}
        links = []
        for role_id in value:
            target = roles.get(role_id)
            links.append(_record_link("roles", target) if target is not None else '{} <strong>(missing)</strong>'.format(html.escape(str(role_id))))
        return ", ".join(links) if links else "—"
    return None


def _dependency_section(catalog_action: str, record: Dict[str, Any], catalogs: Mapping[str, List[Dict[str, Any]]]) -> str:
    record_id = record["id"]
    dependencies = []
    if catalog_action == "installers":
        dependencies.extend(("hosts", item) for item in catalogs["hosts"] if item.get("installer_id") == record_id)
        dependencies.extend(("templates", item) for item in catalogs["templates"] if item.get("installer_id") == record_id)
    elif catalog_action == "roles":
        dependencies.extend(("hosts", item) for item in catalogs["hosts"] if record_id in item.get("role_ids", []))
        dependencies.extend(("templates", item) for item in catalogs["templates"] if record_id in item.get("role_ids", []))
    elif catalog_action == "templates":
        dependencies.extend(("hosts", item) for item in catalogs["hosts"] if item.get("template_id") == record_id)
    if catalog_action == "hosts":
        return ""
    if not dependencies:
        return "<h2>Referenced by</h2><p>No records reference this item.</p>"
    items = "".join("<li>{}: {}</li>".format(html.escape(action.rstrip("s").title()), _record_link(action, item)) for action, item in dependencies)
    return "<h2>Referenced by</h2><ul>{}</ul>".format(items)


def _record_detail(catalog_action: str, record: Dict[str, Any], catalogs: Mapping[str, List[Dict[str, Any]]]) -> str:
    rows = []
    for key in sorted(record):
        reference = _reference_value(key, record[key], catalogs)
        if reference is not None:
            rendered_value = reference
        else:
            rendered_value = render_markdown(str(record[key])) if key == "description" else html.escape(_display_value(record[key], key))
        rows.append(
            "<tr><th scope=\"row\">{}</th><td>{}</td></tr>".format(
                html.escape(key.replace("_", " ").title()), rendered_value
            )
        )
    return "<table><tbody>{}</tbody></table>{}".format("".join(rows), _dependency_section(catalog_action, record, catalogs))


def render_markdown(source: str) -> str:
    """Render the documented Markdown subset and sanitize the resulting HTML."""
    if markdown is None or bleach is None:
        return "<pre>{}</pre>".format(html.escape(source))
    with_strikethrough = re.sub(r"~~([^\n~]+)~~", r"<del>\1</del>", source)
    rendered = markdown.markdown(with_strikethrough, extensions=["fenced_code"])
    return bleach.clean(
        rendered,
        tags={"p", "br", "h1", "h2", "h3", "h4", "h5", "h6", "ul", "ol", "li", "strong", "em", "del", "code", "pre", "a", "blockquote"},
        attributes={"a": ["href", "title"]},
        protocols={"http", "https", "mailto"},
        strip=True,
    )


def _markdown_help() -> str:
    examples = """# Heading

Use **bold**, *emphasis*, and ~~strikethrough~~.

- Bulleted item
- Another item

1. Numbered item
2. Another item

`inline code` and [safe links](https://example.invalid) are supported.

```text
fenced code block
```"""
    return '<p>Descriptions support the following safely rendered syntax.</p>{}<h2>Source</h2><pre>{}</pre>'.format(
        render_markdown(examples), html.escape(examples)
    )


def _validation_catalogs(config: Config) -> Dict[str, List[Dict[str, Any]]]:
    catalogs = {}
    for action, definition in CATALOG_ACTIONS.items():
        try:
            catalogs[action] = load_catalog(getattr(config, definition[1]))
        except CatalogError:
            catalogs[action] = []
    return catalogs


def _finding_resource(resource: str, catalogs: Mapping[str, List[Dict[str, Any]]]) -> str:
    for action in ("hosts", "installers", "roles", "templates"):
        for record in catalogs[action]:
            labels = {str(record["id"]), str(record.get("hostname", "")), str(record.get("name", ""))}
            if resource in labels:
                return _record_link(action, record)
    return html.escape(resource)


def _findings_table(findings: List[Finding], params: Mapping[str, List[str]], catalogs: Mapping[str, List[Dict[str, Any]]]) -> str:
    selected_severity = _query_value(params, "severity").casefold()
    resource_query = _query_value(params, "resource")
    filtered = findings
    if selected_severity in {"error", "warning", "information"}:
        filtered = [finding for finding in filtered if finding.severity == selected_severity]
    if resource_query:
        needle = resource_query.casefold()
        filtered = [finding for finding in filtered if needle in finding.resource.casefold() or needle in finding.message.casefold()]
    counts = {severity: sum(1 for finding in findings if finding.severity == severity) for severity in ("error", "warning", "information")}
    summary = '<div class="finding-summary"><span class="severity severity-error">{} Errors</span><span class="severity severity-warning">{} Warnings</span><span class="severity severity-information">{} Information</span></div>'.format(
        counts["error"], counts["warning"], counts["information"]
    )
    options = "".join(
        '<option value="{}"{}>{}</option>'.format(value, " selected" if selected_severity == value else "", label)
        for value, label in (("", "All severities"), ("error", "Errors"), ("warning", "Warnings"), ("information", "Information"))
    )
    controls = '<form class="validation-filter" method="get"><input type="hidden" name="action" value="validate"><label for="severity-filter">Severity</label><select id="severity-filter" name="severity">{}</select><label for="resource-filter">Resource</label><input id="resource-filter" name="resource" value="{}"><button type="submit">Filter</button><a href="?action=validate">Reset</a></form>'.format(
        options, html.escape(resource_query, quote=True)
    )
    rows = "".join(
        '<tr><td><span class="severity severity-{}">{}</span></td><td>{}</td><td>{}</td></tr>'.format(
            finding.severity,
            html.escape(finding.severity.title()),
            _finding_resource(finding.resource, catalogs),
            html.escape(f"{finding.message} ({finding.location})" if finding.location else finding.message),
        )
        for finding in filtered
    )
    if not rows:
        rows = '<tr><td colspan="3">No validation findings match the selected filters.</td></tr>'
    return '<p>Read-only validation; no files were changed.</p>{}{}<p>{} matching finding(s)</p><table><thead><tr><th scope="col">Severity</th><th scope="col">Resource</th><th scope="col">Finding</th></tr></thead><tbody>{}</tbody></table>'.format(
        summary, controls, len(filtered), rows
    )


def _login(config: Config) -> Response:
    content = """<p>Sign in to continue.</p><form method="post" action="{action}">
<label for="username">Username</label><input id="username" name="{username}" autocomplete="username" required autofocus>
<label for="password">Password</label><input id="password" type="password" name="{password}" autocomplete="current-password" required>
<input type="hidden" name="{location}" value="{destination}"><p><button type="submit">Sign in</button></p></form>""".format(
        action=html.escape(config.auth_form_action, quote=True),
        username=html.escape(config.auth_form_username_field, quote=True),
        password=html.escape(config.auth_form_password_field, quote=True),
        location=html.escape(config.auth_form_location_field, quote=True),
        destination=html.escape(config.auth_form_default_location, quote=True),
    )
    return _html_response("Login", content)


def dispatch(
    environ: Mapping[str, str],
    body: bytes = b"",
    config: Optional[Config] = None,
    identity_resolver: Callable[[str, Config], Optional[Identity]] = resolve_identity,
) -> Response:
    """Dispatch one side-effect-free milestone-one request."""
    del body
    active = config or Config()
    params: Dict[str, list] = parse_qs(environ.get("QUERY_STRING", ""), keep_blank_values=True)
    action = params.get("action", [""])[0]
    user = environ.get("REMOTE_USER", "").strip()
    if not action:
        action = "hosts" if user else "login"
    if action == "favicon":
        return Response("200 OK", (("Content-Type", active.favicon_mime_type), ("Cache-Control", "public, max-age=86400")), FAVICON_BYTES)
    if action == "login":
        return _login(active)
    messages = {
        "login_failed": ("Login failed", "The sign-in attempt was not accepted. Please try again.", True),
        "logged_out": ("Signed out", "You have been signed out.", True),
        "auth_error": ("Sign-in error", "Sign-in could not be completed.", False),
    }
    if action in messages:
        title, message, show_login_link = messages[action]
        login_link = ' <a href="?action=login">Return to login</a>.' if show_login_link else ""
        return _html_response(title, "<p>{}{}</p>".format(html.escape(message), login_link))
    if not user:
        location = "?action=login"
        return Response("303 See Other", (("Location", location), ("Content-Type", "text/plain; charset=utf-8"), ("Cache-Control", "no-store")), b"Authentication required.\n")
    identity = identity_resolver(user, active)
    if identity is None:
        return _html_response("Forbidden", "<p>Your account is not authorized to use ProvManager.</p>", "403 Forbidden", public=False)
    required = ACTION_CAPABILITIES.get(action)
    if required is not None and required not in identity.capabilities:
        return _html_response("Forbidden", "<p>You do not have permission to perform this action.</p>", "403 Forbidden", public=False, identity=identity, config=active)
    if action in CATALOG_ACTIONS:
        title, path_field, _sort_field, _columns = CATALOG_ACTIONS[action]
        try:
            records = load_catalog(getattr(active, path_field))
        except CatalogError as error:
            content = "<p>{}</p>".format(html.escape(str(error)))
            return _html_response(title, content, "500 Internal Server Error", public=False, identity=identity, config=active)
        return _html_response(
            title,
            _catalog_table(action, records, params, active),
            public=False,
            identity=identity,
            config=active,
            top_controls=_catalog_search_controls(action, params),
        )
    if action in DETAIL_ACTIONS:
        catalog_action, singular_title = DETAIL_ACTIONS[action]
        _catalog_title, path_field, _sort_field, _columns = CATALOG_ACTIONS[catalog_action]
        record_id = params.get("id", [""])[0]
        if not record_id:
            return _html_response("Invalid request", "<p>A record ID is required.</p>", "400 Bad Request", public=False, identity=identity, config=active)
        try:
            catalogs = {
                catalog_name: load_catalog(getattr(active, catalog_definition[1]))
                for catalog_name, catalog_definition in CATALOG_ACTIONS.items()
            }
            records = catalogs[catalog_action]
        except CatalogError as error:
            return _html_response(singular_title, "<p>{}</p>".format(html.escape(str(error))), "500 Internal Server Error", public=False, identity=identity, config=active)
        record = next((item for item in records if item["id"] == record_id), None)
        if record is None:
            return _html_response("Not found", "<p>The requested record was not found.</p>", "404 Not Found", public=False, identity=identity, config=active)
        display_name = record.get("hostname") or record.get("name") or record["id"]
        return _html_response(
            "{}: {}".format(singular_title, display_name),
            _record_detail(catalog_action, record, catalogs),
            public=False,
            identity=identity,
            config=active,
        )
    if action == "validate":
        findings = validate_catalogs(active)
        return _html_response(
            "Validation",
            _findings_table(findings, params, _validation_catalogs(active)),
            public=False,
            identity=identity,
            config=active,
        )
    if action == "markdown_help":
        return _html_response("Markdown Help", _markdown_help(), public=False, identity=identity, config=active)
    if action in ACTION_CAPABILITIES:
        return _html_response("Not implemented", "<p>This authorized action is not implemented in the initial slice.</p>", "501 Not Implemented", public=False, identity=identity, config=active)
    return _html_response("Not found", "<p>The requested action is not available.</p>", "404 Not Found", public=False, identity=identity, config=active)


def run_cgi(environ: Optional[Mapping[str, str]] = None) -> bytes:
    source = os.environ if environ is None else environ
    config, _diagnostics = load_config(source.get("PROVMANAGER_CONFIG"))
    return dispatch(source, config=config).to_cgi()


# Keep the embedded image after executable source; production icons can be much larger.
FAVICON_BYTES = base64.b64decode(
    """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"""
)
