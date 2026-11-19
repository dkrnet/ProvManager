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
from typing import Any, Callable, Dict, FrozenSet, List, Mapping, Optional, Tuple
from urllib.parse import parse_qs

try:
    import yaml
except ImportError:  # pragma: no cover - exercised by deployments without dependencies
    yaml = None


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


@dataclass(frozen=True)
class Config:
    site_config_file: str = "/etc/provmanager.conf"
    hosts_file: str = "/data/provisioning/hosts.yaml"
    installers_file: str = "/data/provisioning/installers.yaml"
    roles_file: str = "/data/provisioning/roles.yaml"
    templates_file: str = "/data/provisioning/templates.yaml"
    audit_log_file: str = "/var/log/provmanager/audit.log"
    tftp_root: str = "/var/lib/tftp/efi/"
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
    auth_form_action: str = "/login"
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


def load_catalog(path: str) -> List[Dict[str, Any]]:
    """Read a version-1 catalog using PyYAML's non-constructing safe loader."""
    if yaml is None:
        raise CatalogError("YAML support is unavailable; install the documented PyYAML dependency.")
    try:
        with open(path, "r", encoding="utf-8") as stream:
            document = yaml.safe_load(stream)
    except FileNotFoundError:
        raise CatalogError("The catalog file is not available.")
    except OSError:
        raise CatalogError("The catalog file could not be read.")
    except yaml.YAMLError:
        raise CatalogError("The catalog contains invalid YAML and was not loaded.")
    if not isinstance(document, dict):
        raise CatalogError("The catalog must be a versioned mapping.")
    if document.get("schema_version") != 1:
        raise CatalogError("The catalog schema version is missing or unsupported.")
    records = document.get("records")
    if not isinstance(records, list) or any(not isinstance(record, dict) for record in records):
        raise CatalogError("The catalog records value must be a list of mappings.")
    identifiers = [record.get("id") for record in records]
    if any(not isinstance(identifier, str) or not identifier for identifier in identifiers):
        raise CatalogError("Every catalog record must have a nonempty string ID.")
    if len(set(identifiers)) != len(identifiers):
        raise CatalogError("The catalog contains duplicate record IDs.")
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


def validate_catalogs(config: Config) -> List[Finding]:
    """Inspect canonical catalogs and referenced paths without modifying them."""
    catalogs = {}
    findings = []
    for action, (title, path_field, _sort, _columns) in CATALOG_ACTIONS.items():
        try:
            catalogs[action] = load_catalog(getattr(config, path_field))
        except CatalogError as error:
            catalogs[action] = []
            findings.append(Finding("error", title, str(error)))

    for action, records in catalogs.items():
        seen = {}
        name_field = "hostname" if action == "hosts" else "name"
        for record in records:
            value = record.get(name_field)
            canonical = value.casefold() if isinstance(value, str) else ""
            if not canonical:
                findings.append(Finding("error", str(record.get("id")), "A required {} is missing.".format(name_field)))
            elif canonical in seen:
                findings.append(Finding("error", str(record.get("id")), "The {} duplicates another record.".format(name_field)))
            else:
                seen[canonical] = record.get("id")

    installers = {record["id"]: record for record in catalogs["installers"]}
    roles = {record["id"]: record for record in catalogs["roles"]}
    templates = {record["id"]: record for record in catalogs["templates"]}
    used_macs = {}
    used_ips = {}
    for host in catalogs["hosts"]:
        resource = str(host.get("hostname") or host["id"])
        if not _valid_hostname(host.get("hostname")):
            findings.append(Finding("error", resource, "Hostname is not a valid DNS name."))
        macs = host.get("mac_addresses", [])
        if not isinstance(macs, list) or not macs:
            findings.append(Finding("error", resource, "At least one MAC address is required."))
        else:
            for mac in macs:
                normalized = _normalize_mac(mac)
                if normalized is None:
                    findings.append(Finding("error", resource, "A MAC address is invalid."))
                elif host.get("enabled", True) and normalized in used_macs:
                    findings.append(Finding("error", resource, "A MAC address is already used by another enabled host."))
                elif host.get("enabled", True):
                    used_macs[normalized] = host["id"]
        for field in ("ipv4_address", "ipv6_address"):
            value = host.get(field)
            if not value:
                continue
            try:
                parsed = str(ipaddress.ip_address(value))
            except ValueError:
                findings.append(Finding("error", resource, "{} is invalid.".format(field.replace("_", " ").upper())))
                continue
            if host.get("enabled", True) and parsed in used_ips:
                findings.append(Finding("error", resource, "An IP address is already used by another enabled host."))
            elif host.get("enabled", True):
                used_ips[parsed] = host["id"]
        for field, index, label in (("installer_id", installers, "installer"), ("template_id", templates, "template")):
            reference = host.get(field)
            if reference and reference not in index:
                findings.append(Finding("error", resource, "Referenced {} does not exist.".format(label)))
        role_ids = host.get("role_ids", [])
        if not isinstance(role_ids, list) or any(not isinstance(role_id, str) for role_id in role_ids) or len(role_ids) != len(set(role_ids)):
            findings.append(Finding("error", resource, "Role references must be an ordered list without duplicates."))
        elif any(role_id not in roles for role_id in role_ids):
            findings.append(Finding("error", resource, "A referenced role does not exist."))

    for role in catalogs["roles"]:
        path = role.get("role_path")
        resource = str(role.get("name") or role["id"])
        if not isinstance(path, str) or not _inside(path, config.ansible_root):
            findings.append(Finding("error", resource, "Role path is outside the approved Ansible root."))
        elif not os.path.isdir(path) or not os.access(path, os.R_OK):
            findings.append(Finding("error", resource, "Role path is not a readable directory."))

    template_roots = {"kickstart": config.kickstart_root, "ansible": config.ansible_root, "boot": config.tftp_root}
    for template in catalogs["templates"]:
        resource = str(template.get("name") or template["id"])
        template_type = template.get("template_type")
        path = template.get("content_path")
        root = template_roots.get(template_type)
        if root is None:
            findings.append(Finding("error", resource, "Template type is unsupported."))
        elif not isinstance(path, str) or not _inside(path, root):
            findings.append(Finding("error", resource, "Template content path is outside its approved root."))
        elif not os.path.isfile(path) or not os.access(path, os.R_OK):
            findings.append(Finding("error", resource, "Template content is not a readable file."))

    for installer in catalogs["installers"]:
        resource = str(installer.get("name") or installer["id"])
        path = installer.get("source_path")
        if not isinstance(path, str) or not os.path.isabs(path):
            findings.append(Finding("error", resource, "Installer source path must be absolute."))
        elif not os.path.exists(path) or not os.access(path, os.R_OK):
            findings.append(Finding("error", resource, "Installer source path is not readable."))
        else:
            findings.append(Finding("warning", resource, "Installer path is readable, but no installer-root allowlist is specified yet."))
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
        ("operations_read", "Operations", "operations"),
        ("settings_read", "Settings", "settings"),
        ("audit_read", "Audit Log", "audit"),
    ):
        if capability in identity.capabilities:
            links.append('<a href="?action={}">{}</a>'.format(action, label))
    return "<nav>{}</nav>".format(" | ".join(links))


def _html_page(title: str, content: str, public: bool = True, identity: Optional[Identity] = None, config: Optional[Config] = None) -> bytes:
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
<style>body{{font-family:system-ui,sans-serif;margin:2rem;line-height:1.45}}header{{height:35px;background:linear-gradient(90deg,#E6E9EF,transparent);color:#7b8290;padding:.5rem 1rem}}main{{max-width:70rem;margin:1.5rem auto}}nav{{display:flex;gap:.8rem;flex-wrap:wrap}}table{{border-collapse:collapse;width:100%;font-size:.9rem}}th,td{{padding:.4rem;text-align:left;border-bottom:1px solid #ddd;vertical-align:top}}label{{display:block;margin-top:.8rem}}input{{padding:.4rem}}footer{{text-align:center;color:#667;margin-top:3rem}}</style></head>
<body><header>ProvManager</header><main>{3}{4}<h1>{0}</h1>{1}</main>{2}</body></html>""".format(
        html.escape(title), content, footer, welcome, navigation
    )
    return document.encode("utf-8")


def _html_response(title: str, content: str, status: str = "200 OK", public: bool = True, identity: Optional[Identity] = None, config: Optional[Config] = None) -> Response:
    return Response(
        status,
        (("Content-Type", "text/html; charset=utf-8"), ("Cache-Control", "no-store")),
        _html_page(title, content, public, identity, config),
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


def _catalog_table(action: str, records: List[Dict[str, Any]]) -> str:
    title, _path_field, sort_field, columns = CATALOG_ACTIONS[action]
    sorted_records = sorted(records, key=lambda record: str(record.get(sort_field, "")).casefold())
    headings = "".join("<th scope=\"col\">{}</th>".format(html.escape(column.replace("_", " ").title())) for column in columns)
    if not sorted_records:
        rows = '<tr><td colspan="{}">No {} are configured.</td></tr>'.format(len(columns), html.escape(title.lower()))
    else:
        detail_action = {"hosts": "host_view", "installers": "installer_view", "roles": "role_view", "templates": "template_view"}[action]
        rendered_rows = []
        for record in sorted_records:
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
    return '<p>{} record(s)</p><table><thead><tr>{}</tr></thead><tbody>{}</tbody></table>'.format(len(sorted_records), headings, rows)


def _record_detail(record: Dict[str, Any]) -> str:
    rows = []
    for key in sorted(record):
        rows.append(
            "<tr><th scope=\"row\">{}</th><td>{}</td></tr>".format(
                html.escape(key.replace("_", " ").title()), html.escape(_display_value(record[key], key))
            )
        )
    return "<table><tbody>{}</tbody></table>".format("".join(rows))


def _findings_table(findings: List[Finding]) -> str:
    rows = "".join(
        "<tr><td>{}</td><td>{}</td><td>{}</td></tr>".format(
            html.escape(finding.severity.title()), html.escape(finding.resource), html.escape(finding.message)
        )
        for finding in findings
    )
    return '<p>Read-only validation; no files were changed.</p><table><thead><tr><th scope="col">Severity</th><th scope="col">Resource</th><th scope="col">Finding</th></tr></thead><tbody>{}</tbody></table>'.format(rows)


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
        "login_failed": ("Login failed", "The sign-in attempt was not accepted. Please try again."),
        "logged_out": ("Signed out", "You have been signed out."),
        "auth_error": ("Sign-in error", "Sign-in could not be completed."),
    }
    if action in messages:
        title, message = messages[action]
        return _html_response(title, "<p>{}</p>".format(html.escape(message)))
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
        return _html_response(title, _catalog_table(action, records), public=False, identity=identity, config=active)
    if action in DETAIL_ACTIONS:
        catalog_action, singular_title = DETAIL_ACTIONS[action]
        _catalog_title, path_field, _sort_field, _columns = CATALOG_ACTIONS[catalog_action]
        record_id = params.get("id", [""])[0]
        if not record_id:
            return _html_response("Invalid request", "<p>A record ID is required.</p>", "400 Bad Request", public=False, identity=identity, config=active)
        try:
            records = load_catalog(getattr(active, path_field))
        except CatalogError as error:
            return _html_response(singular_title, "<p>{}</p>".format(html.escape(str(error))), "500 Internal Server Error", public=False, identity=identity, config=active)
        record = next((item for item in records if item["id"] == record_id), None)
        if record is None:
            return _html_response("Not found", "<p>The requested record was not found.</p>", "404 Not Found", public=False, identity=identity, config=active)
        display_name = record.get("hostname") or record.get("name") or record["id"]
        return _html_response("{}: {}".format(singular_title, display_name), _record_detail(record), public=False, identity=identity, config=active)
    if action == "validate":
        return _html_response("Validation", _findings_table(validate_catalogs(active)), public=False, identity=identity, config=active)
    if action in ACTION_CAPABILITIES:
        return _html_response("Not implemented", "<p>This authorized action is not implemented in the initial slice.</p>", "501 Not Implemented", public=False, identity=identity, config=active)
    return _html_response("Not found", "<p>The requested action is not available.</p>", "404 Not Found", public=False, identity=identity, config=active)


def run_cgi(environ: Optional[Mapping[str, str]] = None) -> bytes:
    source = os.environ if environ is None else environ
    config, _diagnostics = load_config(source.get("PROVMANAGER_CONFIG"))
    return dispatch(source, config=config).to_cgi()


# Keep the embedded image after executable source; production icons can be much larger.
FAVICON_BYTES = base64.b64decode(
    "AAABAAEAAQEAAAEAIABoBAAAFgAAACgAAAABAAAAAgAAAAEAIAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAD///8A"
)
