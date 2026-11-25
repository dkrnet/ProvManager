# Catalog schema version 1

ProvManager’s initial read-only catalog loader accepts UTF-8 YAML documents with this envelope:

```yaml
schema_version: 1
records: []
```

`records` must be a list of mappings. Every record must contain a unique, nonempty string `id`. Unknown record fields are retained in memory and ignored by list views when they are not relevant to that resource type.

An empty catalog is represented by an empty `records` list. A missing file, empty physical file, malformed YAML document, unsupported schema version, invalid record collection, unsafe YAML tag, or duplicate record ID is an administrative error and is never treated as an empty catalog.

The initial implementation opens catalog files for reading only. Loading or viewing a catalog does not create, normalize, rewrite, or repair it.

Validation reports one-based YAML line and column numbers when available. If a
field is missing or a finding applies to the whole record, the location points
to the start of the record.

## Minimal examples

Hosts can store each NIC's configuration together. Select a provisioning NIC
by its name in the mapping:

```yaml
provisioning_interface: eno1
interfaces:
  eno1:
    mac_address: "52:54:00:12:34:01"
    ipv4_address: 192.0.2.21
    ipv4_netmask: 255.255.255.0
    ipv4_gateway: 192.0.2.1
  eno2:
    mac_address: "52:54:00:12:34:02"
    ipv4_address: 198.51.100.21
    ipv4_netmask: 255.255.255.0
```

Add `interfaces` to a template's `allowed_variables` to allow all supported
dotted interface references for the selected host. To limit access, allowlist
individual references such as `interfaces.eno2.ipv4_address` instead. Both
forms allow `{{ interfaces.eno2.ipv4_address }}`. A missing NIC or field still
produces a missing-value finding when the template needs it.
Boot templates can use `{{ provisioning_ipv4_address }}` and
`{{ provisioning_mac_address }}` after adding them to their allowlist.
The selected NIC also supplies the existing `ipv4_address` and `mac_address`
template variables for these hosts. You can omit the top-level
`mac_addresses` and `ipv4_address` when migrating to the interface mapping.
Each NIC requires a MAC. Static IPv4 settings require an address and netmask.

To assign both a Kickstart and a boot template to a host, use
`kickstart_template_id: rocky-ks` and `boot_template_id: rocky-boot`.
Each ID must refer to a template with the matching `template_type`.
Host Detail offers a separate preview link for each. Existing records may
keep `template_id` on its own. Remove it when using the typed references.

Hosts may declare `inventory_groups: [web, linux]` to join Ansible groups in the
inventory preview. Use unique, case-sensitive identifiers made of ASCII letters,
digits, and underscores, starting with a letter or underscore. The names
`all` and `ungrouped` are reserved.

To use `{{ hostname }}` in a template, add `hostname` to its
`allowed_variables`. The host's top-level `hostname` supplies the value
unless the host explicitly defines `variables.hostname`. The template
default applies when neither host value is available.
Allowlist `short_hostname` to use `{{ short_hostname }}`. This reserved
variable is derived from the top-level hostname, so `node01.example.com`
and `node01` both yield `node01`.

Boot and Kickstart templates can also allowlist `ipv4_address`,
`mac_address` (the first MAC), `mac_addresses` (all MACs), and
`role_ids` (directly assigned Ansible role IDs). The two list variables
render as comma-separated text in host record order. These reserved variables
use the top-level host fields. A host without role assignments renders an
empty string for `role_ids`.

To use boot paths from the installer selected by the host's `installer_id`,
allowlist `installer_kernel_path`, `installer_initrd_path`, or
`installer_efi_path` and reference them with `{{ name }}`. Values are the
TFTP-relative paths as stored in the installer record. These reserved names
are resolved from the installer alone.

An installer can also set `kickstart_path: https://install.example/os/setup.ks`
and `stage2_path: https://install.example/os/`. Kickstart can use a local file
path instead. Allowlist `installer_kickstart_path` and
`installer_stage2_path` to use them in a boot template. The values are inserted
as stored, so the template supplies any boot option or device prefix required
by the target. Catalog validation checks syntax without opening the targets.

For per-host Kickstart retrieval, set an installer pattern such as
`kickstart_path: 'http://provisioning.example.com/kickstart/{{ short_hostname }}.cfg'`.
For `build01.example.com`, **Preview boot and Kickstart** shows the resolved
URL and the proposed local file `build01.cfg` under `KICKSTART_ROOT`.
Configure the HTTP server separately to serve that directory. Literal
retrieval locations also work for shared Kickstart files. Validation flags
publish filename collisions among enabled hosts assigned Kickstart templates.
The inventory preview can filter hosts by one assigned group. Included hosts
retain all their group memberships in the filtered YAML.

Use `inventory_variables: {site_name: lab, managed: true}` for host variables
in the inventory preview. Values must be plain text, numbers, or booleans.
The `ansible_` prefix is reserved. Values for names recognized as sensitive
are redacted in the preview.

When supplied, `enabled` must be a YAML boolean. Omitted values default to
enabled. Optional `description` fields must be text within `MAX_DESCRIPTION_CHARS`.
When present, `created_at` and `updated_at` must be ISO 8601 timestamps in UTC.
`created_by` and `updated_by` must be nonempty text when present.

```yaml
schema_version: 1
records:
  - id: host-001
    hostname: build01.example.test
    mac_addresses:
      - "02:00:00:00:00:01"
    provisioning_state: unconfigured
    enabled: true
```

Installer source fields depend on `source_type`:

- `tree`: `source_path` is an absolute readable directory beneath `INSTALLER_ROOTS`.
- `iso`: `iso_path` is an absolute readable `.iso` file beneath `INSTALLER_ROOTS`.
- `network`: `source_path` is a credential-free HTTP(S) URL. Validation does not contact it.

File-backed source paths must not contain `..` traversal or control characters;
tree directories must also be traversable. Network URLs require a valid DNS or
IP hostname and must not contain whitespace.

The initial installer-readiness profile supports only `architecture: x86_64`
and `boot_modes: [uefi]`. `kernel_path`, `initrd_path`, and `efi_path` are
required relative paths beneath `TFTP_ROOT`; validation rejects traversal and
symlink escapes and requires all three resolved files to be readable.

```yaml
schema_version: 1
records:
  - id: installer-001
    name: Example Linux 1
    os_family: example
    os_version: "1"
    architecture: x86_64
    boot_modes:
      - uefi
    source_type: tree
    source_path: /srv/install/example/1
    kernel_path: example/1/vmlinuz
    initrd_path: example/1/initrd.img
    efi_path: example/1/BOOTX64.EFI
    enabled: true
```

```yaml
schema_version: 1
records:
  - id: role-001
    name: base
    role_path: /data/provisioning/ansible/roles/base
    enabled: true
```

```yaml
schema_version: 1
records:
  - id: template-001
    name: default-kickstart
    template_type: kickstart
    content_path: /data/provisioning/kickstart/default.ks
    installer_id: installer-001
    role_ids:
      - role-001
    enabled: true
```

Template `installer_id` and ordered `role_ids` entries must reference records in
their respective catalogs. Duplicate, malformed, or missing role references are
reported by read-only validation.

Template content files may be at most `MAX_TEMPLATE_BYTES` bytes (1 MiB by
default). Oversized files are reported at the `content_path` field.

Use `allowed_variables: [site_name, disk_device]` to declare user-defined
names for a template. Names are case-sensitive and must be unique. Use ASCII
letters, digits, and underscores, starting with a letter or underscore.
An omitted list allows no variables. A template can declare fallback values
for its allowed names with `variable_defaults: {site_name: lab}`.
Use `required_variables: [site_name]` to declare names that must have values
when rendering. Each name must appear in the allowlist and may appear only
once in the required list.
For ready and staged hosts, validation checks required names against the host's
`variables` first and then the selected template's `variable_defaults` when the
host omits a name. An explicit YAML null counts as missing. False and zero count
as values. Host Detail links to a read-only rendered preview using the same
precedence. Use `{{ name }}` for allowlisted scalar values. The preview supports
plain substitution and redacts values for names recognized as sensitive.
Both the source and rendered text are subject to `MAX_TEMPLATE_BYTES`.
Catalog validation checks source placeholders without selecting a host. It
reports up to 20 source errors per template, with the source line and column
and the YAML location of the template's `content_path`.
Readiness checks also require a value for each allowlisted placeholder used in
the source, even if the name is omitted from `required_variables`. A value
used by a placeholder must be text, a number, or a boolean. Validation also
flags non-scalar defaults for placeholders on the template record itself,
even when no host selects the template.
Hosts may store host-scoped values in a mapping such as
`variables: {site_name: lab}`. Mapping keys follow the same naming rules.
