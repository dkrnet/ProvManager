# Catalog schema version 1

ProvManager’s initial read-only catalog loader accepts UTF-8 YAML documents with this envelope:

```yaml
schema_version: 1
records: []
```

`records` must be a list of mappings. Every record must contain a unique, nonempty string `id`. Unknown record fields are retained in memory and ignored by list views when they are not relevant to that resource type.

An empty catalog is represented by an empty `records` list. A missing file, empty physical file, malformed YAML document, unsupported schema version, invalid record collection, unsafe YAML tag, or duplicate record ID is an administrative error and is never treated as an empty catalog.

The initial implementation opens catalog files for reading only. Loading or viewing a catalog does not create, normalize, rewrite, or repair it.

## Minimal examples

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
