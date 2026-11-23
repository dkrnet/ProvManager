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

```yaml
schema_version: 1
records:
  - id: installer-001
    name: Example Linux 1
    os_family: example
    os_version: "1"
    architecture: x86_64
    source_type: tree
    source_path: /srv/install/example/1
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
