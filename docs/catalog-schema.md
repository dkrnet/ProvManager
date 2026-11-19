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
    role_ids:
      - role-001
    enabled: true
```
