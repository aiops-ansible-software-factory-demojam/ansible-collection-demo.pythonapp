# Lightwell discovery and release policy

Requires ansible-core 2.16.0 or newer.

A controller-side role using only built-in Ansible modules. Application details
and credentials are inputs through `lightwell_material`; no target host is changed.

Import `tasks_from: discover` to join the pinned public Lightwell OSV feed to
its authenticated PEP 691 JSON package index. The match requires package,
backport base version, all requested upstream CVEs, a matching fixed-version
event, a compatible non-yanked wheel (tags and approved `requires_python` metadata), SHA256 and same-origin provenance URL.
No fix returns an empty selection; ambiguous fixes require an operator pin.
An optional existing material selection pins version, filename and hash.

The role returns `lightwell_candidates`, `lightwell_selection` and private
`lightwell_discovered_material`. Signing-key trust is never obtained from discovery.
New preparation resolves the vendor feed head and pins its commit before download.
The selected artifact records that revision, which AAP reuses for repeat discovery.
An explicit `lightwell_advisory_revision` can pin a reviewed snapshot instead.
Discovery retrieves metadata; signature verification and RHEL acceptance still
prove the chosen artifact and application behavior separately.

Import `tasks_from: assess` with `lightwell_installed` to return the public
`lightwell_finding` from the prepared policy. Unknown versions stay unknown.
Import `tasks_from: release` with `lightwell_release_file` to validate the exact
single-dependency lock and return `lightwell_release_sha256`.

`playbooks/discover-lightwell.yml` calls `tasks_from: prepare`, which discovers and writes prepared material to
`lightwell_material_output` after successful discovery. It is usable during
bootstrap without a cluster and uses the same role as AAP catalog discovery.

This role uses built-in Ansible modules. Select an explicit `tasks_from` entry:

| Entry | Required input | Output |
| --- | --- | --- |
| `discover` | `lightwell_material` and its baseline version (or `lightwell_base_version`) | `lightwell_selection`, `lightwell_candidates`, `lightwell_discovered_material` |
| `assess` | `lightwell_material`, `lightwell_installed.package` and `.version` | `lightwell_finding` |
| `release` | `lightwell_material`, `lightwell_release_file` | `lightwell_release_sha256` |

`meta/argument_specs.yml` documents and validates each entry's input types before
its tasks run. `inputs.yml` validates the operator profile; release and artifact
tasks retain the exact package, advisory, source and digest checks. Repository
credentials remain private. Discovery uses the immutable advisory revision in
prepared material, or resolves one before a new preparation.

`playbooks/deploy-invoice.yml` runs from both a collection and a raw AAP Git
checkout. Its local role names use `ansible.cfg`'s `roles_path = ./roles` to select
the reviewed checkout rather than an older installed collection. The discovery
entry points use the FQCN because bootstrap and the automation project explicitly
install the collection before discovery. Do not replace the deployment's local
role references with FQCNs without preserving raw-checkout source selection.

`lightwell_discovered_material` contains private repository material. Keep it under
secure logging and never publish it with the public selection or finding.

The argument specs validate the nested profile, advisory mappings and selected
artifact types at each public entry point. Discovery and assessment accept an
absent or empty `lightwell` selection; release requires a complete selection.
Runtime assertions still enforce nonempty values, safe identifiers and hashes,
trusted URLs, cross-field identity, advisory coverage and unambiguous selection.
The channel assertion is retained for assessment of a nonempty selection because
its optional nested schema must also accept the empty no-fix case.
Dynamic defaults remain in `defaults/main.yml`; the specs do not eagerly
evaluate discovery-only defaults while validating assessment or release inputs.

The `prepare` entry requires `lightwell_material_output` as a controller-local
output path and uses the discovery contract plus a private mode-0600 write.
