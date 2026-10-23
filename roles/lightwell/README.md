# Lightwell discovery and release policy

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

`playbooks/discover-lightwell.yml` writes prepared material to
`lightwell_material_output` after successful discovery. It is usable during
bootstrap without a cluster and uses the same role as AAP catalog discovery.
