# demo.pythonapp

Ansible collection for the Python invoice application and dependency-vulnerability demonstration on RHEL. Imported from the invoice implementation in `demo.webapp`; nginx and its SELinux outage remain in [demo.webapp](https://github.com/aiops-ansible-software-factory-demojam/ansible-collection-demo.webapp).

Production playbooks target the separate `pythonapps` inventory group. The app extracts normal PDF invoices; the locked upstream PyPDF2 3.0.1 baseline reproduces CVE-2023-36464 as a bounded two-second extraction timeout. The RHEL host remains SELinux enforcing. Updating `releases/invoice.json` selects an independently approved Lightwell backport; production never resolves latest.

## Layout

| Path | Purpose |
| --- | --- |
| `roles/python_application` | Reusable wheel deployment adapter (provenance, venv, systemd, probes) |
| `roles/lightwell` | Controller-side Lightwell discovery, assessment, and release policy |
| `roles/invoice` | Invoice assets, material binding, source/release guards, containment and AAP evidence |
| `roles/python_application/vars/invoice.yml` | Optional invoice profile for the generic deployment role |
| `roles/invoice/files/invoice` | Application source copied into each immutable release |
| `playbooks/` | Deploy, discover, contain, and remediate entry points |
| `collections/requirements.yml` | Pinned deps for Molecule utility playbooks (`david_igou.molecule_provisioners`) |
| `meta/runtime.yml` | Minimum ansible-core version (`requires_ansible`) for Galaxy and Automation Hub metadata |
| `extensions/molecule/` | Shared EC2/KubeVirt scenario lifecycle |

`roles/python_application` verifies exact wheel bytes, package metadata, signed provenance and the pinned public signing key, then installs an isolated release with activation and rollback. `roles/python_application/vars/invoice.yml` supplies application settings and business probes; application files live in `roles/invoice/files/invoice`. Playbooks orchestrate the roles directly; the invoice role does not call other roles or put application settings in inventory. Reuse `playbooks/invoice-remediate.yml` when authoring a dependency release. Source guards bind each deployment to its approved collection commit, including AAP copies without `.git`.

In the managed Omnigent sandbox:

```sh
source /etc/profile.d/molecule.sh
source /etc/profile.d/invoice.sh
export INVOICE_SOURCE_COMMIT=$(git rev-parse HEAD)
ansible-lint --profile production
# Or lint the roles, playbooks, and invoice_portal scenario only:
# ansible-lint roles/python_application playbooks extensions/molecule/invoice_portal
ansible-galaxy collection build --output-path /tmp
make molecule
make destroy  # Recover after interruption
```

Use mounted Lightwell material/signing trust and the sandbox's scoped AWS test credentials. Both pinned RHEL 9 and RHEL 10 guests must finish creation, convergence, idempotence, verification and destruction. The initial release lock is deliberately the vulnerable baseline, so a real remediation candidate must select the approved Lightwell version before these acceptance tests pass.

Independent mandatory acceptance is maintained in `demojam-ansible`, outside the author's write permissions. It checks the exact published SHA, wheel identity, normal/regression documents, SELinux enforcing, and a real failed-canary rollout with rollback and an untouched follower. Human review/merge and a separate AAP production approval remain required.

Local behavioral tests use stock PyPDF2 3.0.1 and Ansible. The release-role integration tests also require a user allowed to create disposable directories under `/opt`:

```sh
python -m unittest discover -s tests -v
```

Policy fixtures for other packages are synthetic and do not establish another successful deployed remediation. See the [invoice runbook](https://github.com/aiops-ansible-software-factory-demojam/openshift-gitops/blob/main/docs/invoice-lightwell-demo.md) for setup, credentials and runtime evidence.

Lightwell discovery and release-policy checks use the reusable
[`lightwell` role](roles/lightwell/README.md), built entirely from standard
Ansible modules. Package/app/CVE policy remains input data. The role joins a
pinned vendor OSV advisory feed with the authenticated JSON package index;
it requires an unambiguous compatible fix or an explicit approval pin.
`playbooks/discover-lightwell.yml` prepares private material during bootstrap.
Signature verification and mandatory independent RHEL tests remain separate.

Production remediation through AAP requires an `invoice_release_contract` from
the trusted validator and the native `invoice_promote` workflow context. Source,
lock, target group and public material hashes are checked before guest access;
changed shared artifact credentials fail this check. Direct disposable Molecule
runs retain their existing release-policy checks without a production approval.

`playbooks/contain-invoice.yml` implements the router's approved temporary
containment path using built-in Ansible modules. Application service details remain
in `roles/python_application/vars/invoice.yml`; profile policy must explicitly permit `stop_service` and name
the same service. The saved response must match the current profile, pinned AAP
source revision, native `invoice_contain` context and complete `pythonapps` host
scope. Each host must have one known affected observation and still run that exact
observed dependency version before its service can be stopped and disabled.
Service facts must confirm containment before success evidence is published.

Containment causes an outage and leaves the dependency vulnerable (`fixed: false`).
It does not modify package versions or mark an incident resolved. The trusted
controller project owns routing and native approval verification. A later reviewed
fixed deployment uses the existing role to enable/start and verify the service.

## Current acceptance and packaging

The 2026-10-28 dual-application AWS rehearsal exercised these role contracts through
baseline deployment, independent RHEL 9/10 acceptance and approved production
promotion. The actual agent PR updated `releases/invoice.json` to the approved
Lightwell wheel; prebuilt deployment and regression/rollback tests were reused.
This does not turn the checked-in vulnerable baseline into a remediated release.
The collection's local unit and packaging tests validate role contracts on the tested source; they are distinct from machine acceptance in `demojam-ansible`.

`collections/ansible_collections/` is generated installation content: Git ignores
it and Galaxy excludes it. The packaging fixture includes a cache and an external
symlink and verifies neither enters the artifact. `collections/requirements.yml`
declares lint/Molecule collection dependencies and is included in the built artifact.
Keep temporary source exports and installed collections separate. The sandbox helper rejects nonportable
committed content before publication.

See the [tested state and source refs](https://github.com/aiops-ansible-software-factory-demojam/openshift-gitops/blob/main/docs/stable-demo-rehearsal.md)
and [Draw.io XML diagrams](https://github.com/aiops-ansible-software-factory-demojam/openshift-gitops/tree/main/docs/diagrams).
