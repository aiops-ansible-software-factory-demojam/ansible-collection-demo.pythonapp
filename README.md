# demo.pythonapp

Ansible collection for the Python invoice application and dependency-vulnerability demonstration on RHEL. Imported from the invoice implementation in `demo.webapp`; nginx and its SELinux outage remain in [demo.webapp](https://github.com/aiops-ansible-software-factory-demojam/ansible-collection-demo.webapp).

Production playbooks target the separate `pythonapps` inventory group. The app extracts normal PDF invoices; the locked upstream PyPDF2 3.0.1 baseline reproduces CVE-2023-36464 as a bounded two-second extraction timeout. The RHEL host remains SELinux enforcing. Updating `releases/invoice.json` selects an independently approved Lightwell backport; production never resolves latest.

`roles/python_application` verifies exact wheel bytes, package metadata, signed provenance and the pinned public signing key, then installs an isolated release with activation and rollback. `vars/invoice.yml` supplies application settings and business probes; application files live in `files/invoice`. No application wrapper role or inventory settings are needed. Reuse `playbooks/invoice-remediate.yml` when authoring a dependency release. Source guards bind each deployment to its approved collection commit, including AAP copies without .git.

In the managed Omnigent sandbox:

```sh
source /etc/profile.d/molecule.sh
source /etc/profile.d/invoice.sh
export INVOICE_SOURCE_COMMIT=$(git rev-parse HEAD)
ansible-lint roles/python_application playbooks extensions/molecule/invoice_portal
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

Policy fixtures for other packages are synthetic and do not establish another successful deployed remediation. See the [invoice runbook](https://github.com/aiops-ansible-software-factory-demojam/openshift-gitops/blob/feature/separate-demo-applications/docs/invoice-lightwell-demo.md) for setup, credentials and runtime evidence.
