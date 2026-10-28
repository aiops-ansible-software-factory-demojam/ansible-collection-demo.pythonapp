# Python application collection development

This collection owns the Python invoice vulnerability demonstration. The independent nginx/SELinux application lives in `demo.webapp` on a different RHEL host. Production playbooks target `pythonapps`; disposable tests target `molecule`.

Keep application details in `vars/invoice.yml` and application files in `files/invoice`. Call `python_application` directly; do not reintroduce an application wrapper role or put application settings in inventory. Both compatibility entry points import `playbooks/deploy-invoice.yml`.

Use fully qualified Ansible module names and keep roles idempotent. Keep credentials outside roles and repository files. Preserve pinned artifact trust, source identity, release locks, rollback behavior and SELinux enforcing.

For an assigned issue, update `releases/invoice.json` to the exact approved Lightwell package/version/digest and add meaningful regression coverage. Reuse `playbooks/invoice-remediate.yml` and the reusable `python_application` role. Never infer CVE coverage from a signature or modify mandatory independent acceptance.

In the managed sandbox, source `/etc/profile.d/molecule.sh` and `/etc/profile.d/invoice.sh`. Use the mounted material, public signing key, scoped test identity, pinned RHEL 9/10 images and shared Molecule provisioner. Commit before the final machine test and export `INVOICE_SOURCE_COMMIT=$(git rev-parse HEAD)`. Run lint, collection build and `make molecule`; both RHEL versions must finish creation, convergence, idempotence, verification and destruction. After interruption, use `make destroy` in the same sandbox. Keep normal collection paths; source and collection-installation roots must differ.

AAP strips .git. For an overridden checkout, require Controller's protected `awx_job_scm_branch` to be the approved full commit SHA; a branch name is insufficient. Only jobs without an override use `awx_project_revision`, which describes the default project revision. Direct runs check clean Git HEAD. Push the issue branch and open a PR, reporting actual exit codes and the published SHA. Do not merge, change production, or bypass the human review and AAP approval gates.

Run the collection's complete unit suite as well as lint, build and all Molecule
scenarios. Report actual command exit codes and distinguish completed checks from
checks that could not run. Do not hide failures behind a successful shell pipeline.

Molecule provisioning commands (`test`, `converge`, `create`, `check`) deliberately
destroy the scenario's owned test guests before creating replacements. Preserve
these lifecycle sequences. After any code change, rerun the complete test lifecycle
on fresh RHEL 9/10 guests before reporting success; an earlier converge or a run
with skipped creation does not validate the final code. Keep the saved ownership
records so cleanup can remove partial resources; never delete state to force a
new run. Set the shell tool timeout to at least 1800000 ms (30 minutes) for a full EC2
lifecycle; do not add a shorter shell `timeout` around Molecule. A timeout or
incomplete output is not a pass. Run tests without output-filtering pipelines,
or enable `set -o pipefail` and preserve the actual Molecule exit status.

Keep generated collection installations outside the checkout. Never commit the
`collections/ansible_collections/` cache or absolute/outside-checkout symlinks. Use a separate temporary
collection installation root and preserve the sandbox's normal dependency paths.
Before committing and submitting, inspect `git diff --cached --stat` and
`git diff --cached --name-status`; stage only reviewed source and regression tests.
The PR helper rejects nonportable committed content before pushing or publishing.
Keep standard `collections/requirements.yml` dependency declarations in source.
