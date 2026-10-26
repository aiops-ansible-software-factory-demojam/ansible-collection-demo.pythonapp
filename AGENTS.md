# Python application collection development

This collection owns the Python invoice vulnerability demonstration. The independent nginx/SELinux application lives in `demo.webapp` on a different RHEL host. Production playbooks target `pythonapps`; disposable tests target `molecule`.

Keep application details in `vars/invoice.yml` and application files in `files/invoice`. Call `python_application` directly; do not reintroduce an application wrapper role or put application settings in inventory. Both compatibility entry points import `playbooks/deploy-invoice.yml`.

Use fully qualified Ansible module names and keep roles idempotent. Keep credentials outside roles and repository files. Preserve pinned artifact trust, source identity, release locks, rollback behavior and SELinux enforcing.

For an assigned issue, update `releases/invoice.json` to the exact approved Lightwell package/version/digest and add meaningful regression coverage. Reuse `playbooks/invoice-remediate.yml` and the reusable `python_application` role. Never infer CVE coverage from a signature or modify mandatory independent acceptance.

In the managed sandbox, source `/etc/profile.d/molecule.sh` and `/etc/profile.d/invoice.sh`. Use the mounted material, public signing key, scoped test identity, pinned RHEL 9/10 images and shared Molecule provisioner. Commit before the final machine test and export `INVOICE_SOURCE_COMMIT=$(git rev-parse HEAD)`. Run lint, collection build and `make molecule`; both RHEL versions must finish creation, convergence, idempotence, verification and destruction. After interruption, use `make destroy` in the same sandbox. Keep normal collection paths; source and collection-installation roots must differ.

AAP strips .git. For an overridden checkout, require Controller's protected `awx_job_scm_branch` to be the approved full commit SHA; a branch name is insufficient. Only jobs without an override use `awx_project_revision`, which describes the default project revision. Direct runs check clean Git HEAD. Push the issue branch and open a PR, reporting actual exit codes and the published SHA. Do not merge, change production, or bypass the human review and AAP approval gates.

PR submission is not completion. After the final edit, rerun lint, build and all
Molecule tests, then commit and publish the same incident branch and PR. Run
`demo-goldenpath --repository demo-owner/ansible-collection-demo.pythonapp ci <issue> --wait` until independent CI
passes for that exact head. Exit 75 means pending: keep waiting without editing
the published tree. On failure, read trusted CI diagnostics on the PR, fix the
cause on the same branch, rerun local checks, push a new commit and wait again.
Never publish your own CI status, weaken checks or claim completion while CI
is pending or failed. A passing verdict permits human review, not deployment.

Use only the `ci --wait` helper for CI status. Each call waits at most 45 seconds.
Check the exit code after every call: failure requires repair; pending requires
another bounded wait. Do not replace it with shell polling loops, long sleeps or
direct Forgejo status polling. Publish later commits with the same `pr` helper
on the existing PR. Required tests must execute successfully; skipped tests,
expected failures and removed coverage do not satisfy CI.
