# Invoice application lifecycle

Owns the invoice application files, runtime material binding, deployment source
checks, production contract checks, host preparation, containment and AAP evidence.
Application content lives in `files/invoice/`; material and service settings live
in `vars/main.yml`. Nothing here changes the approved dependency lock.

The deployment playbook calls the roles directly in this order:

1. `invoice` (default entry): capture this role's collection root and validate the reviewed source.
2. `lightwell`, `tasks_from: release`: validate the approved dependency lock when remediating.
3. `invoice`, `tasks_from: validate-release-contract`: check the protected production approval contract.
4. `invoice`, `tasks_from: prepare-host`: connect, gather facts and require RHEL 9/10.
5. `python_application`, `vars_from: invoice`: deploy using the explicit invoice application profile.
6. `invoice`, `tasks_from: publish-evidence`: publish verified results.

The generic Python role's optional `vars/invoice.yml` profile supplies its public
`python_application_*` inputs. Generic tasks and defaults stay application-neutral;
the application profile is loaded only when explicitly selected.

`tasks_from: contain` validates the native approval, source, application policy and
current vulnerable observation before stopping and disabling the application.
Containment reports `fixed: false` and never claims a dependency remediation.

The captured `invoice_collection_directory` resolves assets from the executing
role, including raw AAP checkouts and installed collections. Do not derive it from
an unrelated caller's `playbook_dir`, install a different copy of the application,
or bypass source and production gates when moving these tasks.
