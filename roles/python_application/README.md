# Python application release adapter

Requires ansible-core 2.16.0 or newer.

Installs an independently approved self-contained wheel into a per-release venv,
checks provenance for Lightwell, activates the release and runs the application's
probe. Artifact trust and service deployment contain no package names or CVEs.
Call the role directly with a vars file supplying application source, service command and probes. The optional invoice profile is `vars/invoice.yml`, selected explicitly with `vars_from: invoice`; its application assets and source context belong to `roles/invoice`.

Callers must supply approved package/version/digest and compatible wheel filenames
from trusted material, separately from a candidate branch's release manifest.
This adapter currently handles one changed self-contained wheel. It does not
resolve transitive dependency closures or compile native wheels. Provide a
separate adapter/fully pinned dependency closure before admitting those cases.
The role must not silently fetch dependencies from public PyPI.

Use an operator-controlled application profile for business checks. Keep mandatory
acceptance and fault tests outside the candidate collection. A successful signature
is evidence of provenance; advisory evidence is a separate approval input.

Completed releases are sealed over file bytes, modes and link targets. Reusing a
release verifies the seal, source files and approved identity before activation;
existing contents are never repaired or overwritten. Unsealed legacy releases
are rejected: deploy a newly reviewed source revision rather than modifying them.
Failed preparation removes only the incomplete new release. Failed activation
restores the previous release link and service definition and keeps the job failed.

Check mode validates inputs and any existing release, then reports the proposed
activation. It does not download artifacts, install packages, change services or
claim that business probes passed. Normal execution verifies provenance and runs
health and business probes before publishing successful evidence.

Inputs are described in `meta/argument_specs.yml`. Internal release verification
uses root-owned integrity metadata; it detects drift and is not a replacement for
artifact signatures or protection against an attacker with root access.

Role argument validation requires caller-supplied source, command, probe, revision,
artifact and independent approval inputs before deployment. The artifact channel
accepts only `baseline` or `lightwell`. See `meta/argument_specs.yml` for the full contract. Root, service and port retain their usable
role defaults; runtime assertions still enforce safe paths, exact hashes, trusted
URLs and the additional Lightwell signing requirements.
