# Python application release adapter

Installs an independently approved self-contained wheel into a per-release venv,
checks provenance for Lightwell, activates the release and runs the application's
probe. Artifact trust and service deployment contain no package names or CVEs.
`invoice_portal` supplies its application source, command and PDF checks.

Callers must supply approved package/version/digest and compatible wheel filenames
from trusted material, separately from a candidate branch's release manifest.
This adapter currently handles one changed self-contained wheel. It does not
resolve transitive dependency closures or compile native wheels. Provide a
separate adapter/fully pinned dependency closure before admitting those cases.
The role must not silently fetch dependencies from public PyPI.

Use an operator-controlled application profile for business checks. Keep mandatory
acceptance and fault tests outside the candidate collection. A successful signature
is evidence of provenance; advisory evidence is a separate approval input.
