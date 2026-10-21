"""Pure remediation policy: no package names, CVE IDs or application fixtures.

Profiles are operator-controlled data. Catalog availability and signatures are
not advisory evidence. No automatic 'latest' selection is permitted.
"""
import hashlib
from html.parser import HTMLParser
import json
import re
from urllib.parse import unquote, urljoin, urlsplit


def normalize(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate_profile(profile):
    require(profile.get('schema_version') == 1, 'Unsupported profile schema')
    for key in ('application', 'environment', 'package', 'runtime', 'advisories', 'validation'):
        require(bool(profile.get(key)), 'Missing profile field: ' + key)
    require(re.fullmatch(r'[a-zA-Z0-9_-]+', profile['application']['id']), 'Invalid application ID')
    require(bool(profile['package'].get('name')), 'Missing package name')
    require(bool(profile['runtime'].get('wheel_tags')), 'Explicit target wheel tags are required')
    require(profile['validation'].get('scenario'), 'A machine-test scenario is required')
    require(profile['validation'].get('business_checks'), 'Business acceptance checks are required')
    for advisory in profile['advisories']:
        require(advisory.get('id') and advisory.get('source'), 'Advisory evidence must have an ID and source')
        require(advisory.get('affected_versions') and advisory.get('fixed_versions'), 'Explicit affected/fixed version mapping required')
    return profile


def wheel_identity(filename):
    # PEP 427: distribution/version are escaped and cannot contain '-'.
    parts = filename.removesuffix('.whl').split('-')
    require(filename.endswith('.whl') and len(parts) in (5, 6), 'Invalid wheel filename')
    return normalize(parts[0]), parts[1], parts[-3:]


def compatible(filename, profile):
    package, version, tags = wheel_identity(filename)
    target = set(profile['runtime']['wheel_tags'])
    matches = any(f'{py}-{abi}-{platform}' in target
                  for py in tags[0].split('.') for abi in tags[1].split('.') for platform in tags[2].split('.'))
    return package == normalize(profile['package']['name']) and matches


def approve_artifact(profile, artifact):
    validate_profile(profile)
    require(artifact.get('channel') == 'lightwell', 'Remediation requires Lightwell')
    require(normalize(artifact['package']) == normalize(profile['package']['name']), 'Wrong package')
    require(compatible(artifact['filename'], profile), 'Wheel is incompatible with the target runtime')
    require(wheel_identity(artifact['filename'])[1] == artifact['version'], 'Wheel version does not match descriptor')
    require(re.fullmatch(r'[0-9a-f]{64}', artifact.get('sha256', '')), 'Invalid artifact digest')
    for field in ('url', 'provenance_url'):
        url = urlsplit(artifact[field])
        require(url.scheme == 'https' and url.hostname == 'packages.redhat.com'
                and not url.username and not url.password and not url.query and not url.fragment,
                'Artifact must use the trusted repository without embedded credentials')
    fixed = {item['id'] for item in profile['advisories'] if artifact['version'] in item['fixed_versions']}
    require(fixed == {item['id'] for item in profile['advisories']}
            and set(artifact.get('cves', [])) <= fixed, 'Fix lacks the profile advisory/version evidence')
    require(fixed <= set(artifact.get('cves', [])), 'Descriptor omits an approved advisory')
    return sorted(fixed)


def assess(profile, installed, artifact=None):
    validate_profile(profile)
    require(normalize(installed['package']) == normalize(profile['package']['name']), 'Observed package differs from application profile')
    advisories = sorted(item['id'] for item in profile['advisories'] if installed['version'] in item['affected_versions'])
    identity = {'application': profile['application']['id'], 'environment': profile['environment'],
                'package': normalize(installed['package']), 'advisories': sorted(item['id'] for item in profile['advisories'])}
    incident_key = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
    fixed = approve_artifact(profile, artifact) if artifact else []
    known_fixed = all(installed['version'] in item['fixed_versions'] for item in profile['advisories'])
    state = 'affected' if advisories else ('fixed' if known_fixed else 'unknown')
    public_fields = ('channel', 'package', 'base_version', 'version', 'filename', 'url', 'sha256', 'provenance_url', 'cves')
    public_candidate = {key: artifact[key] for key in public_fields if artifact and key in artifact}
    return dict(identity, schema_version=1, incident_key=incident_key, installed_version=installed['version'],
                profile_sha256=hashlib.sha256(json.dumps(profile, sort_keys=True).encode()).hexdigest(),
                assessment_state=state, affected=bool(advisories),
                fix_available=bool(advisories and artifact and set(advisories) <= set(fixed)),
                advisory_evidence=profile['advisories'], candidate=public_candidate,
                application_profile=profile['application'], validation=profile['validation'])


class Catalog(HTMLParser):
    def __init__(self, index_url, profile):
        super().__init__()
        self.index_url, self.profile, self.candidates = index_url, profile, []

    def handle_starttag(self, tag, attrs):
        if tag != 'a':
            return
        href = dict(attrs).get('href', '')
        url = urlsplit(urljoin(self.index_url, href))
        # A malicious catalog must not redirect credentials to another origin.
        if url.scheme != 'https' or url.hostname != 'packages.redhat.com' or url.username or url.password or url.query:
            return
        filename = unquote(url.path.rsplit('/', 1)[-1])
        try:
            if not compatible(filename, self.profile):
                return
        except ValueError:
            return
        digest = url.fragment.removeprefix('sha256=')
        if not url.fragment.startswith('sha256=') or not re.fullmatch(r'[0-9a-f]{64}', digest):
            return
        package, version, _ = wheel_identity(filename)
        fixed = sorted(a['id'] for a in self.profile['advisories'] if version in a['fixed_versions'])
        self.candidates.append({'package': package, 'version': version, 'filename': filename,
                                'url': url._replace(fragment='').geturl(), 'sha256': digest,
                                'advisories': fixed, 'advisory_mapping_available': bool(fixed)})


def validate_release(profile, artifact, release):
    approve_artifact(profile, artifact)
    require(release.get('schema_version') == 1, 'Unsupported release schema')
    require(release.get('application') == profile['application']['id'], 'Wrong application release')
    require(release.get('channel') == 'lightwell', 'A remediation release must select Lightwell')
    dependencies = release.get('dependencies', [])
    require(len(dependencies) == 1, 'This deployment adapter supports exactly one self-contained wheel; dependency closures require another adapter')
    dependency = dependencies[0]
    require(normalize(dependency.get('package', '')) == normalize(artifact['package'])
            and dependency.get('version') == artifact['version']
            and dependency.get('sha256') == artifact['sha256'], 'Release lock differs from the operator-approved artifact')
    return hashlib.sha256(json.dumps(release, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
