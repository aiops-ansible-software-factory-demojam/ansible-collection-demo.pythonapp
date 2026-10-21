#!/usr/bin/python
"""Controller-side assessment, candidate discovery and immutable release checks."""
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import open_url
from ansible_collections.demo.pythonapp.plugins.module_utils.remediation import (
    Catalog, approve_artifact, assess, normalize, validate_profile, validate_release,
)

DOCUMENTATION = r'''
module: lightwell_plan
short_description: Assess an application finding using operator-controlled Lightwell policy
version_added: 0.1.0
description:
  - Catalog availability does not establish CVE remediation. Advisory mappings are explicit trusted inputs.
  - Run on the controller; no target host is changed.
options:
  operation:
    type: str
    choices: [assess, discover, release]
    default: assess
  material_file:
    type: path
    required: true
  installed:
    type: dict
    default: {}
  release_file:
    type: path
  include_profile:
    type: bool
    default: false
author: Demo Maintainer
'''
EXAMPLES = r'''
- name: Assess an observed dependency against the trusted advisory mappings
  demo.pythonapp.lightwell_plan:
    material_file: /runner/artifacts/material.json
    installed: {package: PyPDF2, version: '3.0.1'}
'''
RETURN = r'''
finding:
  description: Public application, advisory, candidate and incident identity.
  type: dict
  returned: On assess
candidates:
  description: Compatible catalog entries, with advisory mapping status; never auto-approved.
  type: list
  returned: On discover
release_sha256:
  description: Digest of the approved release lock.
  type: str
  returned: On release
'''


def main():
    import json
    module = AnsibleModule(argument_spec=dict(
        operation=dict(type='str', choices=['assess', 'discover', 'release'], default='assess'),
        material_file=dict(type='path', required=True), installed=dict(type='dict', default={}),
        release_file=dict(type='path'), include_profile=dict(type='bool', default=False)), supports_check_mode=True)
    try:
        with open(module.params['material_file']) as stream:
            material = json.load(stream)
        profile = validate_profile(material['profile'])
        operation = module.params['operation']
        result = {'changed': False}
        if operation == 'assess':
            result['finding'] = assess(profile, module.params['installed'], material.get('lightwell') or None)
        elif operation == 'release':
            with open(module.params['release_file']) as stream:
                release = json.load(stream)
            result['release_sha256'] = validate_release(profile, material['lightwell'], release)
        else:
            url = 'https://packages.redhat.com/lightwell/python/remediated/simple/' + normalize(profile['package']['name']) + '/'
            response = open_url(url, url_username=material['repository_username'],
                                url_password=material['repository_token'], force_basic_auth=True,
                                follow_redirects='none', timeout=30, validate_certs=True)
            document = response.read(4 * 1024 * 1024 + 1)
            if len(document) > 4 * 1024 * 1024:
                raise ValueError('Catalog exceeds the response-size bound')
            parser = Catalog(url, profile)
            parser.feed(document.decode())
            result['candidates'] = sorted(parser.candidates, key=lambda item: item['filename'])
            result['selection_required'] = True
        if module.params['include_profile']:
            result['profile'] = profile
        module.exit_json(**result)
    except Exception as error:
        # URLs, material and HTTP exception strings can contain credentials.
        module.fail_json(msg='Lightwell policy or catalog operation failed: ' + type(error).__name__)


if __name__ == '__main__':
    main()
