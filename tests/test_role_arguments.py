"""Run native role argument validation without contacting guests or vendor services."""
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def application_inputs():
    return {'python_application_source': '/fixture/source', 'python_application_source_revision': 'a' * 40,
            'python_application_command': ['/fixture/python', '/fixture/app.py'],
            'python_application_probe_argv': ['/fixture/probe'], 'python_application_package': 'fixture',
            'python_application_approved_sha256': 'b' * 64, 'python_application_approved_version': '1',
            'python_application_compatible_wheels': ['fixture-1-py3-none-any.whl'],
            'python_application_repository_token': 'PRIVATE-ROLE-TOKEN',
            'python_application_artifact': {'channel': 'baseline', 'package': 'fixture', 'version': '1',
                'sha256': 'b' * 64, 'filename': 'fixture-1-py3-none-any.whl',
                'url': 'https://example.test/fixture.whl'}}


class RoleArgumentTests(unittest.TestCase):
    def validate(self, role, entry, variables, passes=True):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'arguments.json'
            path.write_text(json.dumps([{'name': 'Validate the actual public role contract', 'hosts': 'localhost',
                'connection': 'local', 'gather_facts': False, 'vars': variables,
                'tasks': [{'name': 'Load the public role entry', 'ansible.builtin.import_role': {
                    'name': str(ROOT / 'roles' / role), 'tasks_from': entry}}]}]))
            # Ansible itself tags the inserted argument validation task "always".
            # Ordinary role tasks cannot run during this controller-only fixture.
            result = subprocess.run(['ansible-playbook', '-i', 'localhost,', str(path), '--tags', 'always'],
                capture_output=True, text=True, timeout=60, env=dict(os.environ, ANSIBLE_NOCOLOR='1'))
            output = result.stdout + result.stderr
            self.assertEqual(result.returncode == 0, passes, output)
            self.assertIn('Validating arguments', output)
            self.assertNotIn('PRIVATE-ROLE-TOKEN', output)
            return output

    def test_application_defaults_and_complete_baseline_or_lightwell_descriptors(self):
        for channel in ['baseline', 'lightwell']:
            with self.subTest(channel=channel):
                variables = application_inputs()
                variables['python_application_artifact']['channel'] = channel
                if channel == 'lightwell':
                    variables['python_application_artifact'].update(provenance_url='https://packages.redhat.com/p',
                        cves=['CVE-TEST'], advisories=['RHLW-TEST'], advisory_mapping_available=True,
                        advisory_revision='c' * 40, base_version='1')
                self.validate('python_application', 'main', variables)

    def test_missing_caller_inputs_fail_before_release_or_guest_access(self):
        for name in ['source', 'source_revision', 'command', 'probe_argv', 'artifact', 'package',
                     'approved_sha256', 'approved_version', 'compatible_wheels']:
            with self.subTest(name=name):
                variables = application_inputs()
                variables.pop('python_application_' + name)
                output = self.validate('python_application', 'main', variables, False)
                self.assertNotIn('Inspect the selected release', output)

    def test_unknown_channel_or_incomplete_descriptor_is_rejected(self):
        for change in ['channel', 'sha256', 'filename']:
            with self.subTest(change=change):
                variables = application_inputs()
                if change == 'channel':
                    variables['python_application_artifact']['channel'] = 'unapproved'
                else:
                    variables['python_application_artifact'].pop(change)
                self.validate('python_application', 'main', variables, False)

    def test_lightwell_entry_points_require_their_own_inputs(self):
        material = {'profile': {}, 'baseline': {'version': '1'}, 'repository_token': 'PRIVATE-ROLE-TOKEN'}
        common = {'lightwell_material': material}
        self.validate('lightwell', 'discover', common)
        self.validate('lightwell', 'assess', dict(common, lightwell_installed={'package': 'fixture', 'version': '1'}))
        self.validate('lightwell', 'release', dict(common, lightwell_release_file='/fixture/release.json'))
        self.validate('lightwell', 'assess', common, False)
        self.validate('lightwell', 'assess', dict(common, lightwell_installed={'package': 'fixture'}), False)
        self.validate('lightwell', 'release', common, False)


if __name__ == '__main__':
    unittest.main()
