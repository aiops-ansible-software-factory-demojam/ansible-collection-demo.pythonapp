"""Exercise collection module packaging and its public/secret output boundary."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from test_remediation_policy import profile, artifact

ROOT = Path(__file__).resolve().parents[1]


class LightwellModuleTests(unittest.TestCase):
    def run_module(self, selected, installed, success=True):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            collection = root / 'collections/ansible_collections/demo'
            collection.mkdir(parents=True)
            (collection / 'pythonapp').symlink_to(ROOT, target_is_directory=True)
            material = root / 'material.json'
            material.write_text(json.dumps({'profile': profile(), 'lightwell': selected,
                                           'repository_username': 'fixture-user',
                                           'repository_token': 'fixture-private-token'}))
            play = root / 'check.yml'
            play.write_text(json.dumps([{'name': 'Exercise controller assessment', 'hosts': 'localhost',
                'gather_facts': False, 'connection': 'local', 'tasks': [
                    {'name': 'Assess without publishing repository access', 'demo.pythonapp.lightwell_plan':
                     {'material_file': str(material), 'installed': installed}, 'register': 'assessment'},
                    {'name': 'Publish public assessment', 'ansible.builtin.debug': {'var': 'assessment'}}]}]))
            environment = dict(os.environ, ANSIBLE_COLLECTIONS_PATH=str(root / 'collections'))
            result = subprocess.run([shutil.which('ansible-playbook'), '-i', 'localhost,', str(play)],
                                    env=environment, capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
            self.assertNotIn('fixture-private-token', result.stdout + result.stderr)
            return result.stdout

    def test_module_runs_with_collection_packaged_module_utils(self):
        selected = artifact()
        selected['repository_token'] = 'fixture-private-token'
        output = self.run_module(selected, {'package': 'PyPDF2', 'version': '3.0.1'})
        self.assertIn('"affected": true', output)
        self.assertIn('"fix_available": true', output)

    def test_no_candidate_is_a_valid_non_authoring_assessment(self):
        output = self.run_module({}, {'package': 'PyPDF2', 'version': '3.0.1'})
        self.assertIn('"fix_available": false', output)

    def test_unmapped_fix_fails_closed(self):
        self.run_module(artifact(version='3.0.1+unmapped'), {'package': 'PyPDF2', 'version': '3.0.1'}, success=False)


if __name__ == '__main__':
    unittest.main()
