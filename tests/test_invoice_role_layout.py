"""Exercise invoice paths and its real release profile outside collection playbooks."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class InvoiceRoleLayoutTests(unittest.TestCase):
    def test_raw_and_installed_profiles_resolve_role_owned_assets(self):
        for installed in (False, True):
            with self.subTest(installed=installed), tempfile.TemporaryDirectory() as directory:
                temp = Path(directory)
                collection = temp / 'collections/ansible_collections/demo/pythonapp'
                collection.mkdir(parents=True)
                shutil.copytree(ROOT / 'roles', collection / 'roles')
                source = collection if installed else ROOT
                role = (lambda name: 'demo.pythonapp.' + name) if installed else (lambda name: str(source / 'roles' / name))
                variables = {'invoice_candidate_sha': 'a' * 40, 'invoice_release_channel': 'baseline',
                    'awx_job_id': 1, 'awx_project_revision': 'a' * 40,
                    'python_application_root': '/opt/invoice-layout-' + temp.name.replace('.', '-'),
                    'invoice_material': {'baseline': {'channel': 'baseline', 'package': 'PyPDF2', 'version': '1',
                        'filename': 'pypdf2-1-py3-none-any.whl', 'sha256': 'b' * 64,
                        'url': 'https://example.test/wheel.whl'}, 'profile': {'validation': {}}},
                    'expected_source': str(source)}
                play = [{'name': 'Exercise actual invoice role contracts', 'hosts': 'localhost',
                    'connection': 'local', 'gather_facts': False, 'tasks': [
                        {'name': 'Bind and validate the invoice source', 'ansible.builtin.import_role': {'name': role('invoice')}},
                        {'name': 'Plan the real generic release with its invoice vars profile',
                         'ansible.builtin.import_role': {'name': role('python_application'), 'vars_from': 'invoice'}},
                        {'name': 'Verify role context survives crossing into the generic role', 'ansible.builtin.assert': {'that': [
                            'invoice_collection_directory == expected_source',
                            "python_application_source == expected_source + '/roles/invoice/files/invoice/'"]}}]}]
                path = temp / 'external-playbook.json'
                path.write_text(json.dumps(play))
                result = subprocess.run(['ansible-playbook', '-i', 'localhost,', '--check', str(path), '-e', json.dumps(variables)],
                    env=dict(os.environ, ANSIBLE_COLLECTIONS_PATH=str(temp / 'collections')), capture_output=True, text=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse(Path(variables['python_application_root']).exists())
                self.assertIn('Report planned release activation', result.stdout)
