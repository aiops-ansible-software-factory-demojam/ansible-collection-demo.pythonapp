"""Exercise the deployment's actual fail-before-connection production checks."""
import copy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]


class ProductionContractTests(unittest.TestCase):
    def setUp(self):
        material = {'profile': {'application': {'inventory_group': 'pythonapps'}},
                    'lightwell': {'sha256': 'b' * 64}, 'signing_key_sha256': 'c' * 64}
        self.values = {'awx_workflow_job_id': 10, 'awx_workflow_job_name': 'invoice_promote',
                       'invoice_candidate_sha': 'a' * 40, 'invoice_target_group': 'pythonapps',
                       'lightwell_release_sha256': 'd' * 64, 'invoice_material': material,
                       'invoice_release_contract': {'schema_version': 1, 'source_revision': 'a' * 40,
                        'wheel_sha256': 'b' * 64, 'release_manifest_sha256': 'd' * 64,
                        'material_sha256': hashlib.sha256(json.dumps(material, sort_keys=True).encode()).hexdigest()}}
        self.tasks = yaml.safe_load((ROOT / 'playbooks/tasks/validate-release-contract.yml').read_text())

    def check(self, values, passes):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'contract.yml'
            path.write_text(yaml.safe_dump([{'name': 'Test production contract before guest access', 'hosts': 'localhost',
                'connection': 'local', 'gather_facts': False, 'tasks': self.tasks}]))
            result = subprocess.run([shutil.which('ansible-playbook'), '-i', 'localhost,', str(path), '-e', json.dumps(values)],
                                    capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode == 0, passes, result.stdout + result.stderr)

    def test_exact_contract_passes(self):
        self.check(self.values, True)

    def test_changed_material_after_last_workflow_gate_fails(self):
        for field in ['profile', 'lightwell', 'signing_key_sha256']:
            with self.subTest(field=field):
                v = copy.deepcopy(self.values)
                if field == 'profile': v['invoice_material']['profile']['changed'] = True
                if field == 'lightwell': v['invoice_material']['lightwell']['sha256'] = 'f' * 64
                if field == 'signing_key_sha256': v['invoice_material']['signing_key_sha256'] = 'f' * 64
                self.check(v, False)

    def test_direct_job_launch_without_workflow_context_fails(self):
        self.values.pop('awx_workflow_job_id')
        self.check(self.values, False)

    def test_changed_source_lock_or_host_group_fails(self):
        for field, changed in [('invoice_candidate_sha', 'f' * 40), ('lightwell_release_sha256', 'f' * 64),
                               ('invoice_target_group', 'webapps')]:
            v = copy.deepcopy(self.values)
            v[field] = changed
            self.check(v, False)

    def test_guards_run_before_guest_connection(self):
        tasks = yaml.safe_load((ROOT / 'playbooks/deploy-invoice.yml').read_text())[0]['tasks']
        names = [t['name'] for t in tasks]
        self.assertLess(names.index('Require the approved immutable production contract before connecting to guests'),
                        names.index('Wait for the RHEL guest connection'))


if __name__ == '__main__':
    unittest.main()
