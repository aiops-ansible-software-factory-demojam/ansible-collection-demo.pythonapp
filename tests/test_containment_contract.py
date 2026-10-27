"""Verify containment fails before connecting to any unapproved host/service."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
import yaml
ROOT = Path(__file__).resolve().parents[1]

class ContainmentContractTests(unittest.TestCase):
    def setUp(self):
        profile = {'application': {'inventory_group': 'pythonapps', 'service': 'invoice-portal'},
            'response': {'containment': 'stop_service', 'high_severity_threshold': 7}}
        digest = hashlib.sha256(json.dumps(profile, sort_keys=True).encode()).hexdigest()
        self.values = {'awx_job_id': 12, 'awx_workflow_job_id': 9, 'awx_workflow_job_name': 'invoice_contain',
            'awx_project_revision': 'd' * 40, 'invoice_material': {'profile': profile}, 'python_application_service': 'invoice-portal',
            'invoice_response': {'schema_version': 1, 'source_revision': 'd' * 40, 'route': 'contain', 'affected': True, 'hosts': ['localhost'],
                'incident_key': 'a' * 64, 'profile_sha256': digest, 'cvss_score': 8},
            'invoice_findings': {'incident_key': 'a' * 64, 'hosts': ['localhost'], 'observations': [
                {'host': 'localhost', 'assessment_state': 'affected', 'installed_version': '1.0', 'profile_sha256': digest}]}}

    def check(self, values, passes):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / 'contract.yml'
            f.write_text(yaml.safe_dump([{'name': 'Exercise actual containment scope', 'hosts': 'localhost',
                'connection': 'local', 'gather_facts': False,
                'tasks': yaml.safe_load((ROOT / 'playbooks/tasks/validate-containment.yml').read_text())}]))
            r = subprocess.run(['ansible-playbook', '-i', 'localhost,', str(f), '-e', json.dumps(values)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(r.returncode == 0, passes, r.stdout + r.stderr)

    def test_exact_approved_scope_passes(self): self.check(self.values, True)

    def test_pinned_containment_source_ignores_later_default_project_revision(self):
        self.check(dict(self.values, awx_project_revision='e' * 40, awx_job_scm_branch='d' * 40), True)

    def test_wrong_workflow_service_profile_hosts_or_fixed_observation_is_rejected(self):
        for field in ['workflow', 'service', 'profile', 'hosts', 'state', 'incident', 'source']:
            v = copy.deepcopy(self.values)
            if field == 'source': v['awx_job_scm_branch'] = 'e' * 40
            if field == 'workflow': v['awx_workflow_job_name'] = 'invoice_promote'
            if field == 'service': v['python_application_service'] = 'sshd'
            if field == 'profile': v['invoice_material']['profile']['response']['containment'] = 'manual'
            if field == 'hosts': v['invoice_response']['hosts'] = ['webapp']
            if field == 'state': v['invoice_findings']['observations'][0]['assessment_state'] = 'fixed'
            if field == 'incident': v['invoice_findings']['incident_key'] = 'b' * 64
            with self.subTest(field=field): self.check(v, False)

    def test_scope_and_current_dependency_checks_precede_service_change(self):
        tasks = yaml.safe_load((ROOT / 'playbooks/contain-invoice.yml').read_text())[0]['tasks']
        self.assertIn('ansible.builtin.import_tasks', tasks[0])
        self.assertIn('ansible.builtin.command', tasks[1])
        self.assertIn('ansible.builtin.assert', tasks[2])
        self.assertIn('ansible.builtin.systemd_service', tasks[3])
