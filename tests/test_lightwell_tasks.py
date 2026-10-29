"""Exercise the actual built-in Ansible tasks against a local Lightwell fixture."""
import copy
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import threading
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
REVISION = 'a' * 40


def profile():
    return {'schema_version': 1, 'application': {'id': 'app', 'release_manifest': 'releases/app.json'},
            'environment': 'test', 'package': {'name': 'PyPDF2'}, 'runtime': {'wheel_tags': ['py3-none-any']},
            'advisories': [{'id': 'CVE-TEST', 'source': 'fixture', 'affected_versions': ['3.0.1'], 'fixed_versions': ['3.0.1+rhlw.1']}],
            'validation': {'scenario': 'invoice_portal', 'business_checks': [{'path': '/healthz'}]}}


def artifact():
    return {'channel': 'lightwell', 'package': 'PyPDF2', 'version': '3.0.1+rhlw.1',
            'filename': 'pypdf2-3.0.1+rhlw.1-1-py3-none-any.whl', 'sha256': 'b' * 64,
            'url': 'https://packages.redhat.com/wheel.whl', 'provenance_url': 'https://packages.redhat.com/provenance',
            'cves': ['CVE-TEST']}


def bootstrap_material():
    """Carry the complete operator context supplied by demo bootstrap."""
    policy = profile()
    policy['application'].update(inventory_group='pythonapps', repository='demo-owner/pythonapp',
        python_executable='/opt/invoice-portal/current/venv/bin/python',
        status_path='/api/status', service='invoice-portal')
    policy['runtime'].update(python='3.12', requires_python=['>=3.6'])
    policy['advisories'][0].update(cvss_score=6.2, fix_evidence='Vendor advisory feed')
    policy['validation'].update(adapter='invoice', baseline_expectation='vulnerable',
        regression={'path': '/api/regression', 'method': 'POST', 'vulnerable_status': 'timed_out',
                    'remediated_status': 'completed', 'text_contains': 'Invoice INV-1042'})
    policy['response'] = {'high_severity_threshold': 7.0, 'containment': 'stop_service', 'review_in_days': 30}
    selected = artifact()
    selected.update(base_version='3.0.1', advisory_revision=REVISION,
                    advisories=['RHLW-TEST'], advisory_mapping_available=True)
    return {'profile': policy,
            'baseline': {'channel': 'baseline', 'package': 'PyPDF2', 'base_version': '3.0.1',
                         'version': '3.0.1', 'filename': 'pypdf2-3.0.1-py3-none-any.whl',
                         'url': 'https://example.test/pypdf2.whl', 'sha256': 'c' * 64,
                         'cves': ['CVE-TEST']},
            'lightwell': selected, 'repository_username': 'fixture',
            'repository_token': 'PRIVATE-FIXTURE-TOKEN', 'signing_key_sha256': 'd' * 64}


def advisory():
    return {'id': 'RHLW-TEST', 'upstream': ['CVE-TEST'], 'affected': [
        {'package': {'name': 'pypdf2', 'ecosystem': 'Red Hat Lightwell:PyPI'},
         'ranges': [{'events': [{'introduced': '0'}, {'fixed': '3.0.1+rhlw.1'}]}],
         'database_specific': {'lightwell': {'backport_base_version': '3.0.1', 'remediated_version': '3.0.1+rhlw.1',
                                           'repository_url': 'https://packages.redhat.com/lightwell/python/remediated/'}}}]}


def catalog():
    a = artifact()
    return {'name': 'pypdf2', 'meta': {'api-version': '1.1'}, 'files': [
        {'filename': a['filename'], 'hashes': {'sha256': a['sha256']}, 'url': a['url'],
         'provenance': a['provenance_url'], 'yanked': False}]}


class LightwellTaskTests(unittest.TestCase):
    def run_tasks(self, operation, *, material=None, records=None, index=None, release=None, success=True, local_release=False, **extra):
        material = copy.deepcopy(material or {'profile': profile(), 'baseline': {'version': '3.0.1'}, 'lightwell': {},
                                             'repository_username': 'fixture', 'repository_token': 'PRIVATE-FIXTURE-TOKEN'})
        records = [advisory()] if records is None else records
        index = index or catalog()
        archive_bytes = io.BytesIO()
        with tarfile.open(fileobj=archive_bytes, mode='w:gz') as archive:
            for i, record in enumerate(records):
                data = json.dumps(record).encode()
                entry = tarfile.TarInfo(f'lightwell-osv-{REVISION}/advisories/record-{i}.json')
                entry.size = len(data)
                archive.addfile(entry, io.BytesIO(data))
            if not records:
                entry = tarfile.TarInfo(f'lightwell-osv-{REVISION}/advisories/empty.json')
                data = b'{"id":"RHLW-EMPTY","affected":[]}'
                entry.size = len(data)
                archive.addfile(entry, io.BytesIO(data))
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                data = archive_bytes.getvalue() if self.path == '/feed' else json.dumps(index).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/gzip' if self.path == '/feed' else 'application/vnd.pypi.simple.v1+json')
                self.end_headers()
                self.wfile.write(data)
            def log_message(self, *args):
                pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                temp = Path(directory)
                collection = temp / 'collections/ansible_collections/demo'
                collection.mkdir(parents=True)
                (collection / 'pythonapp').symlink_to(ROOT)
                (temp / 'release.json').write_text(json.dumps(release or {}))
                variables = {'lightwell_material': material, 'lightwell_installed': {'package': 'PyPDF2', 'version': '3.0.1'},
                             'lightwell_release_file': str(temp / 'release.json'), 'lightwell_advisory_revision': REVISION,
                             'lightwell_advisory_archive': f'http://127.0.0.1:{server.server_port}/feed',
                             'lightwell_index_origin': f'http://127.0.0.1:{server.server_port}', **extra}
                if operation == 'prepare':
                    variables['lightwell_material_output'] = str(temp / 'prepared.json')
                (temp / 'vars.json').write_text(json.dumps(variables))
                result_expression = {'discover': 'lightwell_selection', 'assess': 'lightwell_finding', 'release': 'lightwell_release_sha256', 'prepare': 'lightwell_selection'}[operation]
                play = [{'name': 'Test Lightwell tasks', 'hosts': 'localhost', 'connection': 'local', 'gather_facts': False,
                         'tasks': [{'name': 'Run the actual collection role', 'ansible.builtin.include_role':
                                    {'name': 'demo.pythonapp.lightwell', 'tasks_from': operation}},
                                   {'name': 'Write the public result', 'ansible.builtin.copy':
                                    {'content': '{{ ' + result_expression + ' | to_json }}', 'dest': str(temp / 'result.json'), 'mode': '0600'}}]}]
                run_directory = ROOT
                if local_release:
                    raw = temp / 'raw'
                    (raw / 'playbooks').mkdir(parents=True)
                    (raw / 'releases').mkdir()
                    (raw / 'roles').symlink_to(ROOT / 'roles')
                    (raw / 'ansible.cfg').write_text('[defaults]\nroles_path = ./roles\n')
                    (raw / 'releases/app.json').write_text(json.dumps(release))
                    # A conflicting installed copy must never supply deployment policy.
                    (collection / 'pythonapp').unlink()
                    installed = collection / 'pythonapp/roles/lightwell/tasks'
                    installed.mkdir(parents=True)
                    (installed / 'release.yml').write_text('- name: Reject the wrong installed policy\n  ansible.builtin.fail:\n    msg: WRONG_INSTALLED_COLLECTION\n')
                    source = yaml.safe_load((ROOT / 'playbooks/deploy-invoice.yml').read_text())[0]
                    task = next(copy.deepcopy(t) for t in source['tasks']
                                if t.get('ansible.builtin.include_role', {}).get('tasks_from') == 'release')
                    play[0]['tasks'][0] = task
                    variables.update(invoice_material=material, invoice_release_channel='lightwell')
                    (temp / 'vars.json').write_text(json.dumps(variables))
                    run_directory = raw
                play_path = (run_directory / 'playbooks/check.json') if local_release else (temp / 'play.json')
                play_path.write_text(json.dumps(play))
                env = {**os.environ, 'ANSIBLE_COLLECTIONS_PATH': str(temp / 'collections'), 'ANSIBLE_NOCOLOR': '1'}
                result = subprocess.run([shutil.which('ansible-playbook'), '-i', 'localhost,', str(play_path),
                                         '-e', '@' + str(temp / 'vars.json')], env=env, cwd=run_directory, capture_output=True, text=True, timeout=90)
                self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
                self.assertNotIn('PRIVATE-FIXTURE-TOKEN', result.stdout + result.stderr)
                if operation == 'prepare' and success:
                    prepared = temp / 'prepared.json'
                    self.assertEqual(prepared.stat().st_mode & 0o777, 0o600)
                    material_output = json.loads(prepared.read_text())
                    self.assertEqual(material_output['lightwell']['sha256'], 'b' * 64)
                    self.assertEqual(material_output['repository_token'], 'PRIVATE-FIXTURE-TOKEN')
                    for field in ['application', 'runtime', 'validation', 'response']:
                        self.assertEqual(material_output['profile'].get(field), material['profile'].get(field))
                    self.assertEqual(material_output['baseline'], material['baseline'])
                    self.assertEqual(material_output.get('signing_key_sha256'), material.get('signing_key_sha256'))
                return json.loads((temp / 'result.json').read_text()) if success else None
        finally:
            server.shutdown()
            server.server_close()
            worker.join()

    def test_prepare_discovers_and_privately_writes_material(self):
        self.assertEqual(self.run_tasks('prepare')['sha256'], 'b' * 64)

    def test_prepare_accepts_and_preserves_complete_bootstrap_material(self):
        self.assertEqual(self.run_tasks('prepare', material=bootstrap_material())['sha256'], 'b' * 64)

    def test_raw_aap_checkout_uses_local_release_policy_over_installed_collection(self):
        material = {'profile': profile(), 'baseline': {'version': '3.0.1'}, 'lightwell': artifact(),
                    'repository_token': 'PRIVATE-FIXTURE-TOKEN'}
        release = {'schema_version': 1, 'application': 'app', 'channel': 'lightwell',
                   'dependencies': [{'package': 'PyPDF2', 'version': '3.0.1+rhlw.1', 'sha256': 'b' * 64}]}
        self.assertRegex(self.run_tasks('release', material=material, release=release, local_release=True), r'^[0-9a-f]{64}$')

    def test_discovers_fix_without_preselected_artifact_or_fixed_version_mapping(self):
        p = profile()
        p['advisories'][0].pop('fixed_versions')
        result = self.run_tasks('discover', material={'profile': p, 'baseline': {'version': '3.0.1'}, 'lightwell': {},
                                                     'repository_username': 'fixture', 'repository_token': 'PRIVATE-FIXTURE-TOKEN'})
        self.assertEqual(result['version'], '3.0.1+rhlw.1')
        self.assertEqual(result['sha256'], 'b' * 64)
        self.assertEqual(result['cves'], ['CVE-TEST'])

    def test_another_package_uses_the_same_tasks(self):
        p = profile()
        p['package']['name'] = 'sqlparse'
        record = advisory()
        record['affected'][0]['package']['name'] = 'sqlparse'
        index = catalog()
        index['name'] = 'sqlparse'
        index['files'][0]['filename'] = index['files'][0]['filename'].replace('pypdf2-', 'sqlparse-')
        result = self.run_tasks('discover', records=[record], index=index,
            material={'profile': p, 'baseline': {'version': '3.0.1'}, 'lightwell': {},
                      'repository_username': 'fixture', 'repository_token': 'PRIVATE-FIXTURE-TOKEN'})
        self.assertEqual(result['package'], 'sqlparse')

    def test_filters_hostile_unhashed_yanked_and_incompatible_catalog_files(self):
        index = catalog()
        good = index['files'][0]
        for change in [{'url': 'https://attacker.test/wheel.whl'}, {'url': 'https://user:pass@packages.redhat.com/wheel.whl'},
                       {'provenance': 'https://attacker.test/provenance'}, {'hashes': {}}, {'yanked': True},
                       {'filename': 'pypdf2-3.0.1+rhlw.1-cp313-cp313-linux_aarch64.whl'}]:
            index['files'].append({**good, **change})
        self.assertEqual(self.run_tasks('discover', index=index)['sha256'], 'b' * 64)

    def test_unapproved_python_requirement_is_not_selected(self):
        index = catalog()
        index['files'][0]['requires-python'] = '>=3.13'
        self.assertEqual(self.run_tasks('discover', index=index), {})

    def test_wrong_package_or_base_in_advisory_cannot_supply_fix_evidence(self):
        record = advisory()
        record['affected'][0]['package']['name'] = 'unrelated'
        self.assertEqual(self.run_tasks('discover', records=[record]), {})

    def test_missing_or_withdrawn_advisory_does_not_authorize_a_fix(self):
        record = advisory()
        record['withdrawn'] = '2026-01-01T00:00:00Z'
        self.assertEqual(self.run_tasks('discover', records=[record]), {})

    def test_partial_cve_coverage_does_not_authorize_a_fix(self):
        record = advisory()
        record['upstream'] = ['ANOTHER-CVE']
        self.assertEqual(self.run_tasks('discover', records=[record]), {})

    def test_changed_base_version_does_not_authorize_a_fix(self):
        self.assertEqual(self.run_tasks('discover', lightwell_base_version='1.0'), {})

    def test_ambiguous_wheels_require_an_explicit_pin(self):
        index = catalog()
        index['files'].append({**index['files'][0], 'filename': 'pypdf2-3.0.1+rhlw.1-2-py3-none-any.whl'})
        self.run_tasks('discover', index=index, success=False)

    def test_changed_approval_pin_is_rejected(self):
        self.run_tasks('discover', material={'profile': profile(), 'baseline': {'version': '3.0.1'},
                                           'repository_username': 'fixture', 'repository_token': 'PRIVATE-FIXTURE-TOKEN',
                                           'lightwell': {**artifact(), 'sha256': 'c' * 64}}, success=False)

    def test_unknown_version_stays_unknown_and_no_candidate_stays_unavailable(self):
        result = self.run_tasks('assess', lightwell_installed={'package': 'PyPDF2', 'version': '9.0'})
        self.assertEqual(result['assessment_state'], 'unknown')
        self.assertFalse(result['fix_available'])

    def test_incident_identity_is_compatible_and_survives_fix(self):
        m = {'profile': profile(), 'lightwell': artifact()}
        affected = self.run_tasks('assess', material=m)
        fixed = self.run_tasks('assess', material=m, lightwell_installed={'package': 'PyPDF2', 'version': artifact()['version']})
        self.assertTrue(affected['fix_available'])
        self.assertEqual(fixed['assessment_state'], 'fixed')
        identity = {'application': 'app', 'environment': 'test', 'package': 'pypdf2', 'advisories': ['CVE-TEST']}
        self.assertEqual(affected['incident_key'], hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest())
        self.assertEqual(affected['incident_key'], fixed['incident_key'])

    def test_preselected_wheel_must_match_the_runtime(self):
        selected = artifact()
        selected['filename'] = 'pypdf2-3.0.1+rhlw.1-cp313-cp313-linux_aarch64.whl'
        self.run_tasks('assess', material={'profile': profile(), 'lightwell': selected}, success=False)

    def test_release_hash_is_canonical_and_substitution_fails(self):
        a = artifact()
        release = {'schema_version': 1, 'application': 'app', 'channel': 'lightwell',
                   'dependencies': [{k: a[k] for k in ['package', 'version', 'sha256']}]}
        m = {'profile': profile(), 'lightwell': a}
        expected = hashlib.sha256(json.dumps(release, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        self.assertEqual(self.run_tasks('release', material=m, release=release), expected)
        release['dependencies'][0]['sha256'] = 'c' * 64
        self.run_tasks('release', material=m, release=release, success=False)

    def test_multiple_dependencies_are_not_silently_ignored(self):
        a = artifact()
        self.run_tasks('release', material={'profile': profile(), 'lightwell': a},
                       release={'schema_version': 1, 'application': 'app', 'channel': 'lightwell',
                                'dependencies': [a, a]}, success=False)


if __name__ == '__main__':
    unittest.main()
