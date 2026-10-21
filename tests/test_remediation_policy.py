"""Behavioral policy tests: different packages, advisory evidence and hostile inputs."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('policy', ROOT / 'plugins/module_utils/remediation.py')
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


def profile(package='PyPDF2', version='3.0.1', fixed='3.0.1+rhlw.1'):
    return {'schema_version': 1, 'application': {'id': 'app', 'release_manifest': 'releases/app.json'},
            'environment': 'test', 'package': {'name': package}, 'runtime': {'wheel_tags': ['py3-none-any']},
            'advisories': [{'id': 'TEST-ADVISORY', 'source': 'operator-reviewed-fixture',
                            'affected_versions': [version], 'fixed_versions': [fixed]}],
            'validation': {'scenario': 'application', 'business_checks': [{'path': '/healthz', 'status': 'ready'}]}}


def artifact(package='PyPDF2', version='3.0.1+rhlw.1'):
    filename = f'{package.lower()}-{version}-1-py3-none-any.whl'
    return {'channel': 'lightwell', 'package': package, 'version': version, 'filename': filename,
            'sha256': 'a' * 64, 'url': 'https://packages.redhat.com/wheels/' + filename,
            'provenance_url': 'https://packages.redhat.com/provenance', 'cves': ['TEST-ADVISORY']}


class PolicyTests(unittest.TestCase):
    def test_same_workflow_handles_two_packages_without_code_changes(self):
        for package, base, fixed in [('PyPDF2', '3.0.1', '3.0.1+rhlw.1'),
                                     ('sqlparse', '0.5.5', '0.5.5+test.1')]:
            with self.subTest(package=package):
                config = profile(package, base, fixed)
                selected = artifact(package, fixed)
                finding = policy.assess(config, {'package': package, 'version': base}, selected)
                self.assertTrue(finding['affected'])
                self.assertTrue(finding['fix_available'])
                release = {'schema_version': 1, 'application': 'app', 'channel': 'lightwell',
                           'dependencies': [{k: selected[k] for k in ('package', 'version', 'sha256')}]}
                self.assertEqual(len(policy.validate_release(config, selected, release)), 64)

    def test_unknown_versions_are_not_declared_vulnerable(self):
        finding = policy.assess(profile(), {'package': 'PyPDF2', 'version': '9.0'})
        self.assertFalse(finding['affected'])
        self.assertEqual(finding['assessment_state'], 'unknown')
        self.assertFalse(finding['fix_available'])

    def test_incident_identity_survives_fix_and_changes_between_environments(self):
        config = profile()
        before = policy.assess(config, {'package': 'PyPDF2', 'version': '3.0.1'})
        after = policy.assess(config, {'package': 'PyPDF2', 'version': '3.0.1+rhlw.1'})
        self.assertEqual(before['incident_key'], after['incident_key'])
        self.assertFalse(after['affected'])
        config['environment'] = 'another-environment'
        other = policy.assess(config, {'package': 'PyPDF2', 'version': '3.0.1'})
        self.assertNotEqual(before['incident_key'], other['incident_key'])

    def test_signed_or_available_does_not_mean_fixed(self):
        selected = artifact(version='3.0.1+unmapped')
        with self.assertRaisesRegex(ValueError, 'evidence'):
            policy.approve_artifact(profile(), selected)

    def test_incompatible_native_wheel_is_rejected(self):
        selected = artifact()
        selected['filename'] = 'pypdf2-3.0.1+rhlw.1-cp313-cp313-manylinux_2_28_aarch64.whl'
        with self.assertRaisesRegex(ValueError, 'incompatible'):
            policy.approve_artifact(profile(), selected)

    def test_wrong_package_and_embedded_credentials_are_rejected(self):
        for field, value in [('package', 'unrelated'), ('url', 'https://user:password@packages.redhat.com/x')]:
            selected = artifact()
            selected[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                policy.approve_artifact(profile(), selected)

    def test_catalog_filters_wrong_origins_missing_digests_and_incompatible_wheels(self):
        parser = policy.Catalog('https://packages.redhat.com/simple/pypdf2/', profile())
        name = artifact()['filename']
        parser.feed(f'<a href="https://packages.redhat.com/w/{name}#sha256={"a"*64}">ok</a>'
                    f'<a href="https://attacker.test/{name}#sha256={"a"*64}">wrong origin</a>'
                    f'<a href="https://packages.redhat.com/w/{name}">no digest</a>')
        self.assertEqual(len(parser.candidates), 1)
        self.assertTrue(parser.candidates[0]['advisory_mapping_available'])

    def test_lock_substitution_is_rejected(self):
        selected = artifact()
        release = {'schema_version': 1, 'application': 'app', 'channel': 'lightwell',
                   'dependencies': [{k: selected[k] for k in ('package', 'version', 'sha256')}]}
        release['dependencies'][0]['sha256'] = 'b' * 64
        with self.assertRaisesRegex(ValueError, 'lock differs'):
            policy.validate_release(profile(), selected, release)

    def test_partial_advisory_coverage_is_not_a_complete_fix(self):
        config = profile()
        config['advisories'].append({'id': 'TEST-OTHER', 'source': 'fixture-only',
                                    'affected_versions': ['3.0.1'], 'fixed_versions': ['another-version']})
        with self.assertRaisesRegex(ValueError, 'evidence'):
            policy.approve_artifact(config, artifact())

    def test_dependency_closure_is_not_silently_ignored(self):
        selected = artifact()
        release = {'schema_version': 1, 'application': 'app', 'channel': 'lightwell',
                   'dependencies': [{k: selected[k] for k in ('package', 'version', 'sha256')}] * 2}
        with self.assertRaisesRegex(ValueError, 'dependency closures'):
            policy.validate_release(profile(), selected, release)


if __name__ == '__main__':
    unittest.main()
