"""Verify package identity from actual wheel metadata, independently of filenames."""
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('verifier', ROOT / 'roles/python_application/files/verify_artifact.py')
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)


class ArtifactIdentityTests(unittest.TestCase):
    def check_fixture(self, name, expected_name, requirements=''):
        with tempfile.TemporaryDirectory() as directory:
            wheel = Path(directory) / 'fixture-1.0-py3-none-any.whl'
            with zipfile.ZipFile(wheel, 'w') as archive:
                archive.writestr('fixture-1.0.dist-info/METADATA', f'Name: {name}\nVersion: 1.0\n{requirements}')
            digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
            return verifier.verify({'package': expected_name, 'approved_package': expected_name,
                                    'version': '1.0', 'approved_version': '1.0', 'filename': wheel.name,
                                    'sha256': digest, 'approved_sha256': digest,
                                    'compatible_wheels': [wheel.name], 'channel': 'baseline'}, wheel)

    def test_two_distribution_names_use_same_verifier(self):
        for package in ['PyPDF2', 'sqlparse']:
            with self.subTest(package=package):
                self.assertFalse(self.check_fixture(package, package)['signature_verified'])

    def test_metadata_substitution_rejected(self):
        with self.assertRaisesRegex(ValueError, 'distribution identity'):
            self.check_fixture('different-package', 'sqlparse')

    def test_normalized_distribution_identity(self):
        self.check_fixture('example_package', 'example-package')

    def test_required_dependency_is_not_silently_ignored(self):
        with self.assertRaisesRegex(ValueError, 'transitive dependencies'):
            self.check_fixture('fixture', 'fixture', 'Requires-Dist: another-package>=1\n')

    def test_unselected_extra_does_not_require_network_resolution(self):
        self.check_fixture('fixture', 'fixture', 'Requires-Dist: another-package; extra == "optional"\n')


if __name__ == '__main__':
    unittest.main()
