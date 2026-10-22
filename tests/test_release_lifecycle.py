"""Exercise release integrity and real Ansible check mode without services or downloads."""
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('seal', ROOT / 'roles/python_application/files/seal_release.py')
seal = importlib.util.module_from_spec(spec)
spec.loader.exec_module(seal)


class ReleaseSealTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'app').mkdir()
        (self.root / 'app/program.py').write_text('reviewed code\n')
        (self.root / 'interpreter').symlink_to('/usr/bin/python3')
        seal.create(self.root)

    def test_unchanged_release_is_reusable_without_writes(self):
        before = {str(p): p.lstat().st_mtime_ns for p in self.root.rglob('*')}
        seal.verify(self.root)
        self.assertEqual(before, {str(p): p.lstat().st_mtime_ns for p in self.root.rglob('*')})

    def test_modified_files_are_rejected(self):
        (self.root / 'app/program.py').write_text('unreviewed code\n')
        with self.assertRaises(ValueError):
            seal.verify(self.root)

    def test_extra_files_are_rejected(self):
        (self.root / 'app/extra.py').write_text('extra')
        with self.assertRaises(ValueError):
            seal.verify(self.root)

    def test_missing_files_are_rejected(self):
        (self.root / 'app/program.py').unlink()
        with self.assertRaises(ValueError):
            seal.verify(self.root)

    def test_changed_symlink_targets_are_rejected(self):
        (self.root / 'interpreter').unlink()
        (self.root / 'interpreter').symlink_to('/usr/bin/false')
        with self.assertRaises(ValueError):
            seal.verify(self.root)

    def test_seal_cannot_be_replaced_by_creation(self):
        with self.assertRaises(FileExistsError):
            seal.create(self.root)


class ReleaseCheckModeTests(unittest.TestCase):
    def setUp(self):
        # The public role deliberately confines production releases to /opt.
        self.tmp = tempfile.TemporaryDirectory(prefix='invoice-role-review-', dir='/opt')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / 'source'
        self.source.mkdir()
        (self.source / 'program.py').write_text('reviewed code\n')
        self.release_root = self.root
        self.sha = 'a' * 64
        self.revision = 'b' * 40
        self.release = self.release_root / 'releases' / (self.sha + '-' + self.revision)
        self.variables = {
            'python_application_root': str(self.release_root),
            'python_application_source': str(self.source) + '/',
            'python_application_source_revision': self.revision,
            'python_application_probe_argv': ['/usr/bin/true'],
            'python_application_command': ['/usr/bin/true'],
            'python_application_python': shutil.which('python3'),
            'python_application_artifact': {'channel': 'baseline', 'sha256': self.sha,
                                          'filename': 'fixture-1-py3-none-any.whl', 'package': 'fixture',
                                          'version': '1', 'url': 'https://example.test/fixture.whl'},
            'python_application_package': 'fixture',
            'python_application_approved_sha256': self.sha,
            'python_application_approved_version': '1',
            'python_application_compatible_wheels': ['fixture-1-py3-none-any.whl'],
        }

    def run_role(self, passes):
        play = [{'name': 'Review generic release check mode', 'hosts': 'localhost', 'connection': 'local',
                 'gather_facts': False, 'vars': self.variables,
                 'roles': [{'role': str(ROOT / 'roles/python_application')}]}]
        p = self.root / 'check.yml'
        p.write_text(yaml.safe_dump(play, sort_keys=False))
        run = subprocess.run(['ansible-playbook', '-i', 'localhost,', '--check', str(p)],
                             capture_output=True, text=True, timeout=120)
        self.assertEqual(run.returncode == 0, passes, run.stdout + run.stderr)
        self.assertNotIn('undefined variable', run.stdout)
        return run

    def make_release(self):
        app = self.release / 'app'
        shutil.copytree(self.source, app)
        (app / 'program.py').chmod(0o644)
        (app / 'release.json').write_text(json.dumps({'source_revision': self.revision,
                                                     'wheel_sha256': self.sha, 'version': '1'}))
        seal.create(self.release)

    def test_new_release_check_mode_does_not_create_release(self):
        self.run_role(True)
        self.assertFalse((self.release_root / 'releases').exists())

    def test_existing_release_check_mode_preserves_contents(self):
        self.make_release()
        before = seal.inventory(self.release)
        self.run_role(True)
        self.assertEqual(before, seal.inventory(self.release))

    def test_existing_release_drift_is_rejected_without_repair(self):
        self.make_release()
        target = self.release / 'app/program.py'
        target.write_text('drift\n')
        self.run_role(False)
        self.assertEqual(target.read_text(), 'drift\n')

    def test_different_source_is_rejected_without_overwriting_release(self):
        self.make_release()
        (self.source / 'program.py').write_text('different source\n')
        self.run_role(False)
        self.assertEqual((self.release / 'app/program.py').read_text(), 'reviewed code\n')

    def test_failed_preparation_removes_only_new_release(self):
        previous = self.release_root / 'releases/previous'
        previous.mkdir(parents=True)
        (previous / 'marker').write_text('known good')
        current = self.release_root / 'current'
        current.symlink_to(previous)
        variables = dict(self.variables)
        variables['python_application_source'] = str(self.root / 'missing-source') + '/'
        play = [{'name': 'Exercise failed release preparation', 'hosts': 'localhost',
                 'connection': 'local', 'gather_facts': False, 'vars': variables,
                 'tasks': [{'name': 'Prepare a new release', 'ansible.builtin.include_role': {
                     'name': str(ROOT / 'roles/python_application'),
                     'tasks_from': 'prepare-release.yml'}}]}]
        path = self.root / 'failure.yml'
        path.write_text(yaml.safe_dump(play, sort_keys=False))
        result = subprocess.run(['ansible-playbook', '-i', 'localhost,', str(path)],
                                capture_output=True, text=True, timeout=60)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('active release was not changed', result.stdout)
        self.assertFalse(self.release.exists())
        self.assertEqual(current.resolve(), previous)
        self.assertEqual((current / 'marker').read_text(), 'known good')


if __name__ == '__main__':
    unittest.main()
