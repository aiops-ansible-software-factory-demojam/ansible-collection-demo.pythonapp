"""Build the actual collection metadata with a deliberately contaminated cache."""
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class CollectionPackagingTests(unittest.TestCase):
    def test_generated_installs_and_external_links_are_not_packaged(self):
        with tempfile.TemporaryDirectory(prefix='collection-packaging-') as directory:
            temp = Path(directory)
            source = temp / 'source'
            source.mkdir()
            for name in ['galaxy.yml', 'README.md', 'LICENSE']:
                shutil.copy2(ROOT / name, source / name)
            cache = source / 'collections/ansible_collections/demo/generated'
            cache.mkdir(parents=True)
            (cache / 'install-state.json').write_text('{}')
            outside = temp / 'outside-source.txt'
            outside.write_text('Must not enter a source artifact\n')
            (cache / 'source-link').symlink_to(outside)
            artifacts = temp / 'artifacts'
            artifacts.mkdir()
            result = subprocess.run(['ansible-galaxy', 'collection', 'build', '--force',
                                     '--output-path', str(artifacts)], cwd=source,
                                    capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            paths = list(artifacts.glob('*.tar.gz'))
            self.assertEqual(len(paths), 1)
            with tarfile.open(paths[0]) as archive:
                names = archive.getnames()
                self.assertFalse(any(name == 'collections' or name.startswith('collections/') for name in names), names)
                self.assertIn('README.md', names)


if __name__ == '__main__':
    unittest.main()
