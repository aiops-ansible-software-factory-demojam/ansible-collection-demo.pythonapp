"""Exercise the real source guard in isolated AAP-like and Git workspaces."""
import copy
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
SOURCE_TASKS = {
    "Read the Git revision outside AAP",
    "Select the actual execution revision",
    "Require the execution source to match the approved revision",
    "Record the source revision for deployment evidence",
}


class SourceRevisionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="invoice-source-check-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / "playbooks").mkdir()
        self.ansible = shutil.which("ansible-playbook")
        self.assertIsNotNone(self.ansible, "Run in an Ansible execution environment")
        source = yaml.safe_load((ROOT / "playbooks/invoice.yml").read_text())[0]
        self.tasks = [copy.deepcopy(task) for task in source["pre_tasks"] if task["name"] in SOURCE_TASKS]
        self.assertEqual(len(self.tasks), len(SOURCE_TASKS))

    def run_guard(self, variables, passes):
        play = [{"name": "Check the invoice source contract", "hosts": "localhost",
                 "connection": "local", "gather_facts": False, "vars": variables, "tasks": self.tasks}]
        path = self.root / "playbooks/check.yml"
        path.write_text(yaml.safe_dump(play, sort_keys=False))
        result = subprocess.run([self.ansible, "-i", "localhost,", str(path)],
                                cwd=self.root, text=True, capture_output=True, timeout=60)
        if passes:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, "A mismatched source passed the guard")

    def test_aap_revision_without_git_metadata(self):
        self.run_guard({"awx_job_id": 1, "awx_project_revision": "a" * 40,
                        "invoice_candidate_sha": "a" * 40}, True)

    def test_aap_revision_mismatch_fails(self):
        self.run_guard({"awx_job_id": 1, "awx_project_revision": "a" * 40,
                        "invoice_candidate_sha": "b" * 40}, False)

    def test_missing_aap_revision_fails(self):
        self.run_guard({"awx_job_id": 1, "invoice_candidate_sha": "a" * 40}, False)

    def git_commit(self):
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        subprocess.run(["git", "-C", str(self.root), "-c", "user.name=Fixture",
                        "-c", "user.email=fixture@example.test", "commit", "--allow-empty", "-qm", "fixture"], check=True)
        return subprocess.check_output(["git", "-C", str(self.root), "rev-parse", "HEAD"], text=True).strip()

    def test_direct_git_revision_matches(self):
        self.run_guard({"invoice_candidate_sha": self.git_commit()}, True)

    def test_direct_git_revision_mismatch_fails(self):
        self.git_commit()
        self.run_guard({"invoice_candidate_sha": "b" * 40}, False)


if __name__ == "__main__":
    unittest.main()
