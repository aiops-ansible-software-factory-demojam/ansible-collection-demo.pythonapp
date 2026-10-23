"""Exercise the real source guard in isolated AAP-like and Git workspaces."""
import copy
import json
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
    "Reject modified or untracked deployment source",
}


class SourceRevisionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="invoice-source-check-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / "playbooks").mkdir()
        self.ansible = shutil.which("ansible-playbook")
        self.assertIsNotNone(self.ansible, "Run in an Ansible execution environment")
        source = yaml.safe_load((ROOT / "playbooks/tasks/validate-source.yml").read_text())
        self.tasks = [copy.deepcopy(task) for task in source if task["name"] in SOURCE_TASKS]
        self.assertEqual(len(self.tasks), len(SOURCE_TASKS))
        play = [{"name": "Check the invoice source contract", "hosts": "localhost",
                 "connection": "local", "gather_facts": False, "tasks": self.tasks}]
        self.playbook = self.root / "playbooks/check.yml"
        self.playbook.write_text(yaml.safe_dump(play, sort_keys=False))

    def run_guard(self, variables, passes):
        result = subprocess.run([self.ansible, "-i", "localhost,", str(self.playbook),
                                 "--extra-vars", json.dumps(variables)],
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
        subprocess.run(["git", "-C", str(self.root), "add", "playbooks/check.yml"], check=True)
        subprocess.run(["git", "-C", str(self.root), "-c", "user.name=Fixture",
                        "-c", "user.email=fixture@example.test", "commit", "-qm", "guard fixture"], check=True)
        return subprocess.check_output(["git", "-C", str(self.root), "rev-parse", "HEAD"], text=True).strip()

    def test_direct_git_revision_matches(self):
        self.run_guard({"invoice_candidate_sha": self.git_commit()}, True)

    def test_modified_tracked_source_fails(self):
        sha = self.git_commit()
        self.playbook.write_text(self.playbook.read_text() + "\n# modified source\n")
        self.run_guard({"invoice_candidate_sha": sha}, False)

    def test_untracked_source_fails(self):
        sha = self.git_commit()
        (self.root / "unreviewed.py").write_text("unreviewed = True\n")
        self.run_guard({"invoice_candidate_sha": sha}, False)

    def test_direct_git_revision_mismatch_fails(self):
        self.git_commit()
        self.run_guard({"invoice_candidate_sha": "b" * 40}, False)


if __name__ == "__main__":
    unittest.main()
