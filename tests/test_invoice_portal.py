"""Exercise real stock PyPDF2, bounded extraction and the verification boundary."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "roles/invoice/files/invoice"
sys.path.insert(0, str(APP))
from fixtures import invoice_pdf
from probe import check, request


class InvoicePortalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = subprocess.Popen([sys.executable, str(APP / "portal.py"), "--host", "127.0.0.1", "--port", "0"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        event = json.loads(cls.server.stdout.readline())
        cls.url = f'http://127.0.0.1:{event["port"]}'

    @classmethod
    def tearDownClass(cls):
        cls.server.terminate()
        cls.server.wait(timeout=5)
        cls.server.stdout.close()

    def test_normal_invoice_extracts_expected_business_data(self):
        result = request(self.url, "/api/sample", "POST")
        self.assertEqual(result["status"], "completed")
        self.assertIn("INV-1042", result["text"])
        self.assertIn("USD 125.00", result["text"])

    def test_real_baseline_reproduces_the_cve_with_a_bounded_timeout(self):
        result = check(self.url, "vulnerable")
        self.assertEqual(result["regression"]["status"], "timed_out")
        self.assertLess(result["regression"]["elapsed_ms"], 6000)
        self.assertEqual(request(self.url, "/healthz")["status"], "ready")

    def test_unpatched_release_cannot_pass_remediation(self):
        with self.assertRaisesRegex(ValueError, "regression document"):
            check(self.url, "remediated")

    def test_wrong_artifact_identity_fails_before_processing(self):
        with self.assertRaisesRegex(ValueError, "approved artifact"):
            check(self.url, "remediated", "0" * 64)

    def test_rejected_document_is_not_a_successful_invoice(self):
        with urlopen(Request(self.url + "/api/process", data=b"not a pdf", headers={"Content-Type": "application/pdf"}), timeout=10) as response:
            result = json.load(response)
        self.assertEqual(result["status"], "rejected")

    def test_large_upload_is_rejected(self):
        with self.assertRaises(HTTPError) as error:
            urlopen(Request(self.url + "/api/process", data=b"x" * 262145, headers={"Content-Type": "application/pdf"}), timeout=10)
        self.assertEqual(error.exception.code, 413)

    def test_fixtures_are_reproducible_and_distinct(self):
        self.assertEqual(invoice_pdf(), invoice_pdf())
        self.assertNotEqual(invoice_pdf(), invoice_pdf(True))


class ArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("verify_artifact", ROOT / "roles/python_application/files/verify_artifact.py")
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def test_substituted_wheel_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "substituted.whl"
            path.write_bytes(b"substituted artifact")
            with self.assertRaisesRegex(ValueError, "digest"):
                self.module.verify({"sha256": "0" * 64, "filename": path.name}, path)


if __name__ == "__main__":
    unittest.main()
