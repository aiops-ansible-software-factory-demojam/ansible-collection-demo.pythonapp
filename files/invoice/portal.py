"""Invoice intake service. Library identity and processing results are real."""
import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from fixtures import invoice_pdf

ROOT = Path(__file__).resolve().parent
SLOTS = threading.BoundedSemaphore(2)
JOBS = []
LOCK = threading.Lock()
DEADLINE = float(os.environ.get("INVOICE_PROCESS_TIMEOUT", "2"))


def release():
    path = ROOT / "release.json"
    details = json.loads(path.read_text()) if path.exists() else {"channel": "development"}
    return {**details, "installed_version": importlib.metadata.version("PyPDF2")}


def process(pdf):
    if not SLOTS.acquire(blocking=False):
        return {"status": "busy", "error": "Processing capacity is occupied"}
    started = time.monotonic()
    try:
        with tempfile.TemporaryDirectory(prefix="invoice-") as directory:
            path = Path(directory) / "invoice.pdf"
            path.write_bytes(pdf)
            try:
                child = subprocess.run(
                    [sys.executable, str(ROOT / "extract.py"), str(path)],
                    capture_output=True, text=True, timeout=DEADLINE, check=False,
                )
                result = json.loads(child.stdout)
                if result.get("status") not in ("completed", "rejected"):
                    raise ValueError("Unexpected worker result")
            except subprocess.TimeoutExpired:
                result = {"status": "timed_out", "error": "The extraction worker exceeded its deadline"}
            except (ValueError, OSError):
                result = {"status": "worker_error", "error": "The extraction worker failed"}
        result.update(elapsed_ms=round((time.monotonic() - started) * 1000), document_sha256=hashlib.sha256(pdf).hexdigest())
        with LOCK:
            JOBS.insert(0, result)
            del JOBS[20:]
        print(json.dumps({"event": "invoice_processed", **result}), flush=True)
        return result
    finally:
        SLOTS.release()


class Handler(BaseHTTPRequestHandler):
    server_version = "InvoicePortal"

    def send(self, status, body, content_type="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/healthz":
            return self.send(200, {"status": "ready"})
        if self.path == "/api/status":
            with LOCK:
                jobs = list(JOBS)
            return self.send(200, {"release": release(), "installed": {"package": "PyPDF2", "version": importlib.metadata.version("PyPDF2")}, "jobs": jobs, "timeout_seconds": DEADLINE})
        files = {"/": ("index.html", "text/html; charset=utf-8"), "/portal.js": ("portal.js", "text/javascript"), "/portal.css": ("portal.css", "text/css")}
        if self.path in files:
            name, kind = files[self.path]
            return self.send(200, (ROOT / name).read_bytes(), kind)
        return self.send(404, {"error": "Unknown endpoint"})

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return self.send(400, {"error": "Invalid content length"})
        if length < 0 or length > 262144:
            return self.send(413, {"error": "Maximum invoice size is 256 KiB"})
        if self.path in ("/api/sample", "/api/regression"):
            if length:
                self.rfile.read(length)
            return self.send(200, process(invoice_pdf(self.path.endswith("regression"))))
        if self.path == "/api/process":
            if not length or self.headers.get("Content-Type", "").split(";")[0] != "application/pdf":
                return self.send(415, {"error": "Send a PDF with Content-Type application/pdf"})
            return self.send(200, process(self.rfile.read(length)))
        return self.send(404, {"error": "Unknown endpoint"})


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.daemon_threads = True
    print(json.dumps({"event": "listening", "port": server.server_port}), flush=True)
    server.serve_forever()
