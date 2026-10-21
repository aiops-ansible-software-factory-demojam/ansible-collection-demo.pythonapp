"""Compatibility entry point; package-independent verification lives in python_application."""
import runpy
from pathlib import Path

_SHARED = Path(__file__).resolve().parents[2] / "python_application/files/verify_artifact.py"
if __name__ == "__main__":
    runpy.run_path(str(_SHARED), run_name="__main__")
else:
    verify = runpy.run_path(str(_SHARED))["verify"]
