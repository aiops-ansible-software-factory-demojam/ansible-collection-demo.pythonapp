#!/usr/bin/env python3
"""Source-tree entry point for AAP projects that are not installed collections."""
import argparse
import json
from pathlib import Path
import runpy

policy = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'plugins/module_utils/remediation.py'))
parser = argparse.ArgumentParser()
parser.add_argument('--material', required=True, type=Path)
parser.add_argument('--release', required=True, type=Path)
args = parser.parse_args()
try:
    material = json.loads(args.material.read_text())
    digest = policy['validate_release'](material['profile'], material['lightwell'], json.loads(args.release.read_text()))
    print(json.dumps({'release_sha256': digest}))
except Exception as error:
    parser.exit(1, 'Release policy validation failed: ' + type(error).__name__ + '\n')
