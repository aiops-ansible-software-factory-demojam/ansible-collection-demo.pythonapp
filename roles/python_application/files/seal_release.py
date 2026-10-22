#!/usr/bin/env python3
"""Seal and verify a completed release without modifying it during reuse."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat

SEAL = '.release-seal.json'


def inventory(root):
    """Record bytes, permissions and link targets without following links."""
    result = {}
    for parent, directories, files in os.walk(root, followlinks=False):
        for name in sorted(directories + files):
            path = Path(parent) / name
            relative = path.relative_to(root).as_posix()
            if relative == SEAL:
                continue
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode):
                result[relative] = {'link': os.readlink(path)}
            elif stat.S_ISDIR(mode):
                result[relative] = {'directory_mode': stat.S_IMODE(mode)}
            elif stat.S_ISREG(mode):
                digest = hashlib.sha256()
                with path.open('rb') as stream:
                    for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                        digest.update(chunk)
                result[relative] = {'sha256': digest.hexdigest(), 'mode': stat.S_IMODE(mode)}
            else:
                raise ValueError('Unexpected release file type: ' + relative)
    return result


def create(root):
    """Write a seal exactly once after preparation has succeeded."""
    contents = inventory(root)
    with (root / SEAL).open('x') as stream:
        json.dump(contents, stream, sort_keys=True)
        stream.write('\n')
    (root / SEAL).chmod(0o644)


def verify(root):
    """Fail on missing seals, changed files, deleted files or extra files."""
    expected = json.loads((root / SEAL).read_text())
    if inventory(root) != expected:
        raise ValueError('Release contents have changed; refusing to reuse or overwrite this release.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['create', 'verify'])
    parser.add_argument('root', type=Path)
    args = parser.parse_args()
    try:
        {'create': create, 'verify': verify}[args.operation](args.root)
    except (OSError, ValueError) as error:
        parser.exit(1, str(error) + '\n')


if __name__ == '__main__':
    main()
