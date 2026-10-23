"""Verify wheel bytes, metadata and Lightwell's PEP 740 provenance with Cosign."""
import argparse
import base64
from email.parser import BytesParser
import hashlib
import json
import re
from pathlib import Path
import subprocess
import tempfile
from urllib.parse import urlsplit
import zipfile


def verify(descriptor, wheel, provenance=None, key=None, key_sha256=None):
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    if digest != descriptor["sha256"] or wheel.name != descriptor["filename"]:
        raise ValueError("Wheel digest or filename differs from the approved descriptor")
    normalize = lambda name: re.sub(r"[-_.]+", "-", name).lower()
    if (normalize(descriptor["package"]) != normalize(descriptor["approved_package"])
            or digest != descriptor["approved_sha256"]
            or descriptor["version"] != descriptor["approved_version"]
            or wheel.name not in descriptor["compatible_wheels"]):
        raise ValueError("Artifact differs from the independent release approval")
    with zipfile.ZipFile(wheel) as archive:
        names = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
        if len(names) != 1:
            raise ValueError("Expected exactly one wheel distribution")
        metadata = BytesParser().parsebytes(archive.read(names[0]))
        from packaging.requirements import Requirement
        for raw in metadata.get_all("Requires-Dist", []):
            requirement = Requirement(raw)
            if requirement.marker is None or requirement.marker.evaluate({"extra": ""}):
                raise ValueError("Required transitive dependencies need a fully locked deployment adapter")
        if normalize(metadata["Name"]) != normalize(descriptor["approved_package"]) or metadata["Version"] != descriptor["version"]:
            raise ValueError("Wheel distribution identity does not match the release")
    channel = descriptor["channel"]
    if channel == "baseline":
        return {"channel": channel, "sha256": digest, "signature_verified": False}
    if channel != "lightwell" or not provenance or not key or not key_sha256:
        raise ValueError("Lightwell provenance and pinned public key are required")
    for field in ("url", "provenance_url"):
        parsed = urlsplit(descriptor[field])
        if parsed.scheme != "https" or parsed.hostname != "packages.redhat.com" or parsed.username or parsed.password:
            raise ValueError("Lightwell metadata must reference the trusted repository")
    if hashlib.sha256(key.read_bytes()).hexdigest() != key_sha256:
        raise ValueError("Signing key differs from the operator-pinned trust root")
    document = json.loads(provenance.read_text())
    envelope = document["attestation_bundles"][0]["attestations"][0]["envelope"]
    dsse = {"payloadType": "application/vnd.in-toto+json", "payload": envelope["statement"], "signatures": [{"sig": envelope["signature"]}]}
    statement = json.loads(base64.b64decode(dsse["payload"], validate=True))
    if statement.get("predicateType") != "https://slsa.dev/provenance/v1":
        raise ValueError("Unexpected provenance predicate")
    if not any(subject.get("digest", {}).get("sha256") == digest for subject in statement.get("subject", [])):
        raise ValueError("Provenance does not describe this wheel")
    with tempfile.TemporaryDirectory(prefix="invoice-provenance-") as directory:
        signature = Path(directory) / "dsse.json"
        signature.write_text(json.dumps(dsse))
        subprocess.run(["cosign", "verify-blob-attestation", "--insecure-ignore-tlog", "--type", "https://slsa.dev/provenance/v1", "--key", str(key), "--signature", str(signature), str(wheel)], check=True, capture_output=True)
    return {"channel": channel, "sha256": digest, "signature_verified": True}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("descriptor", type=Path)
    parser.add_argument("wheel", type=Path)
    parser.add_argument("--provenance", type=Path)
    parser.add_argument("--key")
    parser.add_argument("--key-sha256")
    args = parser.parse_args()
    try:
        result = verify(json.loads(args.descriptor.read_text()), args.wheel, args.provenance, Path(args.key) if args.key else None, args.key_sha256)
        print(json.dumps(result))
    except (ValueError, OSError, KeyError, IndexError, zipfile.BadZipFile, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Artifact verification failed: {type(error).__name__}\n")
