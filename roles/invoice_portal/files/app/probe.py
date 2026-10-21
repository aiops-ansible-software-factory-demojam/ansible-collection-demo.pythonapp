"""Fail closed on worker errors, wrong artifacts, and incorrect extracted text."""
import argparse
import json
from urllib.request import Request, urlopen


def request(base, path, method="GET"):
    with urlopen(Request(base.rstrip("/") + path, method=method, data=b"" if method == "POST" else None), timeout=15) as response:
        return json.load(response)


def check(base, expect, expected_digest=None):
    details = request(base, "/api/status")
    if expected_digest and details["release"].get("wheel_sha256") != expected_digest:
        raise ValueError("The running release does not match the approved artifact")
    normal = request(base, "/api/sample", "POST")
    regression = request(base, "/api/regression", "POST")
    if normal.get("status") != "completed" or "Invoice INV-1042" not in normal.get("text", ""):
        raise ValueError("Normal invoice processing failed")
    if expect == "vulnerable":
        if regression.get("status") != "timed_out":
            raise ValueError("The baseline did not reproduce the expected vulnerability")
    elif regression.get("status") != "completed" or "Invoice INV-1042" not in regression.get("text", ""):
        raise ValueError("The regression document did not process correctly within the deadline")
    return {"expected": expect, "passed": True, "release": details["release"], "normal": normal, "regression": regression}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("url")
    parser.add_argument("--expect", choices=["vulnerable", "remediated"], required=True)
    parser.add_argument("--expected-wheel-sha256")
    args = parser.parse_args()
    try:
        print(json.dumps(check(args.url, args.expect, args.expected_wheel_sha256)))
    except (ValueError, OSError, KeyError) as error:
        parser.exit(1, f"Invoice verification failed: {error}\n")
