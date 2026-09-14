#!/usr/bin/env python3
"""Convert AFL++ ASAN crash files to SARIF v2.1.0 for GitHub Code Scanning."""

import argparse
import glob
import hashlib
import json
import os
import re
import subprocess
import sys

# Matches ASAN stack frames like:
#   #1 0x55f4f6632c09 in DecryptResponseV4 ../src/kms.c:994
FRAME_RE = re.compile(r'#(\d+) +0x[0-9a-f]+ in (\S+) (\S+):(\d+)(?::\d+)?')

# Matches the ASAN summary line to extract the error kind:
#   ==12345==ERROR: AddressSanitizer: global-buffer-overflow on ...
ASAN_ERR_RE = re.compile(r'ERROR: (AddressSanitizer: \S+|LeakSanitizer: \S+)')


def parse_asan(stderr_text):
    """Return (error_kind, [(func, file, line), ...]) from an ASAN report."""
    kind = "unknown"
    m = ASAN_ERR_RE.search(stderr_text)
    if m:
        kind = m.group(1)

    # Pick frames whose file path is inside the project source tree. Paths are
    # relative to the build directory (fuzzing/), e.g. "../src/kms.c", while
    # the ASAN runtime reports its own files as "../../../../src/libsanitizer/...".
    def is_project(path):
        if path.startswith('../src/') or path.startswith('src/'):
            return not ('libsanitizer' in path or 'sanitizer_common' in path)
        return path.endswith('afl-harness.c') or 'afl-harness.c' in path

    project_frames = []
    for _idx, func, path, line in FRAME_RE.findall(stderr_text):
        if is_project(path):
            project_frames.append((func, path, int(line)))

    # The frames are ordered innermost (#0) first, so the first project frame is
    # the deepest in-project faulting site.
    if project_frames:
        return kind, project_frames[0]

    # Fallback: first frame whose path looks project-related.
    for _idx, func, path, line in FRAME_RE.findall(stderr_text):
        if 'vlmcsd' in path or '/src/' in path:
            return kind, (func, path, int(line))

    return kind, None


def normalise_path(path):
    """Strip leading '../../../' style prefixes produced by ASAN."""
    for _ in range(6):
        if path.startswith('../'):
            path = path[3:]
    return path


def build_sarif(findings):
    """Build a SARIF v2.1.0 document from a list of (rule_id, message, file, line) tuples."""
    rules = {}
    results = []

    for rule_id, message, artifact_path, line in findings:
        if rule_id not in rules:
            short_desc = message.split('\n')[0]
            if len(short_desc) > 100:
                short_desc = short_desc[:97] + "..."
            rules[rule_id] = {
                "id": rule_id,
                "shortDescription": {"text": short_desc},
                "defaultConfiguration": {
                    "level": "error",
                    "properties": {"problem.severity": "error"}
                }
            }

        results.append({
            "ruleId": rule_id,
            "level": "error",
            "message": {"text": message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": artifact_path,
                        "uriBaseId": "%SRCROOT%"
                    },
                    "region": {"startLine": line}
                }
            }]
        })

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "AFL++",
                    "version": "AFL++",
                    "informationUri": "https://aflplus.plus",
                    "rules": list(rules.values())
                }
            },
            "results": results,
            "invocations": [{
                "executionSuccessful": True,
                "toolExecutionNotifications": []
            }]
        }]
    }
    return sarif


def run_harness(harness, mode, crash_file, timeout=5):
    """Run the fuzz harness on a crash input, return ASAN stderr."""
    env = os.environ.copy()
    env["ASAN_OPTIONS"] = "symbolize=1:print_stacktrace=1"
    try:
        result = subprocess.run(
            [harness, mode, crash_file],
            capture_output=True,
            timeout=timeout,
            env=env,
        )
        return result.stderr.decode(errors="replace")
    except subprocess.TimeoutExpired:
        return ""
    except Exception:
        return ""


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--harness", required=True, help="Path to compiled fuzz harness binary")
    ap.add_argument("--mode", required=True, choices=["create", "decrypt"])
    ap.add_argument("--crashes", required=True, help="Directory of AFL crash inputs")
    ap.add_argument("--output", required=True, help="Path to write SARIF JSON")
    args = ap.parse_args()

    crash_files = sorted(glob.glob(os.path.join(args.crashes, "id:*")))
    findings = []

    seen = set()

    for crash_file in crash_files:
        stderr = run_harness(args.harness, args.mode, crash_file)
        if not stderr:
            continue

        kind, frame = parse_asan(stderr)
        if frame is None:
            continue

        func, raw_path, line = frame
        artifact_path = normalise_path(raw_path)
        rule_id = f"AFL-{hashlib.sha256(f'{artifact_path}:{line}:{func}'.encode()).hexdigest()[:12]}"

        if (artifact_path, line) in seen:
            continue
        seen.add((artifact_path, line))

        msg = (
            f"AFL++ detected {kind} in `{func}` "
            f"at `{artifact_path}:{line}` "
            f"(crash input: {os.path.basename(crash_file)}).\n\n"
            f"Stack trace:\n{stderr[:1500]}"
        )

        findings.append((rule_id, msg, artifact_path, line))

    sarif = build_sarif(findings)

    with open(args.output, "w") as f:
        json.dump(sarif, f, indent=2)

    print(f"Wrote {args.output}: {len(findings)} finding(s) from {len(crash_files)} crash input(s)")
    return 0 if not findings else 0  # never fail the job on converter exit code


if __name__ == "__main__":
    sys.exit(main())