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

# Matches unsymbolized ASAN frames like:
#   #1 0x55f4f6632c09  (/tmp/opencode/harness+0x2c09) (BuildId: ...)
# produced by clang/afl builds without a working external symbolizer.
RAW_FRAME_RE = re.compile(r'#(\d+) +0x[0-9a-f]+ +\(([^)]+)\+0x([0-9a-f]+)\)')

# Matches the ASAN summary line to extract the error kind:
#   ==12345==ERROR: AddressSanitizer: global-buffer-overflow on ...
ASAN_ERR_RE = re.compile(r'ERROR: (AddressSanitizer: \S+|LeakSanitizer: \S+)')


def parse_asan(stderr_text, harness=None):
    """Return (error_kind, [(func, file, line), ...]) from an ASAN report."""
    kind = "unknown"
    m = ASAN_ERR_RE.search(stderr_text)
    if m:
        kind = m.group(1)

    # Pick frames whose file path is inside the project source tree. Paths are
    # relative to the build directory (fuzzing/), e.g. "../src/kms.c", while
    # the ASAN runtime reports its own files as "../../../../src/libsanitizer/...".
    def is_project(path):
        if 'libsanitizer' in path or 'sanitizer_common' in path:
            return False
        if path.startswith('../src/') or path.startswith('src/'):
            return True
        if '/src/' in path:
            return True
        return 'afl-harness.c' in path

    # The frames are ordered innermost (#0) first, so the first project frame is
    # the deepest in-project faulting site.
    def first_project_frame(frames):
        for func, path, line in frames:
            if is_project(path):
                return func, path, int(line)
        return None

    symbolic_frames = []
    for _idx, func, path, line in FRAME_RE.findall(stderr_text):
        symbolic_frames.append((func, path, int(line)))

    top = first_project_frame(symbolic_frames)
    if top:
        return kind, top

    # The symbolizer may be missing (e.g. clang-built binary on a box without
    # llvm-symbolizer), in which case ASAN prints raw addresses like
    #   #0 0x55f4f6632c09  (/tmp/opencode/harness+0x2c09)
    # Recover function names and source locations with addr2line.
    raw_offsets = []
    for _idx, path, offset in RAW_FRAME_RE.findall(stderr_text):
        raw_offsets.append((path, offset))

    resolved = []
    for path, offset in raw_offsets:
        if harness and os.path.basename(path) == os.path.basename(harness):
            try:
                out = subprocess.run(
                    ["addr2line", "-f", "-e", harness, f"0x{offset}"],
                    capture_output=True, text=True, timeout=10,
                ).stdout.splitlines()
                if len(out) >= 2 and out[1] and ':0' not in out[1]:
                    resolved.append((out[0].strip(), out[1].strip()))
            except Exception:
                pass

    for func, loc in resolved:
        try:
            file, line = loc.rsplit(':', 1)
        except ValueError:
            continue
        if is_project(file) and file.endswith('.c'):
            return kind, (func, file, int(line))

    # Fallback: first frame whose path looks project-related.
    for func, path, line in symbolic_frames:
        if 'vlmcsd' in path or '/src/' in path:
            return kind, (func, path, int(line))

    return kind, None


def normalise_path(path):
    """Strip leading '../../../' style prefixes produced by ASAN."""
    for _ in range(6):
        if path.startswith('../'):
            path = path[3:]
    # addr2line returns absolute paths. Code scanning resolves locations
    # relative to the checkout root, so collapse "/.../src/foo.c" to
    # "src/foo.c" and "…/fuzzing/afl-harness.c" to "fuzzing/afl-harness.c".
    if 'afl-harness.c' in path:
        return 'fuzzing/' + os.path.basename(path)
    if '/src/' in path:
        return 'src/' + path.split('/src/', 1)[1]
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


def run_harness(harness, mode, crash_file, timeout=5, attempts=3):
    """Run the fuzz harness on a crash input, return ASAN stderr.

    The afl persistent-loop harness re-seeds its PRNG per iteration, so a
    crash input may occasionally not fault on the first standalone run.
    Retry a few times before giving up.
    """
    env = os.environ.copy()
    env["ASAN_OPTIONS"] = "symbolize=1:print_stacktrace=1"
    for _ in range(attempts):
        try:
            result = subprocess.run(
                [harness, mode, crash_file],
                capture_output=True,
                timeout=timeout,
                env=env,
            )
            stderr = result.stderr.decode(errors="replace")
            if result.returncode != 0 and "AddressSanitizer" in stderr:
                return stderr
        except subprocess.TimeoutExpired:
            return ""
        except Exception:
            return ""
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

        kind, frame = parse_asan(stderr, harness=args.harness)
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