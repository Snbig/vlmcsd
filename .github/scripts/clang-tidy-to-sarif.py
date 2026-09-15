#!/usr/bin/env python3
"""Convert clang-tidy text output to SARIF v2.1.0 for GitHub Code Scanning.

clang-tidy has no native SARIF output and the clang-tidy-sarif PyPI package
does not exist, so we parse the stable text format:

    <file>:<line>:<col>: <severity>: <message> [<check-name>]
"""

import argparse
import json
import re
import sys

# Matches one clang-tidy diagnostic line, e.g.
#   /path/src/kms.c:508:5: warning: Using pointer to local variable 'ePid'
#   that is out of scope [clang-analyzer-core.StackAddressEscape]
DIAG_RE = re.compile(
    r"^(?P<file>.+?):(?P<line>\d+):(?P<col>\d+):\s+"
    r"(?P<severity>error|warning|note):\s+(?P<message>.+?)"
    r"(?:\s+\[(?P<check>[^\]]+)\])?$"
)

# clang-tidy severity -> SARIF level
LEVEL_MAP = {
    "error": "error",
    "warning": "warning",
    "note": "note",
}


def normalise_path(path):
    """Collapse absolute paths to checkout-relative ones."""
    if "/src/" in path:
        return "src/" + path.split("/src/", 1)[1]
    if "/lib/" in path:
        return "lib/" + path.split("/lib/", 1)[1]
    if "/fuzzing/" in path:
        return "fuzzing/" + path.split("/fuzzing/", 1)[1]
    return path


def build_sarif(findings):
    """Build a SARIF v2.1.0 document from parsed clang-tidy diagnostics."""
    rules = {}
    results = []

    for file, line, col, severity, message, check in findings:
        rule_id = check or "clang-tidy"
        level = LEVEL_MAP.get(severity, "warning")
        artifact_path = normalise_path(file)

        if rule_id not in rules:
            short_desc = message.split("\n")[0]
            if len(short_desc) > 100:
                short_desc = short_desc[:97] + "..."
            rules[rule_id] = {
                "id": rule_id,
                "shortDescription": {"text": short_desc},
                "defaultConfiguration": {
                    "level": level,
                    "properties": {"problem.severity": severity},
                },
            }

        region = {"startLine": line}
        if col:
            region["startColumn"] = col
        results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {"text": message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": artifact_path,
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": region,
                }
            }],
        })

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "clang-tidy",
                    "version": "clang-tidy",
                    "informationUri": "https://clang.llvm.org/extra/clang-tidy/",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
            "invocations": [{
                "executionSuccessful": True,
                "toolExecutionNotifications": [],
            }],
        }],
    }
    return sarif


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("text_file", help="clang-tidy text output")
    ap.add_argument("output", help="Path to write SARIF JSON")
    args = ap.parse_args()

    findings = []
    current = None  # (file, line, col, severity, message_parts, check)

    def flush():
        nonlocal current
        if current is None:
            return
        file, line, col, severity, parts, check = current
        message = " ".join(p.strip() for p in parts if p.strip())
        findings.append((file, line, col, severity, message, check))
        current = None

    with open(args.text_file, errors="replace") as f:
        for raw in f:
            line = raw.rstrip("\n")
            m = DIAG_RE.match(line)
            if m:
                flush()
                current = (
                    m.group("file"),
                    int(m.group("line")),
                    int(m.group("col")),
                    m.group("severity"),
                    [m.group("message").strip()],
                    m.group("check"),
                )
            elif current is not None and line.strip():
                # Continuation of a wrapped diagnostic. The [check-name]
                # suffix, if any, sits on the last continuation line.
                parts = current[4]
                parts.append(line.strip())
                if current[5] is None:
                    cm = re.search(r"\[([^\]]+)\]$", line.strip())
                    if cm:
                        current = (
                            current[0], current[1], current[2],
                            current[3], parts, cm.group(1),
                        )
    flush()

    sarif = build_sarif(findings)
    with open(args.output, "w") as f:
        json.dump(sarif, f, indent=2)

    print(f"Wrote {args.output}: {len(findings)} finding(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())