#!/usr/bin/env python3
"""Convert cppcheck XML output to SARIF v2.1.0 for GitHub Code Scanning.

cppcheck's SARIF output (--output-format=sarif) only exists in >= 2.14,
but Ubuntu 24.04 ships 2.13. XML output (--xml) is stable across all
versions, so we parse that and emit SARIF ourselves.
"""

import argparse
import json
import sys
import xml.etree.ElementTree as ET

# cppcheck severity -> SARIF level
LEVEL_MAP = {
    "error": "error",
    "warning": "warning",
    "style": "note",
    "performance": "note",
    "portability": "warning",
    "information": "note",
}


def normalise_path(path):
    """Collapse absolute/../-prefixed paths to checkout-relative ones."""
    if "/src/" in path:
        return "src/" + path.split("/src/", 1)[1]
    if "/lib/" in path:
        return "lib/" + path.split("/lib/", 1)[1]
    return path


def build_sarif(errors):
    """Build a SARIF v2.1.0 document from parsed cppcheck <error> elements."""
    rules = {}
    results = []

    for err in errors:
        rule_id = err.get("id", "cppcheck")
        severity = err.get("severity", "warning")
        level = LEVEL_MAP.get(severity, "warning")
        msg = err.get("msg", "")
        verbose = err.get("verbose", msg)
        cwe = err.get("cwe")

        loc = err.find("location")
        if loc is None:
            continue
        artifact_path = normalise_path(loc.get("file", ""))
        line = int(loc.get("line", 0) or 0)
        column = int(loc.get("column", 0) or 0)

        if rule_id not in rules:
            short_desc = msg.split("\n")[0]
            if len(short_desc) > 100:
                short_desc = short_desc[:97] + "..."
            rule = {
                "id": rule_id,
                "shortDescription": {"text": short_desc},
                "defaultConfiguration": {
                    "level": level,
                    "properties": {"problem.severity": severity},
                },
            }
            if cwe:
                rule["properties"] = {"tags": [f"external/cwe/cwe-{cwe}"]}
            rules[rule_id] = rule

        region = {"startLine": line}
        if column:
            region["startColumn"] = column
        results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {"text": verbose},
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
                    "name": "Cppcheck",
                    "version": "Cppcheck",
                    "informationUri": "https://cppcheck.sourceforge.io/",
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
    ap.add_argument("xml_file", help="cppcheck XML report (--xml --xml-version=2)")
    ap.add_argument("output", help="Path to write SARIF JSON")
    args = ap.parse_args()

    tree = ET.parse(args.xml_file)
    root = tree.getroot()
    errors = root.findall(".//error")

    sarif = build_sarif(errors)
    with open(args.output, "w") as f:
        json.dump(sarif, f, indent=2)

    print(f"Wrote {args.output}: {len(errors)} finding(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())