import json
from typing import List

def to_json(vulns: List[dict], filename: str) -> dict:
    return {
        "tool": "Vulnerability Insight Analyzer v1.0",
        "file": filename,
        "total_vulnerabilities": len(vulns),
        "findings": vulns
    }

def to_sarif(vulns: List[dict], filename: str) -> dict:
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Vulnerability Insight Analyzer", "version": "1.0.0"}},
            "results": [
                {
                    "ruleId": v["name"].replace(" ", "_"),
                    "level": "error" if v["severity"] in ("critical", "high") else "warning",
                    "message": {"text": v["description"]},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": filename},
                            "region": {"startLine": v["line"], "endLine": v["line"]}
                        }
                    }]
                } for v in vulns
            ]
        }]
    }