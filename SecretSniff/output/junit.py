"""SecretSniff — JUnit XML output format."""

from __future__ import annotations
import xml.etree.ElementTree as ET
from typing import Any


def generate_junit(findings: list[dict], tool_name: str = "SecretSniff") -> str:
    """Generate JUnit XML report.

    Args:
        findings: List of finding dicts.
        tool_name: Tool name.

    Returns:
        JUnit XML string.
    """
    testsuite = ET.Element("testsuite")
    testsuite.set("name", tool_name)
    testsuite.set("tests", str(len(findings)))
    testsuite.set("failures", str(sum(1 for f in findings if f.get("severity") in ("CRITICAL", "HIGH"))))
    testsuite.set("errors", "0")

    for finding in findings:
        testcase = ET.SubElement(testsuite, "testcase")
        testcase.set("name", f"{finding.get('rule', 'Unknown')} in {finding.get('file', '')}")
        testcase.set("classname", finding.get("file", ""))

        if finding.get("severity") in ("CRITICAL", "HIGH"):
            failure = ET.SubElement(testcase, "failure")
            failure.set("message", f"Secret found: {finding.get('rule', '')}")
            failure.text = (
                f"File: {finding.get('file\', '')}\n"
                f"Line: {finding.get('line\', 0)}\n"
                f"Rule: {finding.get('rule\', '')}\n"
                f"Severity: {finding.get('severity\', '')}\n"
                f"Value (redacted): {finding.get('value_redacted\', '')}"
            )

    return ET.tostring(testsuite, encoding="unicode")
