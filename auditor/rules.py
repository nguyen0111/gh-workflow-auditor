"""Workflow compliance rules."""

from dataclasses import dataclass
from typing import Any


@dataclass
class Finding:
    """A compliance finding."""

    rule_id: str
    severity: str
    message: str
    line: int
    file: str


def _find_line_number(file_path: str, search_pattern: str) -> int:
    """Find the 1-based line number containing a pattern in a file."""
    try:
        with open(file_path, "r") as f:
            for i, line in enumerate(f, start=1):
                if search_pattern in line:
                    return i
    except Exception:
        pass
    return 0


def check_unpinned_actions(data: dict[str, Any], file_path: str) -> list[Finding]:
    """Check if third-party actions use pinned commit SHAs."""
    findings: list[Finding] = []

    jobs = data.get("jobs", {})
    for job_name, job in jobs.items():
        steps = job.get("steps", [])
        for step in steps:
            uses = step.get("uses", "")
            if not uses:
                continue

            # Skip official actions and local actions
            if uses.startswith("actions/") or uses.startswith("./"):
                continue

            # Check if it's a 40-character SHA
            if "@" in uses:
                ref = uses.split("@")[1]
                if len(ref) == 40 and all(c in "0123456789abcdef" for c in ref.lower()):
                    continue

            # Find line number by searching for the action in the file
            line_num = _find_line_number(file_path, uses)

            findings.append(
                Finding(
                    rule_id="unpinned-action",
                    severity="HIGH",
                    message=f"Third-party action '{uses}' is not pinned to a 40-character commit SHA",
                    line=line_num,
                    file=file_path,
                )
            )

    return findings


def check_missing_permissions(data: dict[str, Any], file_path: str) -> list[Finding]:
    """Check if permissions are missing or set to write-all."""
    findings: list[Finding] = []

    permissions = data.get("permissions")
    if permissions is None:
        # Search for 'on:' or 'name:' to find a good line number near the top
        line_num = _find_line_number(file_path, "on:")
        if line_num == 0:
            line_num = _find_line_number(file_path, "name:")

        findings.append(
            Finding(
                rule_id="missing-permissions",
                severity="CRITICAL",
                message="Top-level 'permissions' is missing. Default is read-all, but should be explicitly set.",
                line=line_num,
                file=file_path,
            )
        )
    elif permissions == "write-all":
        line_num = _find_line_number(file_path, "permissions:")

        findings.append(
            Finding(
                rule_id="write-all-permissions",
                severity="CRITICAL",
                message="Permissions set to 'write-all'. This grants excessive permissions.",
                line=line_num,
                file=file_path,
            )
        )

    return findings


def check_pull_request_target(data: dict[str, Any], file_path: str) -> list[Finding]:
    """Check if workflow triggers on pull_request_target."""
    findings: list[Finding] = []

    on_config = data.get("on", data.get("on", {}))
    if isinstance(on_config, dict):
        if "pull_request_target" in on_config:
            line_num = _find_line_number(file_path, "pull_request_target")
            findings.append(
                Finding(
                    rule_id="pull-request-target",
                    severity="HIGH",
                    message="Workflow triggers on 'pull_request_target'. This can be dangerous if combined with untrusted code.",
                    line=line_num,
                    file=file_path,
                )
            )
    elif isinstance(on_config, list):
        if "pull_request_target" in on_config:
            line_num = _find_line_number(file_path, "pull_request_target")
            findings.append(
                Finding(
                    rule_id="pull-request-target",
                    severity="HIGH",
                    message="Workflow triggers on 'pull_request_target'. This can be dangerous if combined with untrusted code.",
                    line=line_num,
                    file=file_path,
                )
            )

    return findings


def check_missing_timeouts(data: dict[str, Any], file_path: str) -> list[Finding]:
    """Check if jobs have timeout-minutes set."""
    findings: list[Finding] = []

    jobs = data.get("jobs", {})
    for job_name, job in jobs.items():
        if "timeout-minutes" not in job:
            # Find line number by searching for the job name
            line_num = _find_line_number(file_path, f"{job_name}:")
            findings.append(
                Finding(
                    rule_id="missing-timeout",
                    severity="MEDIUM",
                    message=f"Job '{job_name}' does not declare 'timeout-minutes'. Jobs should have explicit timeouts.",
                    line=line_num,
                    file=file_path,
                )
            )

    return findings
