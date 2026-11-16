"""Workflow compliance rules."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

_SHA_RE = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)
_DOCKER_SHA_RE = re.compile(r"^sha256:[0-9a-f]{64}$", re.IGNORECASE)


@dataclass
class Finding:
    """A compliance finding."""

    rule_id: str
    severity: str
    message: str
    line: int
    file: str


def _line_of_key(node: Any, key: Any) -> int | None:
    """Return the 1-based line of `key` inside a ruamel.yaml node, or None."""
    lc = getattr(node, "lc", None)
    entry = (getattr(lc, "data", None) or {}).get(key)
    return entry[0] + 1 if entry else None


def _line_of_node(node: Any) -> int | None:
    """Return the 1-based line a ruamel.yaml node starts on, or None."""
    lc = getattr(node, "lc", None)
    line = getattr(lc, "line", None)
    return line + 1 if line is not None else None


def _is_pinned(uses: str) -> bool:
    """Check whether a `uses:` reference is pinned to an immutable digest."""
    if uses.startswith("./"):
        return True
    if uses.startswith("docker://"):
        ref = uses.rsplit("@", 1)[-1]
        return "@" in uses and bool(_DOCKER_SHA_RE.match(ref))
    if "@" not in uses:
        return False
    return bool(_SHA_RE.match(uses.rsplit("@", 1)[-1]))


def check_unpinned_actions(data: dict[str, Any], file_path: str) -> list[Finding]:
    """Check that every action is pinned to an immutable commit SHA or digest."""
    findings: list[Finding] = []

    if not isinstance(data, dict):
        return findings

    jobs = data.get("jobs") or {}
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        steps = job.get("steps") or []
        for index, step in enumerate(steps):
            if not isinstance(step, dict):
                continue
            uses = step.get("uses")
            if not uses or not isinstance(uses, str) or _is_pinned(uses):
                continue

            line = (
                _line_of_key(step, "uses")
                or _line_of_key(steps, index)
                or _line_of_key(job, "steps")
                or 1
            )
            detail = "a sha256 digest" if uses.startswith("docker://") else "a 40-character commit SHA"
            findings.append(
                Finding(
                    rule_id="unpinned-action",
                    severity="HIGH",
                    message=f"Action '{uses}' is not pinned to {detail}",
                    line=line,
                    file=file_path,
                )
            )

    return findings


def check_missing_permissions(data: dict[str, Any], file_path: str) -> list[Finding]:
    """Check for missing top-level permissions and dangerous write-all overrides."""
    findings: list[Finding] = []

    if not isinstance(data, dict):
        return findings

    permissions = data.get("permissions")
    if permissions is None:
        line = (
            _line_of_key(data, "on")
            or _line_of_key(data, "name")
            or _line_of_node(data)
            or 1
        )
        findings.append(
            Finding(
                rule_id="missing-permissions",
                severity="CRITICAL",
                message="Top-level 'permissions' is missing. Default is read-all, but should be explicitly set.",
                line=line,
                file=file_path,
            )
        )
    elif permissions == "write-all":
        line = _line_of_key(data, "permissions") or 1
        findings.append(
            Finding(
                rule_id="write-all-permissions",
                severity="CRITICAL",
                message="Permissions set to 'write-all'. This grants excessive permissions.",
                line=line,
                file=file_path,
            )
        )

    jobs = data.get("jobs") or {}
    for job_name, job in jobs.items():
        if not isinstance(job, dict) or job.get("permissions") != "write-all":
            continue
        line = _line_of_key(job, "permissions") or _line_of_key(jobs, job_name) or 1
        findings.append(
            Finding(
                rule_id="write-all-permissions",
                severity="CRITICAL",
                message=f"Job '{job_name}' overrides permissions with 'write-all'. This grants excessive permissions.",
                line=line,
                file=file_path,
            )
        )

    return findings


def check_pull_request_target(data: dict[str, Any], file_path: str) -> list[Finding]:
    """Check if workflow triggers on pull_request_target."""
    findings: list[Finding] = []

    if not isinstance(data, dict):
        return findings

    on_config = data.get("on", {})
    found = False
    line = None

    if isinstance(on_config, dict):
        found = "pull_request_target" in on_config
        if found:
            line = _line_of_key(on_config, "pull_request_target")
    elif isinstance(on_config, list):
        for index, item in enumerate(on_config):
            if item == "pull_request_target":
                found = True
                line = _line_of_key(on_config, index)
                break
    elif on_config == "pull_request_target":
        found = True
        line = _line_of_key(data, "on")

    if found:
        findings.append(
            Finding(
                rule_id="pull-request-target",
                severity="HIGH",
                message="Workflow triggers on 'pull_request_target'. This can be dangerous if combined with untrusted code.",
                line=line or _line_of_key(data, "on") or 1,
                file=file_path,
            )
        )

    return findings


def check_missing_timeouts(data: dict[str, Any], file_path: str) -> list[Finding]:
    """Check if jobs have timeout-minutes set."""
    findings: list[Finding] = []

    if not isinstance(data, dict):
        return findings

    jobs = data.get("jobs") or {}
    for job_name, job in jobs.items():
        if not isinstance(job, dict) or "timeout-minutes" in job:
            continue
        line = _line_of_key(jobs, job_name) or _line_of_key(data, "jobs") or 1
        findings.append(
            Finding(
                rule_id="missing-timeout",
                severity="MEDIUM",
                message=f"Job '{job_name}' does not declare 'timeout-minutes'. Jobs should have explicit timeouts.",
                line=line,
                file=file_path,
            )
        )

    return findings
