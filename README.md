# GitHub Workflow Auditor

[![CI Quality & Compliance](https://github.com/nguyen0111/gh-workflow-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/nguyen0111/gh-workflow-auditor/actions/workflows/ci.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)

A security and operational compliance auditor for GitHub Actions workflows. Designed for enterprise banking environments where CI/CD supply chain security, privilege control, and cost management are critical.

## Problem Statement

In enterprise banking environments, CI/CD pipelines are prime targets for supply chain attacks and security breaches. Common risks include:

- **Supply Chain Attacks**: Third-party actions referenced by mutable tags (e.g., `@v2`) can be hijacked or backdoored, introducing malicious code into production builds.
- **Privilege Escalation**: Overly permissive `GITHUB_TOKEN` permissions (especially `write-all`) can lead to unauthorized code modifications, secret leaks, or repository tampering.
- **Dangerous Triggers**: The `pull_request_target` event, when combined with untrusted code execution, can bypass security checks and compromise repositories.
- **Cost Management**: Jobs without explicit `timeout-minutes` can hang indefinitely, consuming runner resources and incurring unexpected cloud costs.

This tool enforces a baseline security posture by detecting these issues before they reach production.

## Compliance Rules Matrix

| Rule ID | Severity | Description |
|---------|----------|-------------|
| **SEC001** | HIGH | Pin Third-Party Actions to 40-character commit SHA. Official GitHub Actions (`actions/*`) and local actions (`./`) are exempt. |
| **SEC002** | CRITICAL | Enforce Explicit Least-Privilege Permissions. Flags missing top-level `permissions` or `write-all` configuration. |
| **SEC003** | HIGH | Restrict Dangerous `pull_request_target` Triggers. Flags workflows that use this event, which can be dangerous with untrusted code. |
| **OPS001** | MEDIUM | Enforce Explicit `timeout-minutes` on all Jobs. Flags jobs that lack timeout declarations to prevent runaway resource consumption. |

## Terminal Output Preview

```
                              Compliance Findings
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┳━━━━━━┓
┃ Severity ┃ Rule ID           ┃ Message           ┃ File               ┃ Line ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━╇━━━━━━┩
│ HIGH     │ unpinned-action   │ Third-party       │ .github/workflows/… │ 11   │
│          │                   │ action            │                    │      │
│          │                   │ 'docker/build-pu… │                    │      │
│          │                   │ is not pinned to  │                    │      │
│          │                   │ a 40-character    │                    │      │
│          │                   │ commit SHA        │                    │      │
│ CRITICAL │ missing-permissi… │ Top-level         │ .github/workflows/… │ 2    │
│          │                   │ 'permissions' is  │                    │      │
│          │                   │ missing. Default  │                    │      │
│          │                   │ is read-all, but  │                    │      │
│          │                   │ should be         │                    │      │
│          │                   │ explicitly set.   │                    │      │
│ HIGH     │ pull-request-tar… │ Workflow triggers │ .github/workflows/… │ 3    │
│          │                   │ on                │                    │      │
│          │                   │ 'pull_request_ta… │                    │      │
│          │                   │ This can be       │                    │      │
│          │                   │ dangerous if      │                    │      │
│          │                   │ combined with     │                    │      │
│          │                   │ untrusted code.   │                    │      │
│ MEDIUM   │ missing-timeout   │ Job 'build' does  │ .github/workflows/… │ 7    │
│          │                   │ not declare       │                    │      │
│          │                   │ 'timeout-minutes… │                    │      │
│          │                   │ Jobs should have  │                    │      │
│          │                   │ explicit          │                    │      │
│          │                   │ timeouts.         │                    │      │
└──────────┴───────────────────┴───────────────────┴────────────────────┴──────┘
```

## Installation & Local Usage

### Install

```bash
# Clone the repository
git clone https://github.com/nguyen0111/gh-workflow-auditor.git
cd gh-workflow-auditor

# Install dependencies
pip install -r requirements.txt

# Install the CLI tool locally
pip install -e .
```

### Scan Workflows

```bash
# Scan default .github/workflows directory
gh-audit .github/workflows

# Scan a specific directory
gh-audit path/to/workflows

# Scan a single workflow file
gh-audit .github/workflows/deploy.yml
```

### Exit Codes

- **0**: No compliance issues found (or only MEDIUM severity issues)
- **1**: CRITICAL or HIGH severity issues found (pipeline should be blocked)

## CI/CD Integration

Add this tool as a PR gatekeeper in your own repositories to enforce compliance before merges:

```yaml
name: Workflow Compliance Check

on:
  pull_request:
    branches: [main]

permissions:
  contents: read

jobs:
  audit:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.10"
      - run: pip install gh-workflow-auditor
      - run: gh-audit .github/workflows
```

This ensures that any workflow file changes are automatically audited for security and operational compliance before they can be merged into your main branch.

## Development

```bash
# Run tests
python -m pytest -v

# Test the CLI locally
gh-audit tests/fixtures
```

## License

MIT License - See LICENSE file for details.
