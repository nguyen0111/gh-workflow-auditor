"""Tests for workflow auditor."""

from io import StringIO
from pathlib import Path

from ruamel.yaml import YAML
from typer.testing import CliRunner

from auditor.cli import app
from auditor.rules import (
    check_missing_permissions,
    check_missing_timeouts,
    check_pull_request_target,
    check_unpinned_actions,
)

FIXTURES = Path(__file__).parent / "fixtures"
SHA = "11bd71901bbe5b1630ceea73d27597364c9af683"


def parse(text: str):
    return YAML().load(StringIO(text))


def load_fixture(name: str):
    return YAML().load((FIXTURES / name).open())


# --- check_unpinned_actions -------------------------------------------------


def test_unpinned_third_party_action_flagged_with_line():
    doc = parse(
        """name: T
on: push
jobs:
  build:
    steps:
      - uses: docker/build-push-action@v2
"""
    )
    findings = check_unpinned_actions(doc, "t.yml")
    assert len(findings) == 1
    assert findings[0].rule_id == "unpinned-action"
    assert findings[0].severity == "HIGH"
    assert findings[0].line == 6


def test_unpinned_official_action_flagged():
    """SEC001 is strict: even actions/* must be SHA-pinned."""
    doc = parse(
        f"""name: T
on: push
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@{SHA}
"""
    )
    findings = check_unpinned_actions(doc, "t.yml")
    assert len(findings) == 1
    assert "actions/checkout@v4" in findings[0].message
    assert findings[0].line == 6


def test_sha_pinned_actions_pass():
    doc = parse(
        f"""name: T
on: push
jobs:
  build:
    steps:
      - uses: actions/checkout@{SHA}
      - uses: actions/setup-python@{SHA}
      - uses: docker/build-push-action@deadbeefdeadbeefdeadbeefdeadbeefdeadbeef
"""
    )
    assert check_unpinned_actions(doc, "t.yml") == []


def test_local_action_exempt():
    doc = parse(
        """name: T
on: push
jobs:
  build:
    steps:
      - uses: ./local/action
      - uses: ./.github/actions/deploy
"""
    )
    assert check_unpinned_actions(doc, "t.yml") == []


def test_docker_action_requires_sha256_digest():
    doc = parse(
        """name: T
on: push
jobs:
  build:
    steps:
      - uses: docker://alpine:3.18
      - uses: docker://alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
"""
    )
    findings = check_unpinned_actions(doc, "t.yml")
    assert len(findings) == 1
    assert "docker://alpine:3.18" in findings[0].message
    assert findings[0].line == 6


def test_duplicate_unpinned_actions_get_distinct_lines():
    doc = parse(
        """name: T
on: push
jobs:
  first:
    steps:
      - uses: evil/action@v1
  second:
    steps:
      - uses: evil/action@v1
"""
    )
    findings = check_unpinned_actions(doc, "t.yml")
    assert len(findings) == 2
    assert findings[0].line == 6
    assert findings[1].line == 9


# --- check_missing_permissions ----------------------------------------------


def test_missing_permissions_flagged_at_on_line():
    doc = parse(
        """name: T
on: push
jobs:
  build:
    steps:
      - run: echo hi
"""
    )
    findings = check_missing_permissions(doc, "t.yml")
    assert len(findings) == 1
    assert findings[0].rule_id == "missing-permissions"
    assert findings[0].severity == "CRITICAL"
    assert findings[0].line == 2


def test_write_all_permissions_flagged():
    doc = parse(
        """name: T
on: push
permissions: write-all
jobs:
  build:
    steps:
      - run: echo hi
"""
    )
    findings = check_missing_permissions(doc, "t.yml")
    assert len(findings) == 1
    assert findings[0].rule_id == "write-all-permissions"
    assert findings[0].line == 3


def test_job_level_write_all_flagged():
    doc = parse(
        """name: T
on: push
permissions:
  contents: read
jobs:
  build:
    permissions: write-all
    steps:
      - run: echo hi
"""
    )
    findings = check_missing_permissions(doc, "t.yml")
    assert len(findings) == 1
    assert findings[0].rule_id == "write-all-permissions"
    assert findings[0].severity == "CRITICAL"
    assert "build" in findings[0].message
    assert findings[0].line == 7


def test_scoped_permissions_pass():
    doc = parse(
        """name: T
on: push
permissions:
  contents: read
jobs:
  build:
    permissions:
      contents: read
    steps:
      - run: echo hi
"""
    )
    assert check_missing_permissions(doc, "t.yml") == []


# --- check_pull_request_target ----------------------------------------------


def test_pull_request_target_dict_form():
    doc = load_fixture("bad_workflow.yml")
    findings = check_pull_request_target(doc, "bad_workflow.yml")
    assert len(findings) == 1
    assert findings[0].rule_id == "pull-request-target"
    assert findings[0].severity == "HIGH"
    assert findings[0].line == 3


def test_pull_request_target_list_form():
    doc = parse(
        """name: T
on:
  - push
  - pull_request_target
jobs: {}
"""
    )
    findings = check_pull_request_target(doc, "t.yml")
    assert len(findings) == 1
    assert findings[0].line == 4


def test_pull_request_target_string_form():
    doc = parse(
        """name: T
on: pull_request_target
jobs: {}
"""
    )
    findings = check_pull_request_target(doc, "t.yml")
    assert len(findings) == 1
    assert findings[0].line == 2


def test_comment_with_fake_keyword_does_not_trigger():
    """Comments must not fool the AST-based parser."""
    doc = parse(
        """name: T
# on: pull_request_target
on: push
jobs: {}
"""
    )
    assert check_pull_request_target(doc, "t.yml") == []


# --- check_missing_timeouts --------------------------------------------------


def test_missing_timeouts_exact_job_lines():
    doc = load_fixture("bad_workflow.yml")
    findings = check_missing_timeouts(doc, "bad_workflow.yml")
    assert len(findings) == 2
    lines = sorted(f.line for f in findings)
    assert lines == [7, 14]
    assert all(f.rule_id == "missing-timeout" for f in findings)
    assert all(f.severity == "MEDIUM" for f in findings)


def test_timeouts_present_pass():
    doc = load_fixture("good_workflow.yml")
    assert check_missing_timeouts(doc, "good_workflow.yml") == []


# --- fixture-level integration ----------------------------------------------


def test_bad_fixture_triggers_all_rules():
    doc = load_fixture("bad_workflow.yml")
    findings = []
    findings.extend(check_unpinned_actions(doc, "bad_workflow.yml"))
    findings.extend(check_missing_permissions(doc, "bad_workflow.yml"))
    findings.extend(check_pull_request_target(doc, "bad_workflow.yml"))
    findings.extend(check_missing_timeouts(doc, "bad_workflow.yml"))

    rule_ids = {f.rule_id for f in findings}
    assert {"unpinned-action", "missing-permissions", "pull-request-target", "missing-timeout"} <= rule_ids


def test_good_fixture_passes_all_rules():
    doc = load_fixture("good_workflow.yml")
    findings = []
    findings.extend(check_unpinned_actions(doc, "good_workflow.yml"))
    findings.extend(check_missing_permissions(doc, "good_workflow.yml"))
    findings.extend(check_pull_request_target(doc, "good_workflow.yml"))
    findings.extend(check_missing_timeouts(doc, "good_workflow.yml"))
    assert findings == []


# --- CLI --------------------------------------------------------------------


def test_cli_clean_file_exit_zero():
    runner = CliRunner()
    result = runner.invoke(app, [str(FIXTURES / "good_workflow.yml")])
    assert result.exit_code == 0
    assert "No compliance issues" in result.output


def test_cli_dirty_file_exit_one():
    runner = CliRunner()
    result = runner.invoke(app, [str(FIXTURES / "bad_workflow.yml")])
    assert result.exit_code == 1
    assert "Compliance Findings" in result.output


def test_cli_empty_file_exit_zero(tmp_path):
    empty = tmp_path / "empty.yml"
    empty.write_text("")
    runner = CliRunner()
    result = runner.invoke(app, [str(empty)])
    assert result.exit_code == 0


def test_cli_nonexistent_path_exit_one():
    runner = CliRunner()
    result = runner.invoke(app, ["/nonexistent/path/to/workflows"])
    assert result.exit_code == 1
