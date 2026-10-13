"""Tests for workflow auditor."""

from pathlib import Path

from ruamel.yaml import YAML

from auditor.rules import (
    check_missing_permissions,
    check_missing_timeouts,
    check_pull_request_target,
    check_unpinned_actions,
)


def test_check_unpinned_actions():
    """Test that unpinned third-party actions are detected."""
    yaml = YAML()
    bad_workflow = yaml.load(Path("tests/fixtures/bad_workflow.yml"))
    good_workflow = yaml.load(Path("tests/fixtures/good_workflow.yml"))

    bad_findings = check_unpinned_actions(bad_workflow, "bad_workflow.yml")
    good_findings = check_unpinned_actions(good_workflow, "good_workflow.yml")

    # Bad workflow should have unpinned actions
    assert len(bad_findings) > 0
    assert any("docker/build-push-action" in f.message for f in bad_findings)

    # Good workflow should have no unpinned actions
    assert len(good_findings) == 0


def test_check_missing_permissions():
    """Test that missing permissions are detected."""
    yaml = YAML()
    bad_workflow = yaml.load(Path("tests/fixtures/bad_workflow.yml"))
    good_workflow = yaml.load(Path("tests/fixtures/good_workflow.yml"))

    bad_findings = check_missing_permissions(bad_workflow, "bad_workflow.yml")
    good_findings = check_missing_permissions(good_workflow, "good_workflow.yml")

    # Bad workflow should have missing permissions
    assert len(bad_findings) > 0
    assert any(f.rule_id == "missing-permissions" for f in bad_findings)

    # Good workflow should have no permission issues
    assert len(good_findings) == 0


def test_check_pull_request_target():
    """Test that pull_request_target triggers are detected."""
    yaml = YAML()
    bad_workflow = yaml.load(Path("tests/fixtures/bad_workflow.yml"))
    good_workflow = yaml.load(Path("tests/fixtures/good_workflow.yml"))

    bad_findings = check_pull_request_target(bad_workflow, "bad_workflow.yml")
    good_findings = check_pull_request_target(good_workflow, "good_workflow.yml")

    # Bad workflow should have pull_request_target
    assert len(bad_findings) > 0
    assert any(f.rule_id == "pull-request-target" for f in bad_findings)

    # Good workflow should not have pull_request_target
    assert len(good_findings) == 0


def test_check_missing_timeouts():
    """Test that missing timeouts are detected."""
    yaml = YAML()
    bad_workflow = yaml.load(Path("tests/fixtures/bad_workflow.yml"))
    good_workflow = yaml.load(Path("tests/fixtures/good_workflow.yml"))

    bad_findings = check_missing_timeouts(bad_workflow, "bad_workflow.yml")
    good_findings = check_missing_timeouts(good_workflow, "good_workflow.yml")

    # Bad workflow should have missing timeouts
    assert len(bad_findings) > 0
    assert any(f.rule_id == "missing-timeout" for f in bad_findings)

    # Good workflow should have no timeout issues
    assert len(good_findings) == 0


def test_bad_workflow_triggers_all_rules():
    """Test that bad workflow triggers all 4 rules."""
    yaml = YAML()
    bad_workflow = yaml.load(Path("tests/fixtures/bad_workflow.yml"))

    findings = []
    findings.extend(check_unpinned_actions(bad_workflow, "bad_workflow.yml"))
    findings.extend(check_missing_permissions(bad_workflow, "bad_workflow.yml"))
    findings.extend(check_pull_request_target(bad_workflow, "bad_workflow.yml"))
    findings.extend(check_missing_timeouts(bad_workflow, "bad_workflow.yml"))

    # Should have findings from all 4 rules
    rule_ids = {f.rule_id for f in findings}
    expected_rules = {"unpinned-action", "missing-permissions", "pull-request-target", "missing-timeout"}
    assert expected_rules.issubset(rule_ids)


def test_good_workflow_passes_all_rules():
    """Test that good workflow passes all rules."""
    yaml = YAML()
    good_workflow = yaml.load(Path("tests/fixtures/good_workflow.yml"))

    findings = []
    findings.extend(check_unpinned_actions(good_workflow, "good_workflow.yml"))
    findings.extend(check_missing_permissions(good_workflow, "good_workflow.yml"))
    findings.extend(check_pull_request_target(good_workflow, "good_workflow.yml"))
    findings.extend(check_missing_timeouts(good_workflow, "good_workflow.yml"))

    # Should have no findings
    assert len(findings) == 0
