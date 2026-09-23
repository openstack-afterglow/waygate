"""CI shape contract (AGENTS.md "CI 파이프라인 성능 규정" rules 3, 7, 9, 10, 11).

These tests pin the workflow invariants that the CI performance changes rely on:
one test execution per SHA and event, image builds gated by the test result,
PR image builds that never publish, and an explicit pytest-xdist worker count.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import yaml

REPOSITORY_ROOT = Path(__file__).parents[1]
WORKFLOWS = REPOSITORY_ROOT / ".github" / "workflows"

BUILD_GATE = (
    "${{ !cancelled() && (needs.test.result == 'success' || "
    "(github.event_name == 'pull_request' && needs.test.result == 'skipped')) }}"
)
NO_PUSH_ON_PR = "${{ github.event_name != 'pull_request' }}"


def _load(name: str) -> dict:
    return yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))


def _triggers(workflow: dict) -> dict:
    # PyYAML (YAML 1.1) parses the bare `on` key as boolean True.
    triggers = workflow.get("on", workflow.get(True))
    assert isinstance(triggers, dict)
    return {name: config or {} for name, config in triggers.items()}


def _run_commands(job: dict) -> list[str]:
    return [" ".join(step["run"].split()) for step in job["steps"] if "run" in step]


def test_ci_runs_only_on_pull_request_and_workflow_call():
    triggers = _triggers(_load("ci.yml"))

    assert set(triggers) == {"pull_request", "workflow_call"}
    assert triggers["pull_request"] == {"branches": ["main", "dev"]}


def test_docker_build_owns_push_tag_and_dispatch_testing():
    triggers = _triggers(_load("docker-build.yml"))

    assert set(triggers) == {"pull_request", "push", "workflow_dispatch"}
    assert triggers["push"] == {"branches": ["main", "dev"], "tags": ["v*"]}


def test_pull_request_trigger_sets_are_identical():
    # Skipping Docker Build's test copy on pull_request is only safe while CI's
    # own pull_request trigger covers every PR that Docker Build builds.
    ci = _triggers(_load("ci.yml"))["pull_request"]
    docker = _triggers(_load("docker-build.yml"))["pull_request"]

    assert ci == docker


def test_docker_test_job_reuses_ci_and_skips_only_on_pull_request():
    test_job = _load("docker-build.yml")["jobs"]["test"]

    assert test_job["uses"] == "./.github/workflows/ci.yml"
    assert test_job["if"] == "github.event_name != 'pull_request'"


def test_image_build_is_gated_by_test_result():
    build = _load("docker-build.yml")["jobs"]["build-and-push"]

    assert build["needs"] == "test"
    assert build["if"] == BUILD_GATE


def test_pull_request_image_builds_never_push():
    build = _load("docker-build.yml")["jobs"]["build-and-push"]
    build_steps = [step for step in build["steps"] if str(step.get("uses", "")).startswith("docker/build-push-action")]

    assert len(build_steps) == 2
    for step in build_steps:
        assert step["with"]["push"] == NO_PUSH_ON_PR


def test_ci_jobs_run_in_parallel_without_gate_jobs():
    jobs = _load("ci.yml")["jobs"]

    assert set(jobs) == {"service", "sdk"}
    for job in jobs.values():
        assert "needs" not in job


def test_service_job_checks_architecture_then_runs_pytest_with_explicit_workers():
    commands = _run_commands(_load("ci.yml")["jobs"]["service"])

    assert commands[0] == "python3 scripts/check_architecture.py"
    pytest_commands = [command for command in commands if "pytest" in command]
    assert pytest_commands == ["uv run pytest tests -n 4 --dist worksteal"]
    assert "-n auto" not in pytest_commands[0]
    # The xdist entry point registers the plugin; `-p xdist` registers it twice.
    assert "-p xdist" not in pytest_commands[0]


def test_serial_pytest_entrypoint_stays_valid():
    pyproject = tomllib.loads((REPOSITORY_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    ini_options = pyproject["tool"]["pytest"]["ini_options"]
    addopts = ini_options.get("addopts", "")
    addopts = addopts if isinstance(addopts, str) else " ".join(addopts)

    assert "-n" not in addopts.split()
    assert "--dist" not in addopts
    assert any(dep.startswith("pytest-xdist") for dep in pyproject["project"]["optional-dependencies"]["dev"])


def test_no_workflow_uses_self_hosted_runners():
    for path in sorted(WORKFLOWS.glob("*.yml")):
        for name, job in yaml.safe_load(path.read_text(encoding="utf-8"))["jobs"].items():
            if "uses" in job:
                continue
            runs_on = job["runs-on"]
            labels = runs_on if isinstance(runs_on, list) else [runs_on]
            assert "self-hosted" not in labels, f"{path.name}:{name}"
            assert labels == ["ubuntu-latest"], f"{path.name}:{name}"
