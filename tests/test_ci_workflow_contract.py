"""CI shape contract (AGENTS.md "CI 파이프라인 성능 규정" rules 3, 7, 9, 10, 11).

These tests pin the workflow invariants that the CI performance changes rely on:
one test execution per pushed ref or PR sync (a release tag push re-tests the SHA
its branch push already tested), image publishing gated by the test result, PR
image builds that never publish or log in, and an explicit pytest-xdist worker count.

The publish gate is only as strong as ci.yml's own result, so ci.yml is pinned
structurally: its workflow, job and step key sets (no `if`, `continue-on-error`,
`env`, `shell` or `working-directory`, and `defaults` only for the sdk job), the
ordered steps of each job, and a checkout without `with`. Any job in any workflow
that can publish must wait for the test job, and workflows accept only
unprivileged triggers and never interpolate event payloads into `run:`.

Limits. The contract runs under the pytest configuration it would have to judge,
so it cannot detect a change that makes pytest itself skip or only collect tests
(pyproject `addopts`, `conftest.py`). It runs only inside ci.yml. A PR that removes
or narrows ci.yml's own pull_request trigger therefore runs no tests before merge;
the regression shows up on the next branch push, where Docker Build & Push's test
job fails this contract and blocks the image. actionlint is a local check and is
not run by any workflow.
"""

from __future__ import annotations

import re
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
SKIP_ON_PR = "github.event_name != 'pull_request'"
CI_CALL = "./.github/workflows/ci.yml"

# Actions reviewed as unable to publish. Every other action, including a local
# composite action (`./...`), a `docker://` container action and any unreviewed
# third-party action, is treated as able to publish.
NON_PUBLISHING_ACTIONS = frozenset(
    {"actions/checkout", "astral-sh/setup-uv", "docker/setup-buildx-action", "docker/metadata-action"}
)
BUILD_ACTIONS = frozenset({"docker/build-push-action", "docker/bake-action"})
PUBLISH_COMMAND = re.compile(
    r"docker\s+(push|login)|--push\b|push=true|type=registry|imagetools\s+create|buildx\s+build"
    r"|\b(crane|skopeo|oras|twine)\b|uv\s+publish"
)
# pull_request_target, workflow_run, issue_comment and similar triggers run with
# base-repository secrets or write tokens on behalf of untrusted actors.
ALLOWED_TRIGGERS = frozenset({"push", "pull_request", "workflow_dispatch", "workflow_call", "schedule"})
EVENT_PAYLOAD_EXPRESSION = re.compile(r"\$\{\{[^}]*\b(github\.event\.|github\.head_ref\b)")
# secrets.NAME, secrets['NAME'] and toJSON(secrets) inside any expression.
SECRET_EXPRESSION = re.compile(r"\$\{\{[^}]*\bsecrets\b")

CI_WORKFLOW_KEYS = {"name", "on", "permissions", "jobs"}
CI_JOB_KEYS = {
    "service": {"name", "runs-on", "steps"},
    "sdk": {"name", "runs-on", "defaults", "steps"},
}
CI_STEP_KEYS = {"name", "uses", "with", "run"}
CI_STEPS = {
    "service": [
        "uses: actions/checkout",
        "run: python3 scripts/check_architecture.py",
        "uses: astral-sh/setup-uv",
        "run: uv sync --extra service --extra dev --frozen",
        "run: uv run pytest tests -n 4 --dist worksteal",
        "run: uv run ruff check .",
    ],
    "sdk": [
        "uses: actions/checkout",
        "uses: astral-sh/setup-uv",
        "run: uv sync --all-extras --frozen",
        "run: uv run pytest",
        "run: uv run ruff check .",
    ],
}


def _load(name: str) -> dict:
    return yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))


def _workflow_paths() -> list[Path]:
    # GitHub runs both extensions; a `.yaml` workflow must not escape these checks.
    return sorted([*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")])


def _all_workflows() -> list[tuple[str, dict]]:
    return [(path.name, yaml.safe_load(path.read_text(encoding="utf-8"))) for path in _workflow_paths()]


def _jobs(workflow: dict) -> dict:
    return workflow.get("jobs") or {}


def _needs(job: dict) -> list[str]:
    needs = job.get("needs", [])
    return [needs] if isinstance(needs, str) else list(needs)


def _top_level_keys(workflow: dict) -> set[str]:
    # PyYAML (YAML 1.1) parses the bare `on` key as boolean True.
    return {"on" if key is True else key for key in workflow}


def _trigger_names(workflow: dict) -> set[str]:
    triggers = workflow.get("on", workflow.get(True))
    if isinstance(triggers, str):
        return {triggers}
    return set(triggers)


def _triggers(workflow: dict) -> dict:
    triggers = workflow.get("on", workflow.get(True))
    assert isinstance(triggers, dict)
    return {name: config or {} for name, config in triggers.items()}


def _action(step: dict) -> str:
    return str(step.get("uses", "")).split("@", 1)[0]


def _step_signature(step: dict) -> str:
    if "uses" in step:
        return f"uses: {_action(step)}"
    return "run: " + " ".join(str(step["run"]).split())


def _step_publishes(step: dict) -> bool:
    if "uses" not in step:
        return bool(PUBLISH_COMMAND.search(str(step.get("run", ""))))
    action = _action(step)
    if action in NON_PUBLISHING_ACTIONS:
        return False
    if action in BUILD_ACTIONS:
        options = step.get("with") or {}
        # `push` defaults to false; anything else (true, an expression) can publish.
        if options.get("push", False) not in (False, "false"):
            return True
        outputs = str(options.get("outputs", "")) + str(options.get("set", ""))
        return "push=true" in outputs or "type=registry" in outputs
    # docker/login-action, local composite actions, docker:// and unreviewed actions.
    return True


def _token_can_publish(permissions: object) -> bool:
    if permissions is None:
        # Unset at job and workflow level inherits the repository default. It is
        # read-only today, but a settings change can flip it without a PR.
        return True
    if isinstance(permissions, str):
        return permissions != "read-all"
    return any(permissions.get(scope) == "write" for scope in ("packages", "id-token", "contents"))


def _job_can_publish(workflow: dict, job: dict) -> bool:
    if "uses" in job:
        # The only reusable workflow call allowed without the gate is the test job itself.
        return job["uses"] != CI_CALL
    if _token_can_publish(job.get("permissions", workflow.get("permissions"))):
        return True
    if SECRET_EXPRESSION.search(str(job)):
        return True
    return any(_step_publishes(step) for step in job.get("steps", []))


def test_ci_runs_only_on_pull_request_and_workflow_call():
    triggers = _triggers(_load("ci.yml"))

    assert set(triggers) == {"pull_request", "workflow_call"}
    assert triggers["pull_request"] == {"branches": ["main", "dev"]}
    assert triggers["workflow_call"] == {}


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

    # No continue-on-error, with, secrets or strategy on the gating call.
    assert set(test_job) == {"if", "uses"}
    assert test_job["uses"] == CI_CALL
    assert test_job["if"] == SKIP_ON_PR


def test_image_build_is_gated_by_test_result():
    build = _load("docker-build.yml")["jobs"]["build-and-push"]

    assert build["needs"] == "test"
    assert build["if"] == BUILD_GATE


def test_pull_request_image_builds_never_push():
    build = _load("docker-build.yml")["jobs"]["build-and-push"]
    build_steps = [step for step in build["steps"] if _action(step) == "docker/build-push-action"]

    assert len(build_steps) == 2
    for step in build_steps:
        assert step["with"]["push"] == NO_PUSH_ON_PR


def test_every_job_that_can_publish_is_gated_by_tests():
    # A job can publish when it uses an action outside NON_PUBLISHING_ACTIONS, runs
    # a registry or package publishing command, has (or inherits) a token that can
    # write packages, id-token or contents, references a secret, or calls a
    # reusable workflow other than ci.yml. `push: ${{ github.event_name !=
    # 'pull_request' }}` is true on push and tag events, so it is not an exemption.
    publishing = []
    for file_name, workflow in _all_workflows():
        for name, job in _jobs(workflow).items():
            if not _job_can_publish(workflow, job):
                continue
            publishing.append(f"{file_name}:{name}")
            assert "test" in _needs(job), f"{file_name}:{name}"
            assert job.get("if") == BUILD_GATE, f"{file_name}:{name}"

    assert publishing == ["docker-build.yml:build-and-push"]


def test_pull_request_image_builds_never_log_in_to_the_registry():
    build = _load("docker-build.yml")["jobs"]["build-and-push"]
    login_steps = [step for step in build["steps"] if _action(step) == "docker/login-action"]

    assert len(login_steps) == 1
    assert login_steps[0].get("if") == SKIP_ON_PR


def test_ci_failures_are_never_masked_or_skipped():
    # A failing step under continue-on-error, or a test step or job skipped by
    # `if:`, still reports needs.test.result == 'success' and would publish
    # push/tag images. Reject both keys whatever their value.
    for name, job in _load("ci.yml")["jobs"].items():
        for key in ("continue-on-error", "if"):
            assert key not in job, f"ci.yml:{name}:{key}"
            for index, step in enumerate(job.get("steps", [])):
                assert key not in step, f"ci.yml:{name}:step{index}:{key}"


def test_ci_workflow_and_jobs_carry_no_environment_or_defaults_overrides():
    # Workflow- or job-level `env` (for example PYTEST_ADDOPTS=--collect-only) or
    # `defaults.run` (working-directory, shell) would change what the pinned
    # commands test without touching them.
    ci = _load("ci.yml")

    assert _top_level_keys(ci) == CI_WORKFLOW_KEYS
    assert ci["permissions"] == {"contents": "read"}
    for name, job in ci["jobs"].items():
        assert set(job) == CI_JOB_KEYS[name], f"ci.yml:{name}"
    assert ci["jobs"]["sdk"]["defaults"] == {"run": {"working-directory": "sdk"}}


def test_ci_steps_cannot_be_redirected():
    for name, job in _load("ci.yml")["jobs"].items():
        for index, step in enumerate(job["steps"]):
            # No step-level if, continue-on-error, env, shell or working-directory.
            assert set(step) <= CI_STEP_KEYS, f"ci.yml:{name}:step{index}"
            if _action(step) == "actions/checkout":
                # ref, repository or sparse-checkout would change the tested tree.
                assert "with" not in step, f"ci.yml:{name}:step{index}"


def test_ci_job_steps_are_pinned_in_order():
    # Pins every run command (so `|| true` or an inserted step fails) and the
    # action sequence. Action versions are not pinned.
    for name, job in _load("ci.yml")["jobs"].items():
        assert [_step_signature(step) for step in job["steps"]] == CI_STEPS[name], f"ci.yml:{name}"


def test_ci_jobs_run_in_parallel_without_gate_jobs():
    jobs = _load("ci.yml")["jobs"]

    assert set(jobs) == {"service", "sdk"}
    for job in jobs.values():
        assert "needs" not in job


def test_service_job_checks_architecture_then_runs_pytest_with_explicit_workers():
    commands = [step["run"] for step in _load("ci.yml")["jobs"]["service"]["steps"] if "run" in step]

    assert commands[0] == "python3 scripts/check_architecture.py"
    pytest_commands = [command for command in commands if "pytest" in command]
    assert pytest_commands == ["uv run pytest tests -n 4 --dist worksteal"]
    assert "-n auto" not in pytest_commands[0]
    # The pytest11 entry point already loads xdist, so `-p xdist` is redundant.
    assert "-p xdist" not in pytest_commands[0]


def test_serial_pytest_entrypoint_stays_valid():
    pyproject = tomllib.loads((REPOSITORY_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    ini_options = pyproject["tool"]["pytest"]["ini_options"]
    addopts = ini_options.get("addopts", "")
    addopts = addopts if isinstance(addopts, str) else " ".join(addopts)

    assert "-n" not in addopts.split()
    assert "--dist" not in addopts
    assert any(dep.startswith("pytest-xdist") for dep in pyproject["project"]["optional-dependencies"]["dev"])


def test_workflows_accept_only_unprivileged_triggers():
    for file_name, workflow in _all_workflows():
        extra = _trigger_names(workflow) - ALLOWED_TRIGGERS
        assert not extra, f"{file_name}: {sorted(extra)}"


def test_run_scripts_never_interpolate_event_payloads():
    # `${{ github.event.* }}` or `${{ github.head_ref }}` in run: is script
    # injection; pass the value through env: and quote the shell variable.
    for file_name, workflow in _all_workflows():
        for name, job in _jobs(workflow).items():
            for index, step in enumerate(job.get("steps", [])):
                run = str(step.get("run", ""))
                assert not EVENT_PAYLOAD_EXPRESSION.search(run), f"{file_name}:{name}:step{index}"


def test_no_workflow_uses_self_hosted_runners():
    workflows = _all_workflows()
    assert {file_name for file_name, _ in workflows} >= {"ci.yml", "docker-build.yml"}
    for file_name, workflow in workflows:
        for name, job in _jobs(workflow).items():
            if "uses" in job:
                continue
            runs_on = job["runs-on"]
            labels = runs_on if isinstance(runs_on, list) else [runs_on]
            assert "self-hosted" not in labels, f"{file_name}:{name}"
            assert labels == ["ubuntu-latest"], f"{file_name}:{name}"
