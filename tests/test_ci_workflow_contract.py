"""CI shape contract (AGENTS.md "CI 파이프라인 성능 규정" rules 3, 7, 9, 10, 11).

These tests pin the workflow invariants that the CI performance changes rely on:
one test execution per pushed ref or PR sync (a release tag push re-tests the SHA
its branch push already tested), image publishing gated by the test result, PR
image builds that never publish or log in, and an explicit pytest-xdist worker count.

"One test execution" is checked across every workflow with a push or pull_request
trigger, counting each job that runs `pytest` in a `run:` step or calls a reusable
workflow. Tests started some other way (a local composite action, `make`) are not seen.

The publish gate is only as strong as ci.yml's own result, so ci.yml is pinned
structurally: its workflow, job and step key sets (no `if`, `continue-on-error`,
`env`, `shell` or `working-directory`, and `defaults` only for the sdk job), the
ordered steps of each job, setup-uv's inputs, and a checkout without `with`. Any
job in any workflow that can publish must wait for the test job, and workflows
accept only unprivileged triggers and never interpolate event payloads into `run:`.
The detection helpers are unit-tested against synthetic workflows at the end of
this file.

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

import pytest
import yaml

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = REPOSITORY_ROOT / ".github" / "workflows"

BUILD_GATE = (
    "${{ !cancelled() && (needs.test.result == 'success' || "
    "(github.event_name == 'pull_request' && needs.test.result == 'skipped')) }}"
)
NO_PUSH_ON_PR = "${{ github.event_name != 'pull_request' }}"
SKIP_ON_PR = "github.event_name != 'pull_request'"
CI_CALL = "./.github/workflows/ci.yml"
# Exact inputs of the two PR-reachable image builds. `outputs` (type=image,push=true
# or type=registry), `cache-to: type=registry` and similar inputs could publish.
BUILD_STEP_INPUTS = {"context", "file", "target", "push", "tags", "labels"}
# The images are built FROM python:3.12-slim, so CI tests the same interpreter.
SETUP_UV_INPUTS = {"python-version": "3.12", "enable-cache": True}

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
REGISTRY_OUTPUT = re.compile(r"push\s*=\s*true|type\s*=\s*registry", re.I)
# pull_request_target, workflow_run, issue_comment and similar triggers run with
# base-repository secrets or write tokens on behalf of untrusted actors.
ALLOWED_TRIGGERS = frozenset({"push", "pull_request", "workflow_dispatch", "workflow_call", "schedule"})
# The body of a `${{ ... }}` expression, up to its closing `}}`. It may contain single
# braces, as in format('{0}', ...). Context and property names are case-insensitive.
_EXPRESSION_BODY = r"\$\{\{(?:(?!\}\}).)*"
# github.event (dot, bracket or as a function argument such as toJSON(github.event))
# and github.head_ref. github.event_name does not match.
EVENT_PAYLOAD_EXPRESSION = re.compile(
    _EXPRESSION_BODY + r"\bgithub\s*(?:\.\s*(?:event|head_ref)\b|\[\s*['\"](?:event|head_ref)['\"])",
    re.S | re.I,
)
# secrets.NAME, secrets['NAME'], toJSON(secrets) and format('{0}', secrets.NAME).
SECRET_EXPRESSION = re.compile(_EXPRESSION_BODY + r"\bsecrets\b", re.S | re.I)
# pytest-xdist options in any spelling: -n 4, -n4, -nauto, --numprocesses=auto, --dist=load.
XDIST_OPTION = re.compile(r"(?:^|\s)(?:-n\S*|--numprocesses\b|--maxprocesses\b|--dist\b|--tx\b)")
TEST_COMMAND = re.compile(r"\bpytest\b")
TEST_TRIGGERS = frozenset({"push", "pull_request"})

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


def _strings(node: object) -> list[str]:
    # Every string key and value under a parsed YAML node, searched one at a time so
    # that a pattern never spans two values.
    if isinstance(node, str):
        return [node]
    if isinstance(node, dict):
        return [text for key, value in node.items() for text in (*_strings(key), *_strings(value))]
    if isinstance(node, list):
        return [text for item in node for text in _strings(item)]
    return []


def _references_secret(node: object) -> bool:
    return any(SECRET_EXPRESSION.search(text) for text in _strings(node))


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
        # outputs: type=image,push=true / type=registry, cache-to: type=registry, set: *.push=true.
        return any(REGISTRY_OUTPUT.search(text) for text in _strings(options))
    # docker/login-action, local composite actions, docker:// and unreviewed actions.
    return True


def _token_can_publish(permissions: object) -> bool:
    if permissions is None:
        # Unset at job and workflow level inherits the repository default. It is
        # read-only today, but a settings change can flip it without a PR.
        return True
    if isinstance(permissions, str):
        return permissions != "read-all"
    # Any write scope counts: packages, contents and id-token publish directly, and
    # statuses, checks, deployments or actions could forge a result a required check reads.
    return any(value not in ("read", "none") for value in permissions.values())


def _job_can_publish(workflow: dict, job: dict) -> bool:
    if "uses" in job:
        # The only reusable workflow call allowed without the gate is the test job itself.
        return job["uses"] != CI_CALL
    if _token_can_publish(job.get("permissions", workflow.get("permissions"))):
        return True
    # Workflow-level env is visible to every job's steps, so a secret there counts too.
    if _references_secret(job) or _references_secret(workflow.get("env")):
        return True
    return any(_step_publishes(step) for step in job.get("steps", []))


def _job_runs_tests(job: dict) -> bool:
    # Any reusable workflow call may run tests, so every call counts.
    if "uses" in job:
        return True
    return any(TEST_COMMAND.search(str(step.get("run", ""))) for step in job.get("steps", []))


def _addopts_use_xdist(addopts: object) -> bool:
    text = addopts if isinstance(addopts, str) else " ".join(addopts)
    return bool(XDIST_OPTION.search(text))


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


def test_tests_run_once_per_push_and_pull_request():
    # Together with the two trigger tests and the test job's `if:`, a push runs only
    # Docker Build & Push's test job and a PR sync runs only CI's own jobs. A new
    # push- or PR-triggered workflow or job that re-runs pytest fails here.
    runners = [
        f"{file_name}:{name}"
        for file_name, workflow in _all_workflows()
        if _trigger_names(workflow) & TEST_TRIGGERS
        for name, job in _jobs(workflow).items()
        if _job_runs_tests(job)
    ]

    assert runners == ["ci.yml:service", "ci.yml:sdk", "docker-build.yml:test"]


def test_image_build_is_gated_by_test_result():
    build = _load("docker-build.yml")["jobs"]["build-and-push"]

    assert build["needs"] == "test"
    assert build["if"] == BUILD_GATE


def test_pull_request_image_builds_never_push():
    build = _load("docker-build.yml")["jobs"]["build-and-push"]
    build_steps = [step for step in build["steps"] if _action(step) in BUILD_ACTIONS]

    assert [_action(step) for step in build_steps] == ["docker/build-push-action"] * 2
    for step in build_steps:
        assert set(step["with"]) == BUILD_STEP_INPUTS
        assert step["with"]["push"] == NO_PUSH_ON_PR


def test_every_job_that_can_publish_is_gated_by_tests():
    # A job can publish when it uses an action outside NON_PUBLISHING_ACTIONS, runs
    # a registry or package publishing command, has (or inherits) a token with any
    # write scope, references a secret in the job or in workflow-level env, or calls
    # a reusable workflow other than ci.yml. `push: ${{ github.event_name !=
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
    # Pins every run command (so `|| true` or an inserted step fails), the action
    # sequence and setup-uv's inputs. Action versions are not pinned.
    for name, job in _load("ci.yml")["jobs"].items():
        assert [_step_signature(step) for step in job["steps"]] == CI_STEPS[name], f"ci.yml:{name}"
        for index, step in enumerate(job["steps"]):
            if _action(step) == "astral-sh/setup-uv":
                assert step.get("with") == SETUP_UV_INPUTS, f"ci.yml:{name}:step{index}"


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


def test_serial_pytest_entrypoint_stays_valid(request):
    # pyproject.toml must be the configuration pytest actually read (a pytest.toml or
    # pytest.ini, including one under tests/, would take precedence), and neither of
    # its pytest tables may carry xdist options.
    assert request.config.inipath is not None
    assert request.config.inipath.resolve() == REPOSITORY_ROOT / "pyproject.toml"
    pyproject = tomllib.loads((REPOSITORY_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    pytest_config = pyproject["tool"]["pytest"]

    for table in (pytest_config, pytest_config.get("ini_options", {})):
        assert not _addopts_use_xdist(table.get("addopts", ""))
    assert any(dep.startswith("pytest-xdist") for dep in pyproject["project"]["optional-dependencies"]["dev"])


def test_workflows_accept_only_unprivileged_triggers():
    for file_name, workflow in _all_workflows():
        extra = _trigger_names(workflow) - ALLOWED_TRIGGERS
        assert not extra, f"{file_name}: {sorted(extra)}"


def test_run_scripts_never_interpolate_event_payloads():
    # `${{ github.event... }}` or `${{ github.head_ref }}` in run: is script
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


# Detection helpers against synthetic workflows. These pin what the checks above
# treat as publishing, as a secret, as an event payload and as an xdist option.

READ_ONLY = {"contents": "read"}
UPLOAD = {"run": 'curl --oauth2-bearer "$UPLOAD_TOKEN" --upload-file dist/sdk.whl https://upload.example.invalid/'}
LINT_STEPS = [{"uses": "actions/checkout@v5"}, {"uses": "astral-sh/setup-uv@v6"}, {"run": "uv run ruff check ."}]
BUILD_WITH = {"context": ".", "file": "docker/Dockerfile", "push": False}


def _upload_job(**extra: object) -> dict:
    return {"runs-on": "ubuntu-latest", "steps": [UPLOAD], **extra}


def _build_job(**options: object) -> dict:
    return {"runs-on": "ubuntu-latest", "steps": [{"uses": "docker/build-push-action@v5", "with": options}]}


@pytest.mark.parametrize(
    ("workflow", "job", "expected"),
    [
        pytest.param(
            {"permissions": READ_ONLY, "env": {"UPLOAD_TOKEN": "${{ secrets.UPLOAD_TOKEN }}"}},
            _upload_job(),
            True,
            id="workflow-env-secret",
        ),
        pytest.param(
            {"permissions": READ_ONLY},
            _upload_job(env={"UPLOAD_TOKEN": "${{ format('{0}', secrets.UPLOAD_TOKEN) }}"}),
            True,
            id="job-env-format-secret",
        ),
        pytest.param(
            {"permissions": READ_ONLY},
            _upload_job(env={"UPLOAD_TOKEN": "${{ secrets['UPLOAD_TOKEN'] }}"}),
            True,
            id="job-env-bracket-secret",
        ),
        pytest.param(
            {"permissions": READ_ONLY},
            {"runs-on": "ubuntu-latest", "steps": [{"run": "echo '${{ toJSON(secrets) }}' > all.json"}]},
            True,
            id="run-tojson-secrets",
        ),
        pytest.param({}, _upload_job(permissions={"statuses": "write", "pages": "write"}), True, id="statuses-write"),
        pytest.param({"permissions": "write-all"}, {"runs-on": "ubuntu-latest", "steps": LINT_STEPS}, True, id="write-all"),
        pytest.param({}, {"runs-on": "ubuntu-latest", "steps": LINT_STEPS}, True, id="inherited-permissions"),
        pytest.param(
            {"permissions": READ_ONLY}, _build_job(**BUILD_WITH, outputs="type=image,push=true"), True, id="outputs-push"
        ),
        pytest.param(
            {"permissions": READ_ONLY},
            _build_job(**BUILD_WITH, **{"cache-to": "type=registry,ref=ghcr.io/o/cache"}),
            True,
            id="cache-to-registry",
        ),
        pytest.param(
            {"permissions": READ_ONLY}, {"uses": "o/other/.github/workflows/release.yml@main"}, True, id="reusable-call"
        ),
        pytest.param(
            {"permissions": READ_ONLY},
            {"runs-on": "ubuntu-latest", "steps": [{"uses": "./.github/actions/release"}]},
            True,
            id="local-action",
        ),
        pytest.param({"permissions": READ_ONLY}, _build_job(**BUILD_WITH), False, id="push-false-build"),
        pytest.param({"permissions": READ_ONLY}, {"runs-on": "ubuntu-latest", "steps": LINT_STEPS}, False, id="lint"),
        pytest.param(
            {"permissions": {}}, {"runs-on": "ubuntu-latest", "steps": LINT_STEPS}, False, id="empty-permissions"
        ),
        pytest.param(
            {"permissions": READ_ONLY, "env": {"REGISTRY": "ghcr.io"}},
            {
                "runs-on": "ubuntu-latest",
                "steps": [{"env": {"TITLE": "${{ github.event.pull_request.title }}"}, "run": 'echo "$TITLE"'}],
            },
            False,
            id="env-pass-through",
        ),
        pytest.param({}, {"uses": CI_CALL}, False, id="ci-call"),
    ],
)
def test_job_can_publish_detection(workflow, job, expected):
    assert _job_can_publish(workflow, job) is expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        pytest.param("${{ secrets.UPLOAD_TOKEN }}", True, id="dot"),
        pytest.param("${{ secrets['UPLOAD_TOKEN'] }}", True, id="bracket"),
        pytest.param("${{ toJSON(secrets) }}", True, id="tojson"),
        pytest.param("${{ format('{0}', secrets.UPLOAD_TOKEN) }}", True, id="format"),
        pytest.param("${{\n  secrets.UPLOAD_TOKEN\n}}", True, id="multiline"),
        pytest.param("${{ SECRETS.UPLOAD_TOKEN }}", True, id="uppercase"),
        pytest.param("${{ github.repository_owner }}", False, id="other-context"),
        pytest.param("${{ steps.meta.outputs.tags }} secrets", False, id="word-after-expression"),
        pytest.param("secrets are passed through env", False, id="plain-text"),
    ],
)
def test_secret_expression_forms(text, expected):
    assert bool(SECRET_EXPRESSION.search(text)) is expected


@pytest.mark.parametrize(
    ("run", "expected"),
    [
        pytest.param('echo "${{ github.event.pull_request.title }}"', True, id="dot"),
        pytest.param("echo \"${{ github.event['pull_request']['title'] }}\"", True, id="bracket-after-event"),
        pytest.param("echo \"${{ github['event']['pull_request']['title'] }}\"", True, id="bracket-event"),
        pytest.param("echo \"${{ format('{0}', github.event.pull_request.title) }}\"", True, id="format"),
        pytest.param("echo '${{ toJSON(github.event) }}'", True, id="tojson"),
        pytest.param('git switch "${{ github.head_ref }}"', True, id="head-ref"),
        pytest.param("echo \"${{ github['head_ref'] }}\"", True, id="head-ref-bracket"),
        pytest.param('echo "${{ github.event_name }}"', False, id="event-name"),
        pytest.param('echo "${{ github.sha }}" github.event', False, id="word-after-expression"),
        pytest.param('echo "$TITLE"', False, id="env-pass-through"),
    ],
)
def test_event_payload_expression_forms(run, expected):
    assert bool(EVENT_PAYLOAD_EXPRESSION.search(run)) is expected


@pytest.mark.parametrize(
    ("addopts", "expected"),
    [
        pytest.param("-n 4", True, id="n-space"),
        pytest.param("-n4", True, id="n-joined"),
        pytest.param("-q -nauto", True, id="n-auto-joined"),
        pytest.param("--numprocesses=auto", True, id="numprocesses"),
        pytest.param("--dist=worksteal", True, id="dist"),
        pytest.param("--maxprocesses 2", True, id="maxprocesses"),
        pytest.param(["-q", "-n", "4"], True, id="list"),
        pytest.param("", False, id="empty"),
        pytest.param("-q --no-header", False, id="no-header"),
        pytest.param("-ra --strict-markers --durations=10", False, id="other-options"),
        pytest.param(["-q"], False, id="list-without-xdist"),
    ],
)
def test_addopts_xdist_detection(addopts, expected):
    assert _addopts_use_xdist(addopts) is expected
