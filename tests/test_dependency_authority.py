import shlex
from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]


def _live_run_commands(workflow_text):
    workflow = yaml.safe_load(workflow_text)
    jobs = workflow.get("jobs")
    assert isinstance(jobs, dict)

    commands = []
    for job in jobs.values():
        assert isinstance(job, dict)
        steps = job.get("steps", [])
        assert isinstance(steps, list)
        for step in steps:
            assert isinstance(step, dict)
            if "run" not in step:
                continue
            assert isinstance(step["run"], str)
            for line in step["run"].splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                commands.append(shlex.split(line, comments=True))
    return commands


def _is_pip_install(command):
    return (
        command[:2] == ["pip", "install"]
        or command[:3] == ["uv", "pip", "install"]
        or command[:4] in (
            ["python", "-m", "pip", "install"],
            ["python3", "-m", "pip", "install"],
        )
    )


def _is_requirements_install(command):
    return any(
        token.startswith("requirements") and token.endswith(".txt")
        for token in command
    )


def _is_pytest_invocation(command):
    return (
        command[:3] == ["uv", "run", "pytest"]
        or command[:1] == ["pytest"]
        or command[:3] in (
            ["python", "-m", "pytest"],
            ["python3", "-m", "pytest"],
        )
    )


def _assert_locked_uv_workflow(workflow_text):
    commands = _live_run_commands(workflow_text)
    locked_sync = [command for command in commands if command == ["uv", "sync", "--locked"]]
    assert len(locked_sync) == 1

    uv_sync = [command for command in commands if command[:2] == ["uv", "sync"]]
    assert uv_sync == [["uv", "sync", "--locked"]]

    assert not any(_is_pip_install(command) for command in commands)
    assert not any(_is_requirements_install(command) for command in commands)

    pytest_commands = [command for command in commands if _is_pytest_invocation(command)]
    assert len(pytest_commands) == 1
    assert pytest_commands[0][:3] == ["uv", "run", "pytest"]


def _assert_dependency_authority(root, workflow_text):
    assert not list(root.glob("requirements*.txt"))
    assert (root / "pyproject.toml").is_file()
    assert (root / "uv.lock").is_file()
    _assert_locked_uv_workflow(workflow_text)


def test_uv_lock_is_the_single_dependency_authority():
    """The repository and CI use the locked uv project, not a legacy manifest."""
    workflow = (ROOT / ".github/workflows/tests.yml").read_text(encoding="utf-8")
    _assert_dependency_authority(ROOT, workflow)


@pytest.mark.parametrize(
    "workflow",
    [
        """
        jobs:
          test:
            steps:
              - run: uv sync --locked
              - run: uv run pytest tests/ -v
              - run: pytest tests/ -v
        """,
        """
        jobs:
          test:
            steps:
              - run: echo "uv sync --locked"
              - run: uv sync
              - run: uv run pytest tests/ -v
        """,
        """
        jobs:
          test:
            steps:
              - run: uv sync --locked
              - run: uv run pytest tests/ -v
              - run: pip install -r requirements-dev.txt
        """,
        """
        jobs:
          test:
            expected_install: uv sync --locked
            steps:
              - run: echo "uv run pytest tests/ -v"
        """,
    ],
)
def test_workflow_contract_rejects_non_authoritative_variants(workflow):
    with pytest.raises(AssertionError):
        _assert_locked_uv_workflow(workflow)


def test_manifest_contract_rejects_requirements_variants(tmp_path):
    (tmp_path / "pyproject.toml").touch()
    (tmp_path / "uv.lock").touch()
    (tmp_path / "requirements-dev.txt").touch()

    with pytest.raises(AssertionError):
        _assert_dependency_authority(
            tmp_path,
            """
            jobs:
              test:
                steps:
                  - run: uv sync --locked
                  - run: uv run pytest tests/ -v
            """,
        )
