import re
import shlex
from itertools import product
from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
_APPROVED_ACTION_USES = frozenset(
    {
        "actions/checkout@v4",
        "actions/setup-python@v5",
        "astral-sh/setup-uv@v6",
    }
)
_DIRECT_TOKEN_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_@%+=:,./-"
)
_DIRECT_TOKEN_PATTERN = rf"[{re.escape(''.join(sorted(_DIRECT_TOKEN_CHARS)))}]+"
_DIRECT_COMMAND_PATTERN = (
    rf"[ \t]*(?:uv[ \t]+sync[ \t]+--locked"
    rf"|uv[ \t]+run[ \t]+pytest(?:[ \t]+{_DIRECT_TOKEN_PATTERN})*)[ \t]*"
)
_DIRECT_RUN_PATTERN = re.compile(
    rf"{_DIRECT_COMMAND_PATTERN}(?:\n{_DIRECT_COMMAND_PATTERN})*\n?"
)
_NON_BASH_TRIM_CHARACTERS = (
    "\u000b",
    "\u000c",
    "\u000d",
    "\u001c",
    "\u001d",
    "\u001e",
    "\u001f",
    "\u0085",
    "\u00a0",
    "\u1680",
    "\u2000",
    "\u2001",
    "\u2002",
    "\u2003",
    "\u2004",
    "\u2005",
    "\u2006",
    "\u2007",
    "\u2008",
    "\u2009",
    "\u200a",
    "\u2028",
    "\u2029",
    "\u202f",
    "\u205f",
    "\u3000",
)
_PYTHON_NON_BASH_LINE_BOUNDARIES = (
    "\u000b",
    "\u000c",
    "\u000d",
    "\u001c",
    "\u001d",
    "\u001e",
    "\u2028",
    "\u2029",
)


def _direct_command_tokens(line):
    assert all(char in _DIRECT_TOKEN_CHARS or char in " \t" for char in line)
    lexer = shlex.shlex(line, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    lexer.commenters = "#"
    command = list(lexer)
    assert command
    assert all(set(token) <= _DIRECT_TOKEN_CHARS for token in command)
    assert command == ["uv", "sync", "--locked"] or command[:3] == [
        "uv",
        "run",
        "pytest",
    ]
    return command


def _assert_unredirected_environment(scope):
    environment = scope.get("env", {})
    assert isinstance(environment, dict)
    assert environment == {}


def _assert_unredirected_run_defaults(scope):
    defaults = scope.get("defaults", {})
    assert isinstance(defaults, dict)
    run_defaults = defaults.get("run", {})
    assert isinstance(run_defaults, dict)
    assert "working-directory" not in run_defaults
    assert "shell" not in run_defaults


def _live_run_commands(workflow_text):
    workflow = yaml.safe_load(workflow_text)
    jobs = workflow.get("jobs")
    assert isinstance(jobs, dict)
    _assert_unredirected_environment(workflow)
    _assert_unredirected_run_defaults(workflow)

    commands = []
    for job in jobs.values():
        assert isinstance(job, dict)
        assert "uses" not in job
        _assert_unredirected_environment(job)
        _assert_unredirected_run_defaults(job)
        steps = job.get("steps", [])
        assert isinstance(steps, list)
        for step in steps:
            assert isinstance(step, dict)
            _assert_unredirected_environment(step)
            assert "working-directory" not in step
            assert "shell" not in step
            if "uses" in step:
                assert isinstance(step["uses"], str)
                assert step["uses"] in _APPROVED_ACTION_USES
            if "run" not in step:
                continue
            assert isinstance(step["run"], str)
            assert _DIRECT_RUN_PATTERN.fullmatch(step["run"])
            for line in step["run"].splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                commands.append(_direct_command_tokens(line))
    return commands


def _workflow_with_commands(install_command, pytest_command):
    return f"""
    jobs:
      test:
        steps:
          - run: |
              {install_command}
          - run: |
              {pytest_command}
    """


def _workflow_from_run_scalars(*run_scalars):
    return yaml.safe_dump(
        {
            "jobs": {
                "test": {
                    "steps": [{"run": run_scalar} for run_scalar in run_scalars]
                }
            }
        },
        allow_unicode=False,
        sort_keys=False,
    )


def _unicode_id(character):
    return f"U+{ord(character):04X}"


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


def test_workflow_contract_rejects_commands_after_and():
    """A benign prefix cannot hide later dependency or test commands."""
    with pytest.raises(AssertionError):
        _assert_locked_uv_workflow(
            """
            jobs:
              test:
                steps:
                  - run: uv sync --locked
                  - run: uv run pytest tests/ -v
                  - run: printf done && pip install anyio && pytest tests/ -q
            """,
        )


@pytest.mark.parametrize(
    "workflow",
    [
        pytest.param(
            """
            jobs:
              test:
                steps:
                  - run: uv sync --locked
                  - run: uv run pytest tests/ -v
                  - run: printf done; pip install anyio; pytest tests/ -q
            """,
            id="semicolon-separated-install-and-pytest",
        ),
        pytest.param(
            """
            jobs:
              test:
                steps:
                  - run: uv sync --locked
                  - run: uv run pytest tests/ -v
                  - run: false || pip install anyio
            """,
            id="or-separated-install",
        ),
        pytest.param(
            """
            jobs:
              test:
                steps:
                  - run: uv sync --locked
                  - run: |
                      uv run pytest tests/ -v
                      pip install anyio
            """,
            id="newline-separated-install",
        ),
        pytest.param(
            """
            jobs:
              test:
                steps:
                  - run: uv sync --locked
                  - run: uv run pytest tests/ -v
                  - run: uv run echo "$(pip install anyio)"
            """,
            id="command-substitution-install",
        ),
    ],
)
def test_workflow_contract_rejects_hidden_executable_paths(workflow):
    """Compound and indirect scalars cannot add executable install paths."""
    with pytest.raises(AssertionError):
        _assert_locked_uv_workflow(workflow)


def test_workflow_contract_accepts_direct_canonical_commands():
    """The bounded grammar accepts the repository's canonical direct commands."""
    _assert_locked_uv_workflow(
        """
        jobs:
          test:
            steps:
              - run: uv sync --locked
              - run: uv run pytest tests/ -v
        """
    )


@pytest.mark.parametrize(
    "workflow",
    [
        pytest.param(
            """
            jobs:
              test:
                env:
                  UV_PROJECT: alternate/pyproject.toml
                steps:
                  - run: uv sync --locked
                  - run: uv run pytest tests/ -v
            """,
            id="job-environment",
        ),
        pytest.param(
            """
            jobs:
              test:
                steps:
                  - run: uv sync --locked
                    env:
                      UV_PROJECT: alternate/pyproject.toml
                  - run: uv run pytest tests/ -v
            """,
            id="step-environment",
        ),
    ],
)
def test_workflow_contract_rejects_uv_project_redirection(workflow):
    """Job and step environments cannot redirect uv to another project."""
    with pytest.raises(AssertionError):
        _assert_locked_uv_workflow(workflow)


@pytest.mark.parametrize(
    "workflow",
    [
        pytest.param(
            """
            defaults:
              run:
                working-directory: alternate
            jobs:
              test:
                steps:
                  - run: uv sync --locked
                  - run: uv run pytest tests/ -v
            """,
            id="workflow-default",
        ),
        pytest.param(
            """
            jobs:
              test:
                defaults:
                  run:
                    working-directory: alternate
                steps:
                  - run: uv sync --locked
                  - run: uv run pytest tests/ -v
            """,
            id="job-default",
        ),
        pytest.param(
            """
            jobs:
              test:
                steps:
                  - run: uv sync --locked
                    working-directory: alternate
                  - run: uv run pytest tests/ -v
            """,
            id="step-setting",
        ),
    ],
)
def test_workflow_contract_rejects_working_directory_redirection(workflow):
    """Run defaults and steps cannot select another project directory."""
    with pytest.raises(AssertionError):
        _assert_locked_uv_workflow(workflow)


def test_workflow_contract_rejects_executable_local_actions():
    """Repository actions cannot add an unexamined dependency install path."""
    with pytest.raises(AssertionError):
        _assert_locked_uv_workflow(
            """
            jobs:
              test:
                steps:
                  - uses: ./.github/actions/dependency-installer
                  - run: uv sync --locked
                  - run: uv run pytest tests/ -v
            """
        )


@pytest.mark.parametrize(
    "uses",
    [
        pytest.param(
            "$/.github/actions/dependency-installer",
            id="self-repository-action",
        ),
        pytest.param(
            "gaoharimran29-glitch/AynOps/.github/actions/"
            "dependency-installer@main",
            id="same-repository-action-at-ref",
        ),
    ],
)
def test_workflow_contract_rejects_unapproved_action_sources(uses):
    """Only the workflow's approved setup actions can execute."""
    with pytest.raises(AssertionError):
        _assert_locked_uv_workflow(
            yaml.safe_dump(
                {
                    "jobs": {
                        "test": {
                            "steps": [
                                {"uses": uses},
                                {"run": "uv sync --locked"},
                                {"run": "uv run pytest tests/ -v"},
                            ]
                        }
                    }
                },
                sort_keys=False,
            )
        )


def test_workflow_contract_rejects_job_level_reusable_workflows():
    """Another job cannot delegate dependency installation to a workflow."""
    with pytest.raises(AssertionError):
        _assert_locked_uv_workflow(
            """
            jobs:
              hidden-install:
                uses: ./.github/workflows/install.yml
              test:
                steps:
                  - run: uv sync --locked
                  - run: uv run pytest tests/ -v
            """
        )


@pytest.mark.parametrize(
    ("runs_on", "environment"),
    [
        pytest.param(
            "windows-latest",
            {"uv_project": "alternate/pyproject.toml"},
            id="windows-case-insensitive-uv-project",
        ),
        pytest.param(
            "ubuntu-latest",
            {"BASH_ENV": ".github/ci-bootstrap"},
            id="bash-startup-file",
        ),
        pytest.param(
            "ubuntu-latest",
            {"PATH": "${{ github.workspace }}/bin"},
            id="repository-command-shadow",
        ),
    ],
)
def test_workflow_contract_rejects_custom_execution_environment(
    runs_on, environment
):
    """Custom environments cannot alter project or executable authority."""
    with pytest.raises(AssertionError):
        _assert_locked_uv_workflow(
            yaml.safe_dump(
                {
                    "jobs": {
                        "test": {
                            "runs-on": runs_on,
                            "env": environment,
                            "steps": [
                                {"run": "uv sync --locked"},
                                {"run": "uv run pytest tests/ -v"},
                            ],
                        }
                    }
                },
                sort_keys=False,
            )
        )


@pytest.mark.parametrize(
    "workflow",
    [
        pytest.param(
            """
            defaults:
              run:
                shell: python
            jobs:
              test:
                steps:
                  - run: uv sync --locked
                  - run: uv run pytest tests/ -v
            """,
            id="workflow-default",
        ),
        pytest.param(
            """
            jobs:
              test:
                defaults:
                  run:
                    shell: python
                steps:
                  - run: uv sync --locked
                  - run: uv run pytest tests/ -v
            """,
            id="job-default",
        ),
        pytest.param(
            """
            jobs:
              test:
                steps:
                  - run: uv sync --locked
                    shell: python
                  - run: uv run pytest tests/ -v
            """,
            id="step-setting",
        ),
    ],
)
def test_workflow_contract_rejects_custom_shell_context(workflow):
    """Canonical command text cannot be interpreted by a different shell."""
    with pytest.raises(AssertionError):
        _assert_locked_uv_workflow(workflow)


@pytest.mark.parametrize(
    "suffix",
    _NON_BASH_TRIM_CHARACTERS,
    ids=_unicode_id,
)
def test_workflow_contract_rejects_python_trim_characters_preserved_by_bash(
    suffix,
):
    """Python-only trimming cannot authenticate a different Bash option."""
    with pytest.raises(AssertionError):
        _assert_locked_uv_workflow(
            _workflow_from_run_scalars(
                f"uv sync --locked{suffix}",
                "uv run pytest tests/ -v",
            )
        )


@pytest.mark.parametrize(
    "boundary",
    _PYTHON_NON_BASH_LINE_BOUNDARIES,
    ids=_unicode_id,
)
def test_workflow_contract_rejects_python_line_boundaries_preserved_by_bash(
    boundary,
):
    """Python-only line boundaries cannot invent separate Bash commands."""
    with pytest.raises(AssertionError):
        _assert_locked_uv_workflow(
            _workflow_from_run_scalars(
                f"uv sync --locked{boundary}uv run pytest tests/ -v"
            )
        )


def test_workflow_contract_rejects_nbsp_prefixed_hash_line():
    """A hash preceded by a non-Bash blank remains executable shell text."""
    with pytest.raises(AssertionError):
        _assert_locked_uv_workflow(
            _workflow_from_run_scalars(
                "\u00a0#alternate\nuv sync --locked\nuv run pytest tests/ -v"
            )
        )


def test_workflow_contract_rejects_midword_hash_suffixes():
    """Forbidden mid-word hash suffixes never become canonical tokens."""
    suffixes = (
        "".join(chars)
        for width in range(1, 4)
        for chars in product("ab09_-", repeat=width)
    )
    for suffix in suffixes:
        with pytest.raises(AssertionError):
            _assert_locked_uv_workflow(
                _workflow_with_commands(
                    f"uv sync --locked#{suffix}",
                    "uv run pytest tests/ -v",
                )
            )
        with pytest.raises(AssertionError):
            _assert_locked_uv_workflow(
                _workflow_with_commands(
                    "uv sync --locked",
                    f"uv run pytest#{suffix} tests/ -v",
                )
            )


@pytest.mark.parametrize(
    ("install_command", "pytest_command"),
    [
        ("uv sync \"--locked\"", "uv run pytest tests/ -v"),
        ('uv "sync" --locked', "uv run pytest tests/ -v"),
        ("uv sync --locked", "uv \"run\" pytest tests/ -v"),
        ("uv sync --locked", "uv run \"pytest\" tests/ -v"),
    ],
)
def test_workflow_contract_rejects_quoted_command_tokens(
    install_command, pytest_command
):
    """Quoted command spellings are outside the shell-free grammar."""
    with pytest.raises(AssertionError):
        _assert_locked_uv_workflow(
            _workflow_with_commands(install_command, pytest_command)
        )


@pytest.mark.parametrize(
    ("install_command", "pytest_command"),
    [
        ("uv sync --lock\\ed", "uv run pytest tests/ -v"),
        ("uv s\\ync --locked", "uv run pytest tests/ -v"),
        ("uv sync --locked", "uv r\\un pytest tests/ -v"),
        ("uv sync --locked", "uv run py\\test tests/ -v"),
    ],
)
def test_workflow_contract_rejects_backslash_escaped_command_letters(
    install_command, pytest_command
):
    """Backslash-escaped command spellings are outside the shell-free grammar."""
    with pytest.raises(AssertionError):
        _assert_locked_uv_workflow(
            _workflow_with_commands(install_command, pytest_command)
        )


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
