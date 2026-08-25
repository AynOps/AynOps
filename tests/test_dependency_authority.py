from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]


def test_uv_lock_is_the_single_dependency_authority():
    """The repository and CI use the locked uv project, not a legacy manifest."""
    assert not (ROOT / "requirements.txt").exists()
    assert (ROOT / "pyproject.toml").is_file()
    assert (ROOT / "uv.lock").is_file()

    workflow = (ROOT / ".github/workflows/tests.yml").read_text(encoding="utf-8")
    assert "uv sync --locked" in workflow
    assert re.search(r"(?m)^\s*- run:\s*uv run pytest\b", workflow)
    assert "pip install -r" not in workflow
