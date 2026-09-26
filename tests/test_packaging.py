"""Checks that runtime code and assets are available from the package."""

from importlib import resources
from pathlib import Path


def test_static_ui_is_a_package_resource():
    static_page = resources.files("code_review_coach").joinpath("static/index.html")
    assert static_page.is_file()
    assert "Code Review Coach" in static_page.read_text(encoding="utf-8")


def test_demo_data_is_importable_from_package():
    from code_review_coach.demos.demo_clean import DEMO_CLEAN

    assert "diff --git" in DEMO_CLEAN


def test_command_entry_points_target_package_modules():
    pyproject = (Path(__file__).parents[1] / "pyproject.toml").read_text(encoding="utf-8")
    assert 'review-coach = "code_review_coach.cli:main"' in pyproject
    assert 'review-coach-web = "code_review_coach.web:main"' in pyproject
