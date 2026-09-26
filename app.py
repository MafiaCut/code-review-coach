"""Backward-compatible imports for the packaged web application."""

from code_review_coach.web import app, main

__all__ = ["app", "main"]


if __name__ == "__main__":
    main()
