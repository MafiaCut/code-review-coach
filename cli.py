"""Backward-compatible launcher for the packaged command-line interface."""

import sys

from code_review_coach.cli import main


if __name__ == "__main__":
    sys.exit(main())
