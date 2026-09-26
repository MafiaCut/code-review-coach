"""Backward-compatible launcher for ``python __main__.py``."""

import sys

from code_review_coach.cli import main


if __name__ == "__main__":
    sys.exit(main())
