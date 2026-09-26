"""Quick smoke test run directly."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from analyzer.engine import analyze_diff, result_to_dict
import json

diff = (
    "diff --git a/app.py b/app.py\n"
    "--- a/app.py\n"
    "+++ b/app.py\n"
    "@@ -1 +1,2 @@\n"
    " import os\n"
    '+password = "secret123"\n'
)
result = analyze_diff(diff)
d = result_to_dict(result)
print("findings:", d["summary"]["total_findings"])
print("recommendation:", d["summary"]["recommendation"])
print("files_reviewed:", d["files_reviewed"])
assert d["summary"]["total_findings"] >= 1, "Expected at least one finding"
assert d["summary"]["recommendation"] != "APPROVE", "Expected non-approval for dirty diff"
print("Smoke test PASSED")
