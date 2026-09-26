"""Inspect what findings the clean demo actually produces."""
import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from analyzer.engine import analyze_diff, result_to_dict
from code_review_coach.demos.demo_clean import DEMO_CLEAN

result = analyze_diff(DEMO_CLEAN)
d = result_to_dict(result)
print("Total findings:", d["summary"]["total_findings"])
print("By severity:", d["summary"]["by_severity"])
print("By category:", d["summary"]["by_category"])
print("Recommendation:", d["summary"]["recommendation"])
print()
for f in d["findings"]:
    print(f"  [{f['severity'].upper()}] {f['category']} @ {f['filename']}:{f['line_number']}")
    print(f"    {f['explanation'][:80]}")
    print(f"    Matched: {f['matched_text'][:60]}")
