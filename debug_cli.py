import subprocess, sys, os
CLI = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cli.py")
diff = "diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n@@ -1 +1,2 @@\n import os\n+os.system(cmd)\n"
proc = subprocess.run([sys.executable, CLI, "--format", "text"], input=diff, capture_output=True, text=True, timeout=10, encoding="utf-8", errors="replace")
print("RC:", proc.returncode)
print("STDOUT:", repr(proc.stdout[:200]))
print("STDERR:", repr(proc.stderr[:300]))
