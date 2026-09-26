"""
Demo example 1: A change with multiple clear issues across Python and TypeScript.
This is entirely synthetic data with no real credentials or personal information.
"""

DEMO_DIRTY = """\
diff --git a/auth/login.py b/auth/login.py
index 0000000..1111111 100644
--- a/auth/login.py
+++ b/auth/login.py
@@ -1,6 +1,35 @@
+import os
+import subprocess
+import requests
+
+DB_PASSWORD = "s3cur3P@ssw0rd!"
+API_KEY = "sk-prod-aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"
+
+def authenticate_user(username, password):
+    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
+    cursor.execute(query)
+    return cursor.fetchone()
+
+def run_report(report_name):
+    os.system("generate_report " + report_name)
+
+def fetch_config(url):
+    resp = requests.get(url)
+    data = resp.json()
+    return data
+
+def process_input(user_data):
+    result = eval(user_data)
+    return result
+
+def get_items(items=[]):
+    items.append("new_item")
+    return items
+
+def risky_compare(x):
+    if x is 42:
+        return True
+    return False
+
+def divide(a, b):
+    try:
+        return a / b
+    except:
+        pass
diff --git a/frontend/dashboard.ts b/frontend/dashboard.ts
index 0000000..2222222 100644
--- a/frontend/dashboard.ts
+++ b/frontend/dashboard.ts
@@ -1,4 +1,18 @@
+const SECRET_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.fakepayload.fakesig";
+
+function renderUserContent(userData: string): void {
+    const container = document.getElementById('content');
+    container.innerHTML = userData;
+}
+
+function loadUser(id: number) {
+    fetch('/api/user/' + id)
+        .then(res => res.json())
+        .then(data => {
+            if (data.role == "admin") {
+                showAdminPanel();
+            }
+        })
+}
+
+function silentFail() {
+    try {
+        riskyOperation();
+    } catch(e) {}
+}
diff --git a/tests/test_auth.py b/tests/test_auth.py
index 0000000..3333333 100644
--- a/tests/test_auth.py
+++ b/tests/test_auth.py
@@ -1,3 +1,8 @@
+import unittest
+
+class TestAuth(unittest.TestCase):
+    def test_authenticate_returns_something(self):
+        # TODO: test with invalid credentials
+        assert True
"""

DEMO_DIRTY_TITLE = "Demo 1 — Auth service with multiple issues"
DEMO_DIRTY_DESCRIPTION = (
    "A synthetic change to an authentication module and dashboard component. "
    "Contains hardcoded credentials, SQL injection, unsafe eval(), mutable default arguments, "
    "XSS via innerHTML, loose equality, empty catch block, and a placeholder test."
)
