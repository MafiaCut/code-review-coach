"""HTTP smoke test against the running Flask server."""
import sys, time, urllib.request, urllib.error, json

time.sleep(1.5)

BASE = "http://localhost:5000"

def check(label, url, method="GET", data=None, headers=None):
    try:
        req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
        r = urllib.request.urlopen(req, timeout=5)
        body = json.loads(r.read())
        print(f"OK  {label}")
        return body
    except Exception as e:
        print(f"ERR {label}: {e}")
        sys.exit(1)

# 1. index page
try:
    r = urllib.request.urlopen(BASE + "/", timeout=5)
    assert b"Code Review Coach" in r.read()
    print("OK  GET / (index)")
except Exception as e:
    print(f"ERR GET /: {e}"); sys.exit(1)

# 2. demos list
demos = check("GET /api/demos", BASE + "/api/demos")
assert len(demos) == 2
assert any(d["id"] == "dirty" for d in demos)

# 3. single demo
demo = check("GET /api/demos/dirty", BASE + "/api/demos/dirty")
assert "diff" in demo

# 4. analyze dirty diff
diff = demo["diff"]
payload = json.dumps({"diff": diff}).encode()
result = check("POST /api/analyze (dirty)",
    BASE + "/api/analyze", method="POST",
    data=payload, headers={"Content-Type": "application/json"})
assert result["summary"]["total_findings"] > 0
assert result["summary"]["recommendation"] == "REQUEST_CHANGES"
print(f"    -> {result['summary']['total_findings']} findings, rec={result['summary']['recommendation']}, {result['elapsed_ms']}ms")

# 5. analyze clean diff
demo2 = check("GET /api/demos/clean", BASE + "/api/demos/clean")
payload2 = json.dumps({"diff": demo2["diff"]}).encode()
result2 = check("POST /api/analyze (clean)",
    BASE + "/api/analyze", method="POST",
    data=payload2, headers={"Content-Type": "application/json"})
assert result2["summary"]["by_severity"].get("critical", 0) == 0
assert result2["summary"]["by_severity"].get("high", 0) == 0
print(f"    -> {result2['summary']['total_findings']} findings, rec={result2['summary']['recommendation']}, {result2['elapsed_ms']}ms")

# 6. missing diff key
try:
    req = urllib.request.Request(BASE + "/api/analyze",
        data=json.dumps({}).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    urllib.request.urlopen(req, timeout=5)
    print("ERR should have returned 400"); sys.exit(1)
except urllib.error.HTTPError as e:
    assert e.code == 400
    print("OK  POST /api/analyze (missing diff -> 400)")

print("\nAll HTTP smoke tests PASSED")
