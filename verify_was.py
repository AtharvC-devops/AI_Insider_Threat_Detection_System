"""Live WAS Security Lab Demo — API verification script"""
import requests
import json

BASE = "http://127.0.0.1:8000/api/v1"

# 1. Login as admin
r = requests.post(f"{BASE}/auth/login", json={"email": "admin@soc.corp", "password": "admin123"})
print(f"=== LOGIN ===> HTTP {r.status_code}")
data = r.json()
print(f"  User: {data['user']['name']} ({data['user']['role']})")
TOKEN = data["access_token"]
H = {"Authorization": f"Bearer {TOKEN}"}

# 2. RBAC test: analyst can't access admin endpoint
r2 = requests.post(f"{BASE}/auth/login", json={"email": "analyst@soc.corp", "password": "analyst123"})
analyst_token = r2.json()["access_token"]
r3 = requests.get(f"{BASE}/admin/audit-logs", headers={"Authorization": f"Bearer {analyst_token}"})
print(f"\n=== RBAC TEST ===> Analyst calling /admin/audit-logs: HTTP {r3.status_code} (expected 403)")

# 3. WAS Demo 1: SQL Injection
print("\n=== WAS DEMO 1: SQL INJECTION ===")
r4 = requests.post(f"{BASE}/was/demo/sql-injection", headers=H)
d = r4.json()
print(f"  HTTP {r4.status_code} | Result: {d['result']} | Rows: {d['rows_returned_by_injection']}/{d['total_employees_in_db']} | Alert: {d['alert_id']}")

# 4. WAS Demo 2: XSS Prevention
print("\n=== WAS DEMO 2: XSS PREVENTION ===")
r5 = requests.post(f"{BASE}/was/demo/xss-prevention", headers=H)
d = r5.json()
print(f"  HTTP {r5.status_code} | Result: {d['result']} | Stored safely: {d['stored_as_literal_text']} | Script executed: {d['script_executed']} | Alert: {d['alert_id']}")

# 5. WAS Demo 3: Broken Access Control
print("\n=== WAS DEMO 3: BROKEN ACCESS CONTROL ===")
r6 = requests.post(f"{BASE}/was/demo/broken-access", headers=H)
d = r6.json()
print(f"  HTTP {r6.status_code} | Result: {d['result']} | Analyst got: HTTP {d['actual_status']} (expected 403) | Alert: {d['alert_id']}")

# 6. WAS Demo 4: Brute Force
print("\n=== WAS DEMO 4: BRUTE-FORCE LOGIN ===")
r7 = requests.post(f"{BASE}/was/demo/brute-force", headers=H)
d = r7.json()
print(f"  HTTP {r7.status_code} | Result: {d['result']} | Rate limit HTTP: {d['actual_status']} | Attempts: {len(d['attempts'])} | Alert: {d['alert_id']}")

# 7. WAS Demo 5: API Rate Limit
print("\n=== WAS DEMO 5: API RATE LIMITING ===")
r8 = requests.post(f"{BASE}/was/demo/rate-limit", headers=H)
d = r8.json()
print(f"  HTTP {r8.status_code} | Result: {d['result']} | Rate limit HTTP: {d['actual_status']} | Requests sent: {d['requests_sent']} | Hit at: #{d['hit_429_at_request']} | Alert: {d['alert_id']}")

# 8. Check SOC alerts for WAS entries
print("\n=== SOC ALERTS WITH [WAS-DEMO] TAG ===")
r9 = requests.get(f"{BASE}/alerts", headers=H)
alerts = r9.json()
was_alerts = [a for a in alerts if "[WAS-DEMO]" in a.get("title", "")]
for a in was_alerts:
    print(f"  [{a['severity']}] {a['alert_id']} - {a['title'][:80]}")
print(f"\n  Total WAS alerts: {len(was_alerts)}")

# 9. Security headers check
print("\n=== SECURITY HEADERS ===")
r10 = requests.get("http://127.0.0.1:8000/health")
for h in ["X-Content-Type-Options", "X-Frame-Options", "X-XSS-Protection", "Referrer-Policy"]:
    print(f"  {h}: {r10.headers.get(h, 'MISSING')}")

print("\nALL DEMOS COMPLETE")
