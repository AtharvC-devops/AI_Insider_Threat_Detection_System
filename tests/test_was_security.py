"""
WAS Security Lab — Automated Test Suite
Tests RBAC enforcement, WAS demo endpoints, security attack prevention, and SOC alert integration.
Run with: PYTHONPATH=backend python -m pytest tests/test_was_security.py -v

Note on rate limiting in tests: The rate limiter uses in-memory state shared across the test run.
Tests that call /auth/login directly are run AFTER the brute-force demo to avoid 5/min spillover.
Token-based tests use create_access_token() directly to bypass login and rate limits.
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.auth import create_access_token
from app.models import UserRole

client = TestClient(app, raise_server_exceptions=False)

# ─── Shared token helpers — use create_access_token to bypass /auth/login rate limit ───

def _analyst_headers() -> dict:
    """Create analyst JWT directly — no /auth/login call needed."""
    token = create_access_token(data={"sub": "analyst@soc.corp", "role": "Security Analyst"})
    return {"Authorization": f"Bearer {token}"}

def _admin_headers() -> dict:
    """Create admin JWT directly — no /auth/login call needed."""
    token = create_access_token(data={"sub": "admin@soc.corp", "role": "Administrator"})
    return {"Authorization": f"Bearer {token}"}

# ─── Test 1: Self-assign Administrator role blocked ─────────────────────────

def test_register_cannot_self_assign_admin():
    """
    Registering with role=Administrator should either:
    - Downgrade to Security Analyst (200), OR
    - Be rejected if email already exists (400), OR
    - Return 422 if Pydantic rejects the enum value
    In any case, the user must NOT end up with Administrator role.
    """
    resp = client.post("/api/v1/auth/register", json={
        "email": "hacker-admin-attempt@was.test",
        "name": "Hacker",
        "password": "hackpass123",
        "role": "Administrator",
        "department": "Hacking"
    })
    if resp.status_code == 200:
        assert resp.json()["role"] != "Administrator", \
            "SECURITY FAILURE: Self-assigned Administrator role was accepted!"
    # 400 = already registered, 422 = schema rejects the Administrator value — both safe
    assert resp.status_code in (200, 400, 422), \
        f"Unexpected status {resp.status_code} — check registration endpoint"

# ─── Test 2: Unauthorized API returns 403 ───────────────────────────────────

def test_analyst_cannot_access_admin_audit_logs():
    """Security Analyst token must receive HTTP 403 on Administrator-only endpoint."""
    resp = client.get("/api/v1/admin/audit-logs", headers=_analyst_headers())
    assert resp.status_code == 403, \
        f"Expected 403 Forbidden, got {resp.status_code}"

# ─── Test 3: Unauthenticated request returns 401 ────────────────────────────

def test_unauthenticated_returns_401():
    """Any protected endpoint without a token must return 401."""
    resp = client.get("/api/v1/employees")
    assert resp.status_code == 401, \
        f"Expected 401 Unauthorized, got {resp.status_code}"

# ─── Test 4: SQL Injection demo is safe ─────────────────────────────────────

def test_was_sql_injection_prevented():
    """WAS SQL injection demo must return result=PREVENTED and 0 injected rows."""
    resp = client.post("/api/v1/was/demo/sql-injection", headers=_admin_headers())
    assert resp.status_code == 200, f"Got {resp.status_code}: {resp.text}"
    data = resp.json()
    assert data["result"] == "PREVENTED"
    assert data["rows_returned_by_injection"] == 0, \
        f"SQL injection returned rows! count={data['rows_returned_by_injection']}"
    assert data["injection_successful"] is False

# ─── Test 5: XSS payload stored safely ──────────────────────────────────────

def test_was_xss_payload_stored_as_plain_text():
    """WAS XSS demo must confirm payload is stored verbatim (not executed)."""
    resp = client.post("/api/v1/was/demo/xss-prevention", headers=_admin_headers())
    assert resp.status_code == 200, f"Got {resp.status_code}: {resp.text}"
    data = resp.json()
    assert data["result"] == "PREVENTED"
    assert data["stored_as_literal_text"] is True, "XSS payload was not stored safely!"
    assert data["script_executed"] is False

# ─── Test 6: Brute-force triggers 429 ───────────────────────────────────────

def test_was_brute_force_triggers_429():
    """Brute-force demo must show actual_status 429 from rate limiter."""
    resp = client.post("/api/v1/was/demo/brute-force", headers=_admin_headers())
    assert resp.status_code == 200, f"Got {resp.status_code}: {resp.text}"
    data = resp.json()
    # Rate limit should fire (5/min) — actual_status must be 429
    assert data["actual_status"] == 429, \
        f"Rate limiter did not fire. actual_status={data['actual_status']}"

# ─── Test 7: API Rate Limit triggers 429 ────────────────────────────────────

def test_was_rate_limit_triggers_429():
    """Rate-limit demo must show actual_status 429 from global limiter."""
    resp = client.post("/api/v1/was/demo/rate-limit", headers=_admin_headers())
    assert resp.status_code == 200, f"Got {resp.status_code}: {resp.text}"
    data = resp.json()
    assert data["actual_status"] == 429, \
        f"API rate limiter did not fire. actual_status={data['actual_status']}. " \
        "If actual_status is 401, the test-JWT sub email may not be in the DB — see was_lab.py demo 5."

# ─── Test 8: WAS demo generates alert in SOC alert table ────────────────────

def test_was_demo_creates_soc_alert():
    """Running any WAS demo must create a ThreatAlert visible in /alerts."""
    # Run SQL injection demo (always completes successfully, no rate limit risk)
    client.post("/api/v1/was/demo/sql-injection", headers=_admin_headers())

    # Check alerts — analyst can also see alerts
    resp = client.get("/api/v1/alerts", headers=_analyst_headers())
    assert resp.status_code == 200
    alerts = resp.json()
    was_alerts = [a for a in alerts if "[WAS-DEMO]" in a.get("title", "")]
    assert len(was_alerts) > 0, "No WAS alerts found in SOC alert table!"

# ─── Test 9: Broken access control demo verifies 403 ────────────────────────

def test_was_broken_access_prevented():
    """Broken access demo must confirm analyst token received 403 on admin endpoint."""
    resp = client.post("/api/v1/was/demo/broken-access", headers=_admin_headers())
    assert resp.status_code == 200, f"Got {resp.status_code}: {resp.text}"
    data = resp.json()
    assert data["actual_status"] == 403, \
        f"Expected 403, got {data['actual_status']} — RBAC may not be enforcing correctly!"
    assert data["result"] == "PREVENTED"

# ─── Test 10: Non-admin cannot access WAS lab endpoints ─────────────────────

def test_analyst_cannot_run_was_demos():
    """Security Analyst must receive 403 on WAS demo endpoints (admin only)."""
    resp = client.post("/api/v1/was/demo/brute-force", headers=_analyst_headers())
    assert resp.status_code == 403, \
        f"Expected 403 for Analyst on WAS lab, got {resp.status_code}"

# ─── Test 11: Login endpoint works (must run before brute-force exhausts limit) ──

def test_normal_login_works():
    """Normal analyst login must return 200. Run this BEFORE brute-force test in isolated run."""
    # Use a fresh TestClient to avoid shared rate limit state from other tests
    from fastapi.testclient import TestClient as _TC
    fresh_client = _TC(app, raise_server_exceptions=False)
    resp = fresh_client.post("/api/v1/auth/login", json={
        "email": "analyst@soc.corp",
        "password": "analyst123"
    })
    # May get 429 if brute-force test ran first in this session — that's expected
    assert resp.status_code in (200, 429), \
        f"Unexpected login status: {resp.status_code}"
    if resp.status_code == 200:
        data = resp.json()
        assert "access_token" in data
        assert data["user"]["role"] == "Security Analyst"


def test_interactive_brute_force_uses_inputs_and_returns_real_rate_limit():
    passwords = [f"lab-wrong-{i}" for i in range(6)]
    resp = client.post(
        "/api/v1/was/interactive/brute-force",
        headers=_admin_headers(),
        json={"passwords": passwords},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert [step["status"] for step in data["steps"]] == [401, 401, 401, 401, 401, 429]
    assert all(step["method"] == "POST" for step in data["steps"])
    assert all(step["request_data"]["password"] == "[REDACTED]" for step in data["steps"])
    assert "lab-wrong" not in str(data["steps"])
    assert data["rate_limited"] is True
    assert data["security_event_id"] == data["alert_id"]


def test_interactive_broken_access_checks_identity_and_read_only_targets():
    endpoint = "/api/v1/admin/audit-logs"
    denied = client.post(
        "/api/v1/was/interactive/broken-access",
        headers=_admin_headers(),
        json={"test_role": "Security Analyst", "endpoint": endpoint},
    )
    assert denied.status_code == 200, denied.text
    assert denied.json()["steps"][0]["status"] == 403
    assert denied.json()["data_modified"] is False
    assert denied.json()["alert_id"]

    allowed = client.post(
        "/api/v1/was/interactive/broken-access",
        headers=_admin_headers(),
        json={"test_role": "Administrator", "endpoint": endpoint},
    )
    assert allowed.status_code == 200, allowed.text
    assert allowed.json()["steps"][0]["status"] == 200
    assert allowed.json()["data_modified"] is False


def test_interactive_broken_access_rejects_arbitrary_roles_and_targets():
    resp = client.post(
        "/api/v1/was/interactive/broken-access",
        headers=_admin_headers(),
        json={"test_role": "SOC Engineer", "endpoint": "/api/v1/employees"},
    )
    assert resp.status_code == 422


def test_interactive_sql_injection_uses_parameterized_employee_search():
    payload = "' OR '1'='1"
    resp = client.post(
        "/api/v1/was/interactive/sql-injection",
        headers=_admin_headers(),
        json={"search_input": payload},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["steps"][0]["method"] == "GET"
    assert data["steps"][0]["status"] == 200
    assert data["steps"][0]["request_data"] == {"search": payload}
    assert data["rows_returned"] == 0
    assert data["injection_successful"] is False
    assert data["sqli_patterns_detected"]
    assert data["security_event_id"] == data["alert_id"]


def test_interactive_xss_round_trips_in_isolated_record():
    payload = "<script>document.body.dataset.wasXss='executed'</script>"
    resp = client.post(
        "/api/v1/was/interactive/xss-prevention",
        headers=_admin_headers(),
        json={"content": payload},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert [step["status"] for step in data["steps"]] == [201, 200]
    assert data["stored_value"] == payload
    assert data["stored_as_literal_text"] is True
    assert "script_executed" not in data
    assert data["alert_id"]


def test_interactive_rate_limit_uses_isolated_allowlisted_endpoint_and_creates_alert():
    endpoint = "/api/v1/was/lab/rate-limit-target"
    resp = client.post(
        "/api/v1/was/interactive/rate-limit",
        headers=_admin_headers(),
        json={"request_count": 12, "endpoint": endpoint},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert [step["status"] for step in data["steps"]] == [200] * 10 + [429]
    assert data["rate_limited"] is True
    assert data["endpoint_tested"] == endpoint
    assert data["security_event_id"] == data["alert_id"]

    alerts = client.get("/api/v1/alerts", headers=_analyst_headers())
    assert alerts.status_code == 200
    assert any(alert["alert_id"] == data["alert_id"] for alert in alerts.json())
    selected_alert = client.get(
        "/api/v1/alerts",
        headers=_analyst_headers(),
        params={"alert_id": data["alert_id"]},
    )
    assert [alert["alert_id"] for alert in selected_alert.json()] == [data["alert_id"]]


def test_was_lab_is_disabled_outside_development_or_demo(monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "APP_ENV", "production")
    resp = client.post(
        "/api/v1/was/interactive/sql-injection",
        headers=_admin_headers(),
        json={"search_input": "safe search"},
    )
    assert resp.status_code == 404
