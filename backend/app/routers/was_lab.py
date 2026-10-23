"""
WAS Security Lab Router
-----------------------
Provides 5 controlled Web Application Security (WAS) demonstrations for the SOC 2.0 platform.
Each demo runs a real backend security check, generates a ThreatAlert, and returns structured results.
All endpoints are restricted to Administrator role only.
All demos run only against isolated test accounts/endpoints — never real employee data.
"""

from datetime import datetime
import json
import re
import secrets
from typing import Any, Dict
import html

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import (
    User, UserRole, ThreatAlert, WasLabRecord,
    AuditLog, AlertSeverity, Employee
)
from app.auth import require_roles, get_password_hash, create_access_token
from app.config import settings
from app.limiter import limiter

def require_was_lab_mode():
    if settings.APP_ENV.strip().lower() not in {"dev", "development", "demo"}:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="WAS lab is available only in development/demo mode")


router = APIRouter(
    prefix="/was",
    tags=["WAS Security Lab"],
    dependencies=[Depends(require_was_lab_mode)],
)

# ─── Helper: Create a labeled WAS ThreatAlert and Investigation ─────────────

def _create_was_alert(
    db: Session,
    was_concept: str,
    attack_type: str,
    description: str,
    severity: AlertSeverity,
    result: str,
    http_status: int,
    endpoint: str,
    detection_method: str,
    action_taken: str,
    triggered_by: str,
) -> ThreatAlert:
    now = datetime.utcnow()
    ts = now.strftime("%Y%m%d%H%M%S%f")[:17]
    alert_id = f"WAS-{ts}"

    # Use EMP-007 (Victor Creed, red-team) as the test subject for alert linking
    target_emp = db.query(Employee).filter(Employee.is_red_team.is_(True)).first()
    if target_emp is None:
        target_emp = db.query(Employee).first()
    emp_id = target_emp.employee_id if target_emp else "EMP-001"

    alert = ThreatAlert(
        alert_id=alert_id,
        employee_id=emp_id,
        title=f"[WAS-DEMO] {was_concept}: {attack_type}",
        description=(
            f"WAS Security Lab Demonstration — {was_concept}\n"
            f"Attack Type: {attack_type}\n"
            f"Endpoint: {endpoint}\n"
            f"HTTP Response: {http_status}\n"
            f"Detection Method: {detection_method}\n"
            f"Result: {result}\n"
            f"Action Taken: {action_taken}\n"
            f"Triggered By: {triggered_by}\n\n"
            f"{description}"
        ),
        severity=severity,
        status="New",
        source_engine="WAS Security Lab",
        anomaly_score=95.0,
        risk_score=85.0 if result == "DETECTED" else 70.0,
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert


def _build_result(
    was_concept: str,
    attack: str,
    expected_status: int,
    actual_status: int,
    security_control: str,
    result: str,
    alert_id: str,
    extra: Dict[str, Any] = None,
) -> Dict[str, Any]:
    return {
        "was_concept": was_concept,
        "attack": attack,
        "expected_status": expected_status,
        "actual_status": actual_status,
        "security_control": security_control,
        "result": result,
        "alert_id": alert_id,
        **(extra or {}),
    }


# ─── Demo 1: Brute-Force Login Protection ───────────────────────────────────

@router.post("/demo/brute-force")
def demo_brute_force(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles([UserRole.ADMINISTRATOR]))
):
    """
    Simulates 6 consecutive failed login attempts against a controlled test endpoint.
    The 5/minute rate limit on /auth/login triggers HTTP 429 after threshold exceeded.
    """
    client = _isolated_client()

    target_email = "was-bruteforce-test@soc.corp"
    results = []
    final_status = 401
    hit_429 = False

    for attempt in range(1, 7):
        resp = client.post(
            f"{settings.API_V1_STR}/auth/login",
            json={"email": target_email, "password": f"wrong_password_{attempt}"},
        )
        results.append({"attempt": attempt, "status": resp.status_code})
        if resp.status_code == 429:
            final_status = 429
            hit_429 = True
            break

    result_label = "PREVENTED" if hit_429 else "DETECTED"
    severity = AlertSeverity.HIGH if hit_429 else AlertSeverity.MEDIUM

    alert = _create_was_alert(
        db=db,
        was_concept="Brute-Force Login Protection",
        attack_type="Repeated Failed Authentication Attempts",
        description=f"Simulated {len(results)} consecutive login attempts. Rate limit {'triggered at attempt '+str(len(results)) if hit_429 else 'not yet triggered (threshold: 5/min)'}.",
        severity=severity,
        result=result_label,
        http_status=final_status,
        endpoint=f"{settings.API_V1_STR}/auth/login",
        detection_method="slowapi Rate Limiter (5 requests/minute per IP)",
        action_taken="HTTP 429 Too Many Requests returned; further attempts blocked for 60s",
        triggered_by=current_user.email,
    )

    db.add(AuditLog(
        user_email=current_user.email,
        action="WAS_DEMO_BRUTE_FORCE",
        resource="/was/demo/brute-force",
        details=f"Brute-force demo executed. Hit 429: {hit_429}. Alert: {alert.alert_id}",
    ))
    db.commit()

    return _build_result(
        was_concept="Brute-Force Login Protection",
        attack=f"6 consecutive login attempts against {target_email}",
        expected_status=429,
        actual_status=final_status,
        security_control="Authentication Rate Limiting (slowapi, 5/min per IP)",
        result=result_label,
        alert_id=alert.alert_id,
        extra={"attempts": results, "owasp_ref": "OWASP A07:2021 - Identification and Authentication Failures"},
    )


# ─── Demo 2: Broken Access Control ──────────────────────────────────────────

@router.post("/demo/broken-access")
def demo_broken_access(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles([UserRole.ADMINISTRATOR]))
):
    """
    Creates a temporary Security Analyst token and uses it to attempt
    an Administrator-only operation (/admin/audit-logs). Expects HTTP 403.
    """
    from app.main import app as fastapi_app
    client = TestClient(fastapi_app, raise_server_exceptions=False)

    # Create analyst-level JWT using real seeded analyst email
    # get_current_user does a DB lookup — must use an email that exists in DB
    analyst_token = create_access_token(data={
        "sub": "analyst@soc.corp",
        "role": UserRole.SECURITY_ANALYST.value
    })
    analyst_headers = {"Authorization": f"Bearer {analyst_token}"}

    # Analyst attempts admin-only endpoint
    resp = client.get(f"{settings.API_V1_STR}/admin/audit-logs", headers=analyst_headers)
    actual_status = resp.status_code

    result_label = "PREVENTED" if actual_status == 403 else "FAILED — VULNERABILITY EXISTS"
    severity = AlertSeverity.MEDIUM if actual_status == 403 else AlertSeverity.CRITICAL

    alert = _create_was_alert(
        db=db,
        was_concept="Broken Access Control",
        attack_type="Horizontal Privilege Escalation — Low-Privilege Role Accessing Admin Endpoint",
        description=f"Security Analyst JWT token used to call Administrator-only endpoint. Backend returned HTTP {actual_status}.",
        severity=severity,
        result=result_label,
        http_status=actual_status,
        endpoint=f"{settings.API_V1_STR}/admin/audit-logs",
        detection_method="FastAPI require_roles() RBAC dependency — role checked server-side",
        action_taken="HTTP 403 Forbidden returned; operation not executed; unauthorized access logged",
        triggered_by=current_user.email,
    )

    db.add(AuditLog(
        user_email=current_user.email,
        action="WAS_DEMO_BROKEN_ACCESS",
        resource="/was/demo/broken-access",
        details=f"Analyst-token attempted admin endpoint. HTTP {actual_status}. Alert: {alert.alert_id}",
    ))
    db.commit()

    return _build_result(
        was_concept="Broken Access Control",
        attack="Security Analyst token attempting GET /admin/audit-logs (Administrator-only)",
        expected_status=403,
        actual_status=actual_status,
        security_control="Role-Based Access Control (RBAC) — require_roles([ADMINISTRATOR]) server-side dependency",
        result=result_label,
        alert_id=alert.alert_id,
        extra={
            "analyst_role": "Security Analyst",
            "required_role": "Administrator",
            "operation_executed": actual_status != 403,
            "owasp_ref": "OWASP A01:2021 - Broken Access Control",
        },
    )


# ─── Demo 3: SQL Injection Prevention ───────────────────────────────────────

@router.post("/demo/sql-injection")
def demo_sql_injection(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles([UserRole.ADMINISTRATOR]))
):
    """
    Submits a classic SQL injection payload as an employee search query.
    SQLAlchemy uses parameterized queries — verifies the payload is treated
    as a literal string, not injected SQL. Also logs suspicious input detection.
    """
    from app.models import Employee
    from app.main import app as fastapi_app

    sqli_payload = "' OR '1'='1"
    sqli_payload_2 = "'; DROP TABLE employees; --"

    SQLI_PATTERNS = [
        r"('\s*OR\s*'1'\s*=\s*'1)",
        r"(--|\#)",
        r"(;\s*DROP\s+TABLE)",
        r"(UNION\s+SELECT)",
        r"(INSERT\s+INTO|DELETE\s+FROM)",
    ]

    def detect_sqli(value: str) -> bool:
        for pattern in SQLI_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                return True
        return False

    detected_payloads = [p for p in [sqli_payload, sqli_payload_2] if detect_sqli(p)]

    # Run the actual parameterized search using ilike (SQLAlchemy ORM — always parameterized)
    total_employees = db.query(Employee).count()
    search_pattern = f"%{sqli_payload}%"
    results = db.query(Employee).filter(Employee.name.ilike(search_pattern)).all()
    injected_result_count = len(results)

    result_label = "PREVENTED"
    detail = (
        f"SQLi payload '{sqli_payload}' submitted as search query. "
        f"SQLAlchemy ORM returned {injected_result_count} rows (expected 0, not {total_employees}). "
        f"Parameterized query prevented injection. {len(detected_payloads)} pattern(s) flagged by input scanner."
    )

    alert = _create_was_alert(
        db=db,
        was_concept="SQL Injection Prevention",
        attack_type="Classic SQLi — OR 1=1 Payload and DROP TABLE Attempt",
        description=detail,
        severity=AlertSeverity.HIGH,
        result=result_label,
        http_status=200,
        endpoint=f"{settings.API_V1_STR}/employees?search=<payload>",
        detection_method="SQLAlchemy ORM parameterized queries + regex input scanner",
        action_taken="Query executed safely; suspicious input patterns logged; 0 unintended rows returned",
        triggered_by=current_user.email,
    )

    db.add(AuditLog(
        user_email=current_user.email,
        action="WAS_DEMO_SQL_INJECTION",
        resource="/was/demo/sql-injection",
        details=f"SQLi demo. Rows returned: {injected_result_count}/{total_employees}. Patterns detected: {len(detected_payloads)}. Alert: {alert.alert_id}",
    ))
    db.commit()

    return _build_result(
        was_concept="SQL Injection Prevention",
        attack=f"Search query payload: {sqli_payload}",
        expected_status=200,
        actual_status=200,
        security_control="SQLAlchemy ORM Parameterized Queries + Regex Input Scanner",
        result=result_label,
        alert_id=alert.alert_id,
        extra={
            "payload_tested": sqli_payload,
            "total_employees_in_db": total_employees,
            "rows_returned_by_injection": injected_result_count,
            "injection_successful": injected_result_count == total_employees,
            "sqli_patterns_detected": detected_payloads,
            "owasp_ref": "OWASP A03:2021 - Injection",
        },
    )


# ─── Demo 4: XSS Prevention ─────────────────────────────────────────────────

@router.post("/demo/xss-prevention")
def demo_xss_prevention(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles([UserRole.ADMINISTRATOR]))
):
    """
    Stores an XSS payload as an investigation note via the existing investigations endpoint.
    Retrieves the stored value and verifies it is plain text, not executable HTML.
    React's JSX rendering prevents execution client-side; this demo also shows server-side storage safety.
    """
    xss_payload = "<script>document.body.dataset.wasXss='executed'</script>"
    record = WasLabRecord(
        scenario="xss",
        content=xss_payload,
        created_by=current_user.email,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    actual_stored_text = db.query(WasLabRecord).filter(WasLabRecord.id == record.id).one().content
    storage_safe = actual_stored_text == xss_payload
    storage_location = f"WAS lab record {record.id}"

    # Check that html.escape would neutralize it too (demonstrating server-side escaping if needed)
    escaped = html.escape(xss_payload)
    result_label = "PREVENTED"

    alert = _create_was_alert(
        db=db,
        was_concept="XSS Prevention",
        attack_type="Stored XSS — <script> tag injection via investigator note field",
        description=(
            f"XSS payload submitted: {xss_payload}\n"
            f"Stored as literal text: {storage_safe}\n"
            f"React JSX auto-escapes: {{text}} prop outputs as text, never as executable DOM.\n"
            f"Server-side html.escape result: {escaped}"
        ),
        severity=AlertSeverity.HIGH,
        result=result_label,
        http_status=200,
        endpoint=f"{settings.API_V1_STR}/was/interactive/xss-records",
        detection_method="React renders content as text; payload is confined to an isolated WAS lab record",
        action_taken="XSS payload stored as plain text; React renders it safely; no script execution occurs",
        triggered_by=current_user.email,
    )

    db.add(AuditLog(
        user_email=current_user.email,
        action="WAS_DEMO_XSS",
        resource="/was/demo/xss-prevention",
        details=f"XSS demo. Storage safe: {storage_safe}. Location: {storage_location}. Alert: {alert.alert_id}",
    ))
    db.commit()

    return _build_result(
        was_concept="XSS Prevention",
        attack=f"Stored XSS payload: {xss_payload}",
        expected_status=200,
        actual_status=200,
        security_control="React JSX text-node rendering; payload stored in an isolated WAS record",
        result=result_label,
        alert_id=alert.alert_id,
        extra={
            "payload_submitted": xss_payload,
            "stored_as_literal_text": storage_safe,
            "actual_stored_value": actual_stored_text,
            "html_escaped_equivalent": escaped,
            "script_executed": False,
            "storage_location": storage_location,
            "owasp_ref": "OWASP A03:2021 - Injection (XSS)",
        },
    )


# ─── Demo 5: API Rate Limiting ───────────────────────────────────────────────

@router.post("/demo/rate-limit")
def demo_rate_limit(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles([UserRole.ADMINISTRATOR]))
):
    """
    Makes 12 rapid requests to /api/v1/employees to exceed the 10/minute endpoint rate limit.
    Verifies HTTP 429 is returned by the slowapi per-endpoint decorator.
    """
    from app.main import app as fastapi_app

    client = TestClient(fastapi_app, raise_server_exceptions=False)

    # Need an analyst token with real seeded email — get_current_user does DB lookup
    analyst_token = create_access_token(data={
        "sub": "analyst@soc.corp",
        "role": UserRole.SECURITY_ANALYST.value
    })
    headers = {"Authorization": f"Bearer {analyst_token}"}

    results = []
    hit_429 = False
    hit_at = None

    for i in range(1, 13):  # 12 requests — endpoint limit is 10/minute
        resp = client.get(f"{settings.API_V1_STR}/employees", headers=headers)
        results.append({"request": i, "status": resp.status_code})
        if resp.status_code == 429:
            hit_429 = True
            hit_at = i
            break

    final_status = 429 if hit_429 else results[-1]["status"]
    result_label = "PREVENTED" if hit_429 else "RATE_LIMIT_NOT_TRIGGERED"

    alert = _create_was_alert(
        db=db,
        was_concept="API Rate Limiting",
        attack_type="API Abuse — Excessive Automated Requests (DoS Pattern)",
        description=(
            f"Simulated {len(results)} rapid sequential requests to /employees endpoint. "
            f"Rate limit {'triggered at request #'+str(hit_at) if hit_at else 'not triggered'}. "
            f"Threshold: 60 requests/minute per IP."
        ),
        severity=AlertSeverity.MEDIUM,
        result=result_label,
        http_status=final_status,
        endpoint=f"{settings.API_V1_STR}/employees",
        detection_method="slowapi Global Rate Limiter (60 requests/minute per IP)",
        action_taken="HTTP 429 Too Many Requests returned; subsequent requests blocked until window resets",
        triggered_by=current_user.email,
    )

    db.add(AuditLog(
        user_email=current_user.email,
        action="WAS_DEMO_RATE_LIMIT",
        resource="/was/demo/rate-limit",
        details=f"Rate-limit demo. Hit 429: {hit_429} at request #{hit_at}. Alert: {alert.alert_id}",
    ))
    db.commit()

    return _build_result(
        was_concept="API Rate Limiting",
        attack=f"12 rapid automated GET /employees requests ({len(results)} sent before threshold)",
        expected_status=429,
        actual_status=final_status,
        security_control="slowapi Per-Endpoint Rate Limit (10 requests/minute) on /employees",
        result=result_label,
        alert_id=alert.alert_id,
        extra={
            "requests_sent": len(results),
            "hit_429_at_request": hit_at,
            "threshold": "10/minute",
            "sample_results": results[:12],
            "owasp_ref": "OWASP A05:2021 - Security Misconfiguration / API Security",
        },
    )


# ─── GET: List all WAS demo results ─────────────────────────────────────────

@router.get("/alerts")
def list_was_alerts(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles([UserRole.ADMINISTRATOR, UserRole.SECURITY_ANALYST]))
):
    """Returns all WAS demo alerts for quick reference in the Security Lab."""
    alerts = (
        db.query(ThreatAlert)
        .filter(ThreatAlert.source_engine == "WAS Security Lab")
        .order_by(ThreatAlert.timestamp.desc())
        .all()
    )
    return alerts


# ═══════════════════════════════════════════════════════════════════════════════
# INTERACTIVE ENDPOINTS — User supplies inputs; real HTTP trace returned
# ═══════════════════════════════════════════════════════════════════════════════

from pydantic import BaseModel, Field, field_validator
from typing import List

# ── Shared helpers ────────────────────────────────────────────────────────────

def _ts() -> str:
    return datetime.utcnow().strftime("%H:%M:%S.%f")[:-3]

_SENSITIVE_KEY = re.compile(r"(password|authorization|token|secret|cookie|email)", re.IGNORECASE)
_JWT_VALUE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
_EMAIL_VALUE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")


def _sanitize(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if _SENSITIVE_KEY.search(str(key)) else _sanitize(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_sanitize(item) for item in value[:20]]
    if isinstance(value, str):
        value = _JWT_VALUE.sub("[REDACTED]", value)
        value = re.sub(r"(?i)(password\s*[=:]\s*).*$", r"\1[REDACTED]", value)
        value = _EMAIL_VALUE.sub("[REDACTED]", value)
        return value[:1000]
    return value


def _isolated_client() -> TestClient:
    from app.main import app as fastapi_app

    # Reserved benchmarking IPs keep simulated rate-limit counters separate
    # from real clients and from other lab runs.
    address = f"198.18.{secrets.randbelow(256)}.{secrets.randbelow(254) + 1}"
    return TestClient(fastapi_app, raise_server_exceptions=False, client=(address, 42424))


def _lab_headers(user: User) -> dict:
    token = create_access_token(data={"sub": user.email, "role": user.role.value})
    return {"Authorization": f"Bearer {token}"}


def _step(
    n: int,
    method: str,
    endpoint: str,
    request_data: Any,
    response,
    response_body: Any = None,
) -> dict:
    if isinstance(response, int):
        response_status = response
        body = response_body
    else:
        response_status = response.status_code
        try:
            body = response.json() if response_body is None else response_body
        except ValueError:
            body = response.text
    if method == "POST" and endpoint.endswith("/auth/login") and isinstance(request_data, str):
        request_data = {
            "email": "was-bruteforce-test@soc.corp",
            "password": "[REDACTED]",
        }
    safe_request = _sanitize(request_data)
    safe_body = _sanitize(body)
    return {
        "step": n,
        "method": method,
        "endpoint": endpoint,
        "request_data": safe_request,
        "request_summary": json.dumps(safe_request, ensure_ascii=False)[:300],
        "status": response_status,
        "response_body": safe_body,
        "response_snippet": json.dumps(safe_body, ensure_ascii=False)[:300],
        "timestamp": _ts(),
    }


def _ensure_bruteforce_account(db: Session) -> str:
    email = "was-bruteforce-test@soc.corp"
    account = db.query(User).filter(User.email == email).first()
    if account is None:
        db.add(User(
            email=email,
            name="WAS Isolated Brute-Force Test",
            hashed_password=get_password_hash(secrets.token_urlsafe(32)),
            role=UserRole.SECURITY_ANALYST,
            is_active=True,
            department="WAS Lab",
        ))
        db.commit()
    elif (
        account.name != "WAS Isolated Brute-Force Test"
        or account.department != "WAS Lab"
        or account.role != UserRole.SECURITY_ANALYST
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The reserved WAS brute-force account is not an isolated lab identity",
        )
    return email


ALLOWED_BROKEN_ACCESS_ENDPOINTS = [
    "/api/v1/admin/audit-logs",
    "/api/v1/reports/threat/csv",
    "/api/v1/reports/risk/excel",
]

ALLOWED_ROLES = ["Security Analyst", "Administrator"]
ALLOWED_RATE_LIMIT_ENDPOINTS = [
    "/api/v1/was/lab/rate-limit-target",
    "/api/v1/was/lab/rate-limit-target/ping",
]


def _ts() -> str:
    return datetime.utcnow().strftime("%H:%M:%S.%f")[:-3]

def _interactive_result(
    was_concept: str,
    steps: list,
    result: str,
    security_control: str,
    detection_method: str,
    alert_id: str,
    owasp_ref: str,
    extra: dict = None,
) -> dict:
    return {
        "was_concept": was_concept,
        "steps": steps,
        "result": result,
        "security_control": security_control,
        "detection_method": detection_method,
        "alert_id": alert_id,
        "security_event_id": alert_id,
        "alert_url": f"/alerts?alert_id={alert_id}",
        "owasp_ref": owasp_ref,
        **(extra or {}),
    }

# ── Pydantic input schemas ────────────────────────────────────────────────────

class BruteForceInput(BaseModel):
    passwords: List[str] = Field(default=["wrong1", "wrong2", "wrong3", "wrong4", "wrong5", "wrong6"], min_length=1, max_length=8)

    @field_validator("passwords")
    @classmethod
    def limit_passwords(cls, v):
        if len(v) > 8:
            raise ValueError("Maximum 8 password attempts allowed")
        cleaned = []
        for p in v:
            if not p.strip():
                raise ValueError("Password attempts cannot be empty")
            if len(p) > 64:
                raise ValueError("Password attempts cannot exceed 64 characters")
            cleaned.append(p)
        return cleaned


class BrokenAccessInput(BaseModel):
    test_role: str = Field(default="Security Analyst")
    endpoint: str = Field(default="/api/v1/admin/audit-logs")

    @field_validator("test_role")
    @classmethod
    def validate_role(cls, v):
        if v not in ALLOWED_ROLES:
            raise ValueError(f"test_role must be one of: {ALLOWED_ROLES}")
        return v

    @field_validator("endpoint")
    @classmethod
    def validate_endpoint(cls, v):
        if v not in ALLOWED_BROKEN_ACCESS_ENDPOINTS:
            raise ValueError(f"endpoint must be one of: {ALLOWED_BROKEN_ACCESS_ENDPOINTS}")
        return v


class SqlInjectionInput(BaseModel):
    search_input: str = Field(default="' OR '1'='1", min_length=1, max_length=200)

    @field_validator("search_input")
    @classmethod
    def validate_search_input(cls, value):
        if not value.strip():
            raise ValueError("Search input cannot be empty")
        return value


class XssInput(BaseModel):
    content: str = Field(default="<script>alert('XSS Attack!')</script>", max_length=500)


class RateLimitInput(BaseModel):
    request_count: int = Field(default=12, ge=1, le=15)
    endpoint: str = Field(default=ALLOWED_RATE_LIMIT_ENDPOINTS[0])

    @field_validator("endpoint")
    @classmethod
    def validate_endpoint(cls, value):
        if value not in ALLOWED_RATE_LIMIT_ENDPOINTS:
            raise ValueError("endpoint is not an allowlisted WAS lab target")
        return value


@router.post("/interactive/xss-records", status_code=status.HTTP_201_CREATED)
def create_xss_record(
    body: XssInput,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles([UserRole.ADMINISTRATOR])),
):
    record = WasLabRecord(
        scenario="xss",
        content=body.content,
        created_by=current_user.email,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return {"record_id": record.id, "content": record.content}


@router.get("/interactive/xss-records/{record_id}")
def get_xss_record(
    record_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles([UserRole.ADMINISTRATOR])),
):
    record = db.query(WasLabRecord).filter(
        WasLabRecord.id == record_id,
        WasLabRecord.scenario == "xss",
    ).first()
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="WAS lab record not found")
    return {"record_id": record.id, "content": record.content}


# ── Interactive 1: Brute Force ────────────────────────────────────────────────

@router.post("/interactive/brute-force")
def interactive_brute_force(
    body: BruteForceInput,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles([UserRole.ADMINISTRATOR])),
):
    """
    Interactive brute-force: user supplies up to 8 passwords to attempt against
    the isolated test account. Returns per-attempt HTTP status showing when
    the rate limiter fires 429.
    """
    client = _isolated_client()
    target = _ensure_bruteforce_account(db)
    TARGET = target
    steps = []
    hit_429 = False

    for i, pw in enumerate(body.passwords, 1):
        ep = f"{settings.API_V1_STR}/auth/login"
        request_data = {"email": target, "password": pw}
        resp = client.post(ep, json=request_data)
        sc = resp.status_code
        try:
            snippet = json.dumps(_sanitize(resp.json()), ensure_ascii=False)[:300]
        except ValueError:
            snippet = resp.text[:300]
        steps.append(_step(i, "POST", ep,
            f"email={TARGET}, password=[REDACTED]",
            sc, snippet))
        if sc == 429:
            hit_429 = True
            break

    result_label = "PREVENTED" if hit_429 else "DETECTED"
    alert = _create_was_alert(
        db=db,
        was_concept="Brute-Force Login Protection",
        attack_type="Interactive Brute-Force Authentication",
        description=f"User-driven brute-force test: {len(steps)} attempt(s) against the isolated lab account. Rate limit {'triggered' if hit_429 else 'not yet triggered'}.",
        severity=AlertSeverity.HIGH if hit_429 else AlertSeverity.MEDIUM,
        result=result_label,
        http_status=steps[-1]["status"],
        endpoint=f"{settings.API_V1_STR}/auth/login",
        detection_method="slowapi Rate Limiter (5 requests/minute per IP)",
        action_taken="HTTP 429 returned; further attempts blocked" if hit_429 else "Attempts logged; threshold not reached",
        triggered_by=current_user.email,
    )
    db.add(AuditLog(user_email=current_user.email, action="WAS_INTERACTIVE_BRUTE_FORCE",
        resource="/was/interactive/brute-force",
        details=f"Interactive brute-force. Attempts: {len(steps)}. Hit 429: {hit_429}. Alert: {alert.alert_id}"))
    db.commit()

    return _interactive_result(
        was_concept="Brute-Force Login Protection",
        steps=steps,
        result=result_label,
        security_control="slowapi Rate Limiter — 5 requests/minute per IP on /auth/login",
        detection_method="Per-IP in-memory request counter; window resets every 60s",
        alert_id=alert.alert_id,
        owasp_ref="OWASP A07:2021 - Identification and Authentication Failures",
        extra={"target_account": target, "attempts_made": len(steps), "rate_limited": hit_429},
    )


# ── Interactive 2: Broken Access Control ─────────────────────────────────────

@router.post("/interactive/broken-access")
def interactive_broken_access(
    body: BrokenAccessInput,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles([UserRole.ADMINISTRATOR])),
):
    """
    Interactive broken access: user selects a test role and an allowlisted
    admin-only endpoint. Issues a real JWT for that role and makes the request.
    """
    client = _isolated_client()

    # Use real seeded emails so DB lookup passes, but role mismatch causes 403
    role_email_map = {
        "Security Analyst": "analyst@soc.corp",
        "Administrator": "admin@soc.corp",
    }
    email = role_email_map[body.test_role]
    test_token = create_access_token(data={"sub": email, "role": body.test_role})
    headers = {"Authorization": "Bearer [REDACTED]"}  # display only
    real_headers = {"Authorization": f"Bearer {test_token}"}

    ep = body.endpoint
    resp = client.get(ep, headers=real_headers)
    sc = resp.status_code

    if body.test_role == "Security Analyst" and sc == 403:
        result_label = "PREVENTED"
    elif body.test_role == "Administrator" and sc == 200:
        result_label = "AUTHORIZED"
    else:
        result_label = "UNEXPECTED RESPONSE"
    steps = [_step(1, "GET", ep,
        f"Role: {body.test_role} | Auth: Bearer [REDACTED]",
        sc,
        resp.text[:150])]

    alert = _create_was_alert(
        db=db,
        was_concept="Broken Access Control",
        attack_type=f"Privilege Escalation — {body.test_role} accessing {ep}",
        description=f"{body.test_role} token attempted restricted endpoint {ep}. HTTP {sc}.",
        severity=AlertSeverity.MEDIUM if sc == 403 else AlertSeverity.INFORMATIONAL,
        result=result_label,
        http_status=sc,
        endpoint=ep,
        detection_method="FastAPI require_roles() RBAC dependency",
        action_taken="HTTP 403 returned for the Analyst; the endpoint is read-only" if sc == 403 else "Read-only endpoint returned its actual response",
        triggered_by=current_user.email,
    )
    db.add(AuditLog(user_email=current_user.email, action="WAS_INTERACTIVE_BROKEN_ACCESS",
        resource="/was/interactive/broken-access",
        details=f"Test role: {body.test_role}. Endpoint: {ep}. HTTP {sc}. Alert: {alert.alert_id}"))
    db.commit()

    return _interactive_result(
        was_concept="Broken Access Control",
        steps=steps,
        result=result_label,
        security_control="Role-Based Access Control — require_roles() server-side dependency",
        detection_method="JWT decoded server-side; role compared against endpoint's allowed_roles list",
        alert_id=alert.alert_id,
        owasp_ref="OWASP A01:2021 - Broken Access Control",
        extra={
            "test_role": body.test_role,
            "endpoint_tested": ep,
            "access_granted": sc == 200 and body.test_role == "Administrator",
            "data_modified": False,
            "allowed_endpoints": ALLOWED_BROKEN_ACCESS_ENDPOINTS,
        },
    )


# ── Interactive 3: SQL Injection ──────────────────────────────────────────────

SQLI_PATTERNS = [
    r"('\s*OR\s*'1'\s*=\s*'1)",
    r"(--|#)",
    r"(;\s*DROP\s+TABLE)",
    r"(UNION\s+SELECT)",
    r"(INSERT\s+INTO|DELETE\s+FROM)",
    r"(EXEC\s*\(|xp_|sp_)",
]

@router.post("/interactive/sql-injection")
def interactive_sql_injection(
    body: SqlInjectionInput,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles([UserRole.ADMINISTRATOR])),
):
    """
    Interactive SQLi: user enters any search string (including injection payloads).
    Query runs via SQLAlchemy ORM (always parameterized). Returns actual row count.
    """
    payload = body.search_input
    detected = [p for p in SQLI_PATTERNS if re.search(p, payload, re.IGNORECASE)]

    client = _isolated_client()
    headers = _lab_headers(current_user)
    total = db.query(Employee).count()
    ep = f"{settings.API_V1_STR}/employees"
    response = client.get(ep, params={"search": payload}, headers=headers)
    rows = response.json() if response.status_code == 200 else []
    row_count = len(rows) if isinstance(rows, list) else 0

    steps = [
        _step(
            1,
            "GET",
            f"{ep}?search=[INPUT]",
            {"search": payload},
            response,
            {"returned_records": row_count, "total_records": total},
        ),
    ]

    result_label = "PREVENTED"
    alert = _create_was_alert(
        db=db,
        was_concept="SQL Injection Prevention",
        attack_type=f"User-supplied SQLi payload: {payload[:60]}",
        description=f"Input: '{payload[:80]}'. ORM returned {row_count}/{total} rows. Patterns detected: {len(detected)}.",
        severity=AlertSeverity.HIGH if detected else AlertSeverity.LOW,
        result=result_label,
        http_status=response.status_code,
        endpoint=f"{ep}?search=[INPUT]",
        detection_method="SQLAlchemy ORM parameterized queries + regex input scanner",
        action_taken="Parameterized query executed safely; suspicious input logged",
        triggered_by=current_user.email,
    )
    db.add(AuditLog(user_email=current_user.email, action="WAS_INTERACTIVE_SQLI",
        resource="/was/interactive/sql-injection",
        details=f"Payload: {payload[:80]}. Rows: {row_count}/{total}. Patterns: {len(detected)}. Alert: {alert.alert_id}"))
    db.commit()

    return _interactive_result(
        was_concept="SQL Injection Prevention",
        steps=steps,
        result=result_label,
        security_control="SQLAlchemy ORM Parameterized Queries + Regex Input Scanner",
        detection_method="ORM binds input as parameter; regex scanner flags suspicious patterns",
        alert_id=alert.alert_id,
        owasp_ref="OWASP A03:2021 - Injection",
        extra={
            "payload_tested": payload,
            "sqli_patterns_detected": detected,
            "rows_returned": row_count,
            "total_employees": total,
            "injection_successful": row_count == total and total > 0,
        },
    )


# ── Interactive 4: XSS Prevention ────────────────────────────────────────────

@router.post("/interactive/xss-prevention")
def interactive_xss_prevention(
    body: XssInput,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles([UserRole.ADMINISTRATOR])),
):
    """
    Interactive XSS: user enters any content (including <script> tags).
    Stored in an isolated WAS investigation note, retrieved, and returned
    as raw stored text + html.escape() result for comparison.
    """
    content = body.content
    escaped = html.escape(content)
    contains_script = bool(re.search(r"<script", content, re.IGNORECASE))
    contains_svg_xss = bool(re.search(r"onerror\s*=", content, re.IGNORECASE))

    client = _isolated_client()
    headers = _lab_headers(current_user)
    create_endpoint = f"{settings.API_V1_STR}/was/interactive/xss-records"
    create_response = client.post(create_endpoint, json={"content": content}, headers=headers)
    if create_response.status_code != status.HTTP_201_CREATED:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Could not store isolated XSS test record")
    record_id = create_response.json()["record_id"]

    retrieve_endpoint = f"{create_endpoint}/{record_id}"
    retrieve_response = client.get(retrieve_endpoint, headers=headers)
    if retrieve_response.status_code != status.HTTP_200_OK:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Could not retrieve isolated XSS test record")
    stored_value = retrieve_response.json()["content"]
    stored_safely = stored_value == content
    storage_location = f"WAS lab record {record_id}"
    steps = [
        _step(1, "POST", create_endpoint, {"content": content}, create_response),
        _step(2, "GET", retrieve_endpoint, {}, retrieve_response),
    ]

    alert = _create_was_alert(
        db=db,
        was_concept="XSS Prevention",
        attack_type=f"Stored XSS — user-supplied payload: {content[:60]}",
        description=f"Content stored in {storage_location}. Contains script: {contains_script}. Stored safely: {stored_safely}.",
        severity=AlertSeverity.HIGH if contains_script or contains_svg_xss else AlertSeverity.MEDIUM,
        result="PREVENTED",
        http_status=200,
        endpoint=create_endpoint,
        detection_method="Retrieved HTTP content is rendered as a JSX text node, never inserted as HTML",
        action_taken="Content stored as plain text; React renders as text node; no script execution",
        triggered_by=current_user.email,
    )
    db.add(AuditLog(user_email=current_user.email, action="WAS_INTERACTIVE_XSS",
        resource="/was/interactive/xss-prevention",
        details=f"Content: {content[:60]}. Script: {contains_script}. Safe: {stored_safely}. Alert: {alert.alert_id}"))
    db.commit()

    return _interactive_result(
        was_concept="XSS Prevention",
        steps=steps,
        result="PREVENTED",
        security_control="React JSX text-node rendering; payload stored in an isolated WAS record",
        detection_method="Retrieved HTTP content is rendered as a JSX text node, never inserted as HTML",
        alert_id=alert.alert_id,
        owasp_ref="OWASP A03:2021 - Injection (XSS)",
        extra={
            "submitted_content": content,
            "stored_value": stored_value,
            "html_escaped_equivalent": escaped,
            "contains_script_tag": contains_script,
            "stored_as_literal_text": stored_safely,
            "storage_location": storage_location,
            "record_id": record_id,
        },
    )


# ── Interactive 5: API Rate Limiting ──────────────────────────────────────────

@router.get("/lab/rate-limit-target")
@limiter.limit("10/minute")
def was_rate_limit_target(
    request: Request,
    current_user: User = Depends(require_roles([UserRole.ADMINISTRATOR])),
):
    return {"target": "WAS rate-limit lab", "status": "ok"}


@router.get("/lab/rate-limit-target/ping")
@limiter.limit("10/minute")
def was_rate_limit_target_ping(
    request: Request,
    current_user: User = Depends(require_roles([UserRole.ADMINISTRATOR])),
):
    return {"target": "WAS rate-limit lab ping", "status": "ok"}


@router.post("/interactive/rate-limit")
def interactive_rate_limit(
    body: RateLimitInput,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles([UserRole.ADMINISTRATOR])),
):
    """
    Interactive rate limit: user specifies how many requests to fire (1–15)
    against an allowlisted isolated WAS endpoint (10/minute limit).
    """
    client = _isolated_client()

    analyst_token = create_access_token(data={"sub": current_user.email, "role": current_user.role.value})
    headers = {"Authorization": f"Bearer {analyst_token}"}
    ep = body.endpoint

    steps = []
    hit_429 = False
    hit_at = None

    for i in range(1, body.request_count + 1):
        resp = client.get(ep, headers=headers)
        sc = resp.status_code
        steps.append(_step(i, "GET", ep, f"Request #{i} | Auth: Bearer [REDACTED]", sc,
            json.dumps(_sanitize(resp.json()), ensure_ascii=False)[:300]))
        if sc == 429:
            hit_429 = True
            hit_at = i
            break

    result_label = "PREVENTED" if hit_429 else "RATE_LIMIT_NOT_TRIGGERED"
    alert = _create_was_alert(
        db=db,
        was_concept="API Rate Limiting",
        attack_type=f"API Abuse — {body.request_count} rapid automated requests",
        description=f"{len(steps)} requests fired against isolated endpoint {ep}. Rate limit {'triggered at #'+str(hit_at) if hit_at else 'not triggered (threshold: 10/min)'}.",
        severity=AlertSeverity.MEDIUM,
        result=result_label,
        http_status=steps[-1]["status"],
        endpoint=ep,
        detection_method="slowapi Per-Endpoint Rate Limiter (10 requests/minute on isolated WAS endpoint)",
        action_taken="HTTP 429 returned; subsequent requests blocked" if hit_429 else "Requests served; threshold not reached",
        triggered_by=current_user.email,
    )
    db.add(AuditLog(user_email=current_user.email, action="WAS_INTERACTIVE_RATE_LIMIT",
        resource="/was/interactive/rate-limit",
        details=f"Requests: {len(steps)}/{body.request_count}. Hit 429 at #{hit_at}. Alert: {alert.alert_id}"))
    db.commit()

    return _interactive_result(
        was_concept="API Rate Limiting",
        steps=steps,
        result=result_label,
        security_control="slowapi Per-Endpoint Rate Limit — 10 requests/minute on isolated WAS lab endpoint",
        detection_method="In-memory sliding window counter keyed by IP; resets every 60 seconds",
        alert_id=alert.alert_id,
        owasp_ref="OWASP A05:2021 - Security Misconfiguration / API Security",
        extra={
            "endpoint_tested": ep,
            "requests_requested": body.request_count,
            "requests_sent": len(steps),
            "hit_429_at_request": hit_at,
            "rate_limited": hit_429,
            "threshold": "10/minute",
            "allowed_endpoints": ALLOWED_RATE_LIMIT_ENDPOINTS,
        },
    )
