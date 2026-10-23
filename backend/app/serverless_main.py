import os
from fastapi import Depends, FastAPI, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from sqlalchemy.orm import Session

from app.config import settings
from app.auth import require_roles
from app.database import get_db
from app.limiter import limiter
from app.models import AuditLog, User, UserRole
from app.routers import (
    activities,
    alerts,
    auth,
    dashboards,
    employees,
    incidents,
    investigations,
    reports,
    risk_scoring,
)

if os.getenv("VERCEL") == "1":
    if not settings.DATABASE_URL.startswith(("postgresql", "postgres://")):
        raise RuntimeError("The Vercel serverless backend requires a PostgreSQL DATABASE_URL.")
    if not os.getenv("FRONTEND_URL"):
        raise RuntimeError("Set FRONTEND_URL to the deployed frontend origin for CORS.")

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Serverless API profile: core SOC records and workflows. ML endpoints are not included.",
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
    redoc_url=None,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    return response


@app.get("/api")
def root():
    return {
        "system": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "status": "OPERATIONAL",
        "deployment_profile": "serverless-core",
        "api_docs": "/api/docs",
    }


@app.get("/api/health")
def health_check():
    return {"status": "healthy", "deployment_profile": "serverless-core"}


@app.get(f"{settings.API_V1_STR}/admin/audit-logs")
def list_audit_logs(
    limit: int = Query(50, ge=1, le=200),
    current_user: User = Depends(
        require_roles([UserRole.ADMINISTRATOR, UserRole.SECURITY_MANAGER])
    ),
    db: Session = Depends(get_db),
):
    return (
        db.query(AuditLog)
        .order_by(AuditLog.timestamp.desc())
        .limit(limit)
        .all()
    )


for router in (
    auth.router,
    employees.router,
    activities.router,
    risk_scoring.router,
    alerts.router,
    incidents.router,
    investigations.router,
    reports.router,
    dashboards.router,
):
    app.include_router(router, prefix=settings.API_V1_STR)
