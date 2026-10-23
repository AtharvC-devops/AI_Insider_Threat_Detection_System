"""
Shared Limiter Module
---------------------
Defines the global slowapi Limiter instance so it can be imported by
both `app.main` and individual routers (e.g., auth.py) without circular
import issues.
"""

from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
