import os
import sys

from app.auth import get_password_hash
from app.database import Base, SessionLocal, engine
from app.models import User, UserRole


def initialize_database():
    email = os.getenv("BOOTSTRAP_ADMIN_EMAIL")
    password = os.getenv("BOOTSTRAP_ADMIN_PASSWORD")
    name = os.getenv("BOOTSTRAP_ADMIN_NAME", "SOC Administrator")
    if not email or not password:
        raise RuntimeError(
            "Set BOOTSTRAP_ADMIN_EMAIL and BOOTSTRAP_ADMIN_PASSWORD before initializing."
        )
    if len(password) < 12:
        raise RuntimeError("BOOTSTRAP_ADMIN_PASSWORD must be at least 12 characters.")
    if len(password.encode("utf-8")) > 72:
        raise RuntimeError("BOOTSTRAP_ADMIN_PASSWORD must not exceed 72 UTF-8 bytes.")

    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        existing_user = db.query(User).filter(User.email == email).first()
        if existing_user:
            if existing_user.role != UserRole.ADMINISTRATOR:
                raise RuntimeError(
                    f"Existing account {email} is not an administrator; refusing to change its role."
                )
            print(f"Administrator account {email} already exists.")
            return

        db.add(
            User(
                email=email,
                name=name,
                hashed_password=get_password_hash(password),
                role=UserRole.ADMINISTRATOR,
                is_active=True,
                department="Information Security",
            )
        )
        db.commit()
        print(f"Created initial administrator account {email}.")
    finally:
        db.close()


if __name__ == "__main__":
    try:
        initialize_database()
    except Exception as error:
        print(f"Database initialization failed: {error}", file=sys.stderr)
        raise
