import base64
import hashlib
import hmac
import os
import time


SECRET_KEY = os.environ.get("GHMON_SECRET_KEY", "change-me-in-production")
SESSION_TTL_SECONDS = 60 * 60 * 12


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 120_000)
    return "pbkdf2_sha256$120000$%s$%s" % (salt.hex(), digest.hex())


def verify_password(password: str, stored: str) -> bool:
    try:
        algorithm, rounds, salt_hex, digest_hex = stored.split("$", 3)
    except ValueError:
        return False
    if algorithm != "pbkdf2_sha256":
        return False
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        bytes.fromhex(salt_hex),
        int(rounds),
    )
    return hmac.compare_digest(digest.hex(), digest_hex)


def make_session(username: str) -> str:
    expires = str(int(time.time()) + SESSION_TTL_SECONDS)
    payload = f"{username}|{expires}"
    signature = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
    raw = f"{payload}|{signature}".encode()
    return base64.urlsafe_b64encode(raw).decode()


def read_session(value: str | None) -> str | None:
    if not value:
        return None
    try:
        raw = base64.urlsafe_b64decode(value.encode()).decode()
        username, expires, signature = raw.rsplit("|", 2)
    except Exception:
        return None
    payload = f"{username}|{expires}"
    expected = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        return None
    if int(expires) < int(time.time()):
        return None
    return username


def hash_value(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def mask_secret(value: str, keep: int = 4) -> str:
    if not value:
        return ""
    if len(value) <= keep * 2:
        return "*" * len(value)
    return f"{value[:keep]}...{value[-keep:]}"
