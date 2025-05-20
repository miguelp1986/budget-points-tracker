import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import jwt

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_DURATION = int(
    os.getenv("ACCESS_TOKEN_EXPIRE_DURATION", "1800")
)  # default to 30 minutes in seconds
REFRESH_TOKEN_EXPIRE_DURATION = int(
    os.getenv("REFRESH_TOKEN_EXPIRE_DURATION", "604800")
)  # default to 7 days in seconds


def create_access_token(
    data: Dict[str, Any], expires_delta: Optional[timedelta] = None
) -> str:
    """
    Create access token.
    """
    if expires_delta is None:
        expires_delta = timedelta(seconds=ACCESS_TOKEN_EXPIRE_DURATION)
    return create_token(data, expires_delta)


def create_refresh_token(
    data: Dict[str, Any], expires_delta: Optional[timedelta] = None
) -> str:
    """
    Create refresh token.
    """
    if expires_delta is None:
        expires_delta = timedelta(seconds=REFRESH_TOKEN_EXPIRE_DURATION)
    return create_token(data, expires_delta)


def create_token(data: Dict[str, Any], expires_delta: timedelta) -> str:
    """
    General function to create a JWT token.
    """
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)  # type: ignore
    return encoded_jwt


def decode_token(token: str) -> Optional[Dict[str, Any]]:
    """
    General function to decode a JWT token.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])  # type: ignore
        return payload
    except jwt.PyJWTError:
        return None
