"""
This module contains the API endpoints for user registration, login, and retrieval of user data.

It utilizes the FastAPI framework for building the API and interacts with a database using SQLModel.
"""

from contextlib import asynccontextmanager
from typing import List

from fastapi import Body, Depends, FastAPI, HTTPException, status
from sqlmodel import Session, SQLModel, select

from src.db.database import engine, get_db
from src.models.data_models import LoginData, UserCreate, UserResponse
from src.models.db_models import User
from src.utils.jwt_handler import (
    create_access_token,
    create_refresh_token,
    decode_token,
)
from src.utils.shared import LOGGER


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    TODO: Initial development only
    Use Alembic for migrations in production.

    Create the database tables on startup
    """
    SQLModel.metadata.create_all(engine)
    yield


# create FastAPI app and register lifespan function
app = FastAPI(lifespan=lifespan)


@app.get("/")
def read_root():
    """
    Test endpoint
    """
    LOGGER.info("Mic check")
    return {"Mic check": 12}


@app.post("/api/v1/users/register", response_model=UserResponse)
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    """Register a new user with a username, email, and password"""
    # Check if the user already exists
    existing_user = db.exec(select(User).where(User.username == user.username)).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already registered")

    new_user = User.model_validate(user)  # validate the user data
    new_user.hash_password(user.password)  # hash user password

    # Save the new user to the database
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # return the new user
    return UserResponse(
        user_id=new_user.user_id or 0, username=new_user.username, email=new_user.email
    )


@app.get("/api/v1/users", response_model=List[UserResponse])
def get_users(db: Session = Depends(get_db)):
    """
    Get all users from the database. For admin only
    TODO: Authentication, pagination, filtering and sorting
    """
    users = db.exec(select(User)).all()
    return [
        UserResponse(
            user_id=user.user_id or 0, username=user.username, email=user.email
        )
        for user in users
    ]


@app.post("/api/v1/users/login", response_model=dict)
def login_user(login_data: LoginData, db: Session = Depends(get_db)):
    """
    Authenticate a user and return both a JWT access token and a refresh token.
    """
    user = db.exec(select(User).where(User.username == login_data.username)).first()
    if not user or not user.verify_password(login_data.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect username or password",
        )

    # Create a JWT access token and a refresh token for the authenticated user
    access_token = create_access_token({"sub": user.username})
    refresh_token = create_refresh_token({"sub": user.username})

    return {"access_token": access_token, "refresh_token": refresh_token}


@app.post("/api/v1/users/refresh-token")
def refresh_token(body: dict[str, str] = Body(...)):
    """
    Refresh the authentication token.
    Expects a JSON body with a 'token' field containing the expired or soon-to-expire JWT.
    Returns a new access token if the old one is valid (not blacklisted/revoked).
    """
    token = body.get("token")
    if not token:
        raise HTTPException(status_code=400, detail="Token is required.")
    payload = decode_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token.")
    # Remove exp from payload to avoid double-expiry
    payload.pop("exp", None)
    new_token = create_access_token(payload)
    return {"access_token": new_token}
