"""
This module contains the API endpoints for user registration, login, and retrieval of user data.

It utilizes the FastAPI framework for building the API and interacts with a database using SQLModel.
"""

from contextlib import asynccontextmanager
from typing import List

from fastapi import Depends, FastAPI, HTTPException, status
from sqlmodel import Session, SQLModel, select

from src.db.database import engine, get_db
from src.models.data_models import LoginData, UserCreate, UserResponse
from src.models.db_models import User
from src.utils.shared import LOGGER

app = FastAPI()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    TODO: Initial development only
    Use Alembic for migrations in production.

    Create the database tables on startup
    """
    SQLModel.metadata.create_all(engine)


@app.get("/")
def read_root():
    """."""
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
        user_id=new_user.user_id, username=new_user.username, email=new_user.email
    )


@app.get("/api/v1/users", response_model=List[UserResponse])
def get_users(db: Session = Depends(get_db)):
    """
    Get all users from the database. For admin only
    TODO: Authentication, pagination, filtering and sorting
    """
    users = db.exec(select(User)).all()
    return [
        UserResponse(user_id=user.user_id, username=user.username, email=user.email)
        for user in users
    ]


@app.get("/api/v1/users/login")
def login_user(login_data: LoginData, db: Session = Depends(get_db)):
    user = db.exec(select(User).where(User.username == login_data.username)).first()
    if not user or not user.verify_password(login_data.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect username or password",
        )
    return {"message": "Login successful"}
