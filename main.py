from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from auth import (
    hash_password, verify_password, create_access_token,
    create_refresh_token, decode_token
)
from models import UserRegister, UserLogin, TokenResponse, UserProfile
from database import get_db, Base, engine
from db_model import User

# Create tables
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Microservice Platform API")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


# Get current user from JWT
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    payload = decode_token(token)
    if payload is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    user = db.query(User).filter(User.email == payload["sub"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


# Home
@app.get("/")
def home():
    return {"message": "Welcome to the Microservice Platform!"}


# Register
@app.post("/register")
def register(user: UserRegister, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="User already exists")

    new_user = User(
        name=user.name,
        email=user.email,
        password_hash=hash_password(user.password)
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {"message": "User registered successfully"}


# Login
@app.post("/login", response_model=TokenResponse)
def login(user: UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if not db_user or not verify_password(user.password, db_user.password_hash):
        raise HTTPException(status_code=400, detail="Invalid credentials")

    access_token = create_access_token({"sub": db_user.email})
    refresh_token = create_refresh_token({"sub": db_user.email})

    # Save refresh token in DB
    db_user.refresh_token = refresh_token
    db.commit()

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }


# Refresh access token
@app.post("/refresh")
def refresh_token_endpoint(refresh_token: str, db: Session = Depends(get_db)):
    payload = decode_token(refresh_token)
    if payload is None:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    user = db.query(User).filter(User.email == payload["sub"]).first()
    if not user or not user.refresh_token:
        # Refresh token missing → force login
        raise HTTPException(status_code=401, detail="No refresh token, please login again")

    if user.refresh_token != refresh_token:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    access_token = create_access_token({"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}


# Profile
@app.get("/me", response_model=UserProfile)
def get_profile(current_user: User = Depends(get_current_user)):
    return {
        "name": current_user.name,
        "email": current_user.email,
        "api_key": str(current_user.api_key)
    }


# Guest microservice
@app.get("/guest")
def guest_service(current_user: User = Depends(get_current_user)):
    return {"message": f"Welcome {current_user.name}! You can access the guest microservice."}


# Host microservice
@app.get("/host")
def host_service(current_user: User = Depends(get_current_user)):
    return {
        "message": f"Welcome {current_user.name}! Use this API key to connect your microservice backend.",
        "api_key": str(current_user.api_key)
    }