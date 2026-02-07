from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from auth import (
    hash_password, verify_password,
    create_access_token, create_refresh_token,
    decode_token
)
from models import UserRegister, UserLogin, TokenResponse, UserProfile
from database import get_db, Base, engine
from db_model import User

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Microservice Platform API")

# ✅ CORS (REQUIRED for frontend)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # lock later
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    payload = decode_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    user = db.query(User).filter(User.email == payload["sub"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@app.get("/")
def home():
    return {"message": "API running"}


@app.post("/register")
def register(user: UserRegister, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(status_code=400, detail="User exists")

    new_user = User(
        name=user.name,
        email=user.email,
        password_hash=hash_password(user.password)
    )
    db.add(new_user)
    db.commit()

    return {"message": "Registered successfully"}


@app.post("/login", response_model=TokenResponse)
def login(user: UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()

    if not db_user or not verify_password(user.password, db_user.password_hash):
        raise HTTPException(status_code=400, detail="Invalid credentials")

    access_token = create_access_token({"sub": db_user.email})
    refresh_token = create_refresh_token({"sub": db_user.email})

    db_user.refresh_token = refresh_token
    db.commit()

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }


@app.post("/refresh")
def refresh(payload: dict, db: Session = Depends(get_db)):
    token = payload.get("refresh_token")
    data = decode_token(token)

    if not data:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    user = db.query(User).filter(User.email == data["sub"]).first()

    if not user or user.refresh_token != token:
        raise HTTPException(status_code=401, detail="Login required")

    new_access = create_access_token({"sub": user.email})
    return {"access_token": new_access, "token_type": "bearer"}


@app.get("/me", response_model=UserProfile)
def me(current_user: User = Depends(get_current_user)):
    return {
        "name": current_user.name,
        "email": current_user.email,
        "api_key": str(current_user.api_key)
    }


@app.get("/guest")
def guest(current_user: User = Depends(get_current_user)):
    return {"message": f"Guest access for {current_user.name}"}


@app.get("/host")
def host(current_user: User = Depends(get_current_user)):
    return {
        "message": "Host access",
        "api_key": str(current_user.api_key)
    }