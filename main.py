from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from models import UserRegister, UserLogin, TokenResponse
from auth import hash_password, verify_password, create_access_token, decode_access_token

app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Fake DB (dictionary)
users_db = {}


# ✅ Register API
@app.post("/register")
def register(user: UserRegister):
    if user.email in users_db:
        raise HTTPException(status_code=400, detail="User already exists")

    users_db[user.email] = {
        "name": user.name,
        "email": user.email,
        "password": hash_password(user.password),
        "role": user.role
    }

    return {"message": "User registered successfully"}


# ✅ Login API
@app.post("/login", response_model=TokenResponse)
def login(user: UserLogin):
    db_user = users_db.get(user.email)

    if not db_user:
        raise HTTPException(status_code=400, detail="Invalid credentials")

    if not verify_password(user.password, db_user["password"]):
        raise HTTPException(status_code=400, detail="Invalid credentials")

    # Create token with role inside
    token = create_access_token({
        "sub": db_user["email"],
        "role": db_user["role"]
    })

    return {"access_token": token}


# ✅ Protected Route Example
def get_current_user(token: str = Depends(oauth2_scheme)):
    payload = decode_access_token(token)

    if payload is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    return payload


@app.get("/me")
def get_profile(current_user: dict = Depends(get_current_user)):
    return {
        "email": current_user["sub"],
        "role": current_user["role"]
    }


# ✅ Host Only Route Example
@app.get("/host/dashboard")
def host_dashboard(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "host":
        raise HTTPException(status_code=403, detail="Only hosts allowed")

    return {"message": "Welcome Host, you can share resources!"}


# ✅ Guest Only Route Example
@app.get("/guest/request")
def guest_request(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "guest":
        raise HTTPException(status_code=403, detail="Only guests allowed")

    return {"message": "Welcome Guest, request compute here!"}
