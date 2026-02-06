from pydantic import BaseModel


class UserRegister(BaseModel):
    name: str
    email: str
    password: str
    role: str  # "host" or "guest"


class UserLogin(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"