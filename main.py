from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect, Response
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from utils import generate_api_key
from auth import (
    hash_password, verify_password,
    create_access_token, create_refresh_token,
    decode_token
)
# from models import UserRegister, UserLogin, TokenResponse, UserProfile, ApiKeyResponse
from database import get_db, Base, engine
from db_model import User
import json
import uvicorn
import asyncio
from models import *
from pydantic import ValidationError
from redis_utils import redis_remove_edge, redis_add_edge, authenticate_edge, get_edge_id, redis_get_all_edges


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

@app.post("/api/regenerate-key", response_model=ApiKeyResponse)
def regenerate_key(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Regenerate the API key for the currently authenticated user."""
    if not current_user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    # Generate new UUID API key
    new_key = generate_api_key()
    current_user.api_key = new_key
    
    # Save to DB
    db.add(current_user)
    db.commit()
    db.refresh(current_user)
    
    return {"api_key": new_key}

@app.get("/guest")
def guest(current_user: User = Depends(get_current_user)):
    return {"message": f"Guest access for {current_user.name}"}


@app.get("/host")
def host(current_user: User = Depends(get_current_user)):
    return {
        "message": "Host access",
        "api_key": str(current_user.api_key)
    }

# Edge Server Backend
EDGE_CONNECTIONS: dict[str, WebSocket] = {}

@app.post("/api/edge/assign/{edge_id}")
async def assign(edge_id: str, resources: Resources, resp: Response):
    ws = EDGE_CONNECTIONS.get(edge_id)
    if (ws is None):
        resp.status_code = 502
        return {"info": "bad gateway"}
    
    payload = {
        "type": MessageType.ASSIGN_REQ.value,
        "resources": resources.model_dump()
    }
    try:
        await ws.send_text(json.dumps(payload))
        raw = await ws.receive_text()
        response = json.loads(raw)

        try:
            response = AssignResp.model_validate(response)

            if not authenticate_edge(response.auth_token):
                resp.status_code = 502
                return {"info": "bad gateway"}

            if response.type == MessageType.ASSIGN_ACK.value:
                resp.status_code = 200
                return response.containerInfo.model_dump()
                
            else:
                resp.status_code = 503
                return {"info": "service unvailable from the client"}

        except ValidationError as e:
            resp.status_code = 502
            return {"info": "bad gateway"}

    except WebSocketDisconnect:
        pass

    resp.status_code = 502
    return {"info": "bad gateway"}

@app.post("/api/edge/execute/{edge_id}")
async def assign(cmdreq: CmdReq, edge_id: str, resp: Response):
    ws = EDGE_CONNECTIONS.get(edge_id)
    if (ws is None):
        resp.status_code = 502
        return {"info": "bad gateway"}
    
    payload = {
        "type": MessageType.CMD_REQ.value,
        "cmdreq": cmdreq.model_dump()
    }
    try:
        await ws.send_text(json.dumps(payload))
        raw = await ws.receive_text()
        response = json.loads(raw)

        try:
            response = ExecResp.model_validate(response)

            if response.type == MessageType.CMD_ACK.value:
                resp.status_code = 200
                return {"stdout": response.stdout}
                
            else:
                resp.status_code = 503
                return {"info": "service unvailable from the client"}

        except ValidationError as e:
            resp.status_code = 502
            return {"info": "bad gateway validation"}

    except WebSocketDisconnect:
        pass

    resp.status_code = 502
    return {"info": "bad gateway"}

@app.post("/api/edge/cleanup/{edge_id}")
async def cleanup(edge_id: str, clnReq: ClnReq, resp: Response):

    ws = EDGE_CONNECTIONS.get(edge_id)
    if (ws is None):
        resp.status_code = 502
        return {"info": "bad gateway"}
    
    payload = {
        "type": MessageType.CLN_REQ.value,
        "container_id": clnReq.container_id,
        "resources": clnReq.resources.model_dump()
    }
    try:
        await ws.send_text(json.dumps(payload))
        raw = await ws.receive_text()
        response = json.loads(raw)

        try:
            if response["type"] != MessageType.CLN_ACK.value:
                resp.status_code = 503
                return {"info": "service unvailable from the client"}
            else:
                resp.status_code = 200
                return {"info": "done"}
                
        except ValidationError as e:
            resp.status_code = 502
            return {"info": "bad gateway validation"}

    except WebSocketDisconnect:
        pass

    resp.status_code = 502
    return {"info": "bad gateway"}

@app.websocket("/api/edge/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()

    try:
        edge_id = None
        while True:

            payload = {
                "type": MessageType.MONITOR_REQ.value,
            }
            await ws.send_text(json.dumps(payload))

            raw = await ws.receive_text()
            response = json.loads(raw)

            try:
                response = MonitorAck.model_validate(response)
            except ValidationError as e:
                response = None

            if response is None or response.type != MessageType.MONITOR_ACK.value:
                payload = {
                    "type": MessageType.INCR_ACK.value
                }
                await ws.send_text(json.dumps(payload))
                break

            auth_token = response.auth_token
            
            if authenticate_edge(auth_token):
                if edge_id is None:
                    edge_id = get_edge_id(auth_token)
            else:
                payload = {
                    "type": MessageType.INCR_AUTH.value
                }
                await ws.send_text(json.dumps(payload))
                break

            EDGE_CONNECTIONS[edge_id] = ws
            redis_add_edge(edge_id, response.resources)
            await asyncio.sleep(5)
    except WebSocketDisconnect:
        pass
    finally:
        if edge_id:
            EDGE_CONNECTIONS.pop(edge_id, None)
            redis_remove_edge(edge_id)


@app.get("/api/servers")
def get_servers():
    edges = redis_get_all_edges()
    servers = []
    
    for edge in edges:
        servers.append({
            "name": edge.get("edge_id", "Unknown-Server"),
            "verified": True,  # optionally customize
            "rating": 4.5,     # placeholder
            "location": "Unknown",  # can store actual location in Redis
            "region": "eu",         # placeholder
            "price": 0.2,           # placeholder
            "cpu": {"cores": edge.get("cpu_cores", 4), "model": "Unknown"},
            "ram": {"size": edge.get("memory_gb", 16), "type": "DDR4", "detail": ""},
            "gpu": {
                "model": "NVIDIA GPU" if edge.get("nvidia_gpu") else "None",
                "vram": f"{edge.get('gpu_memory_mb', 0)}MB"
            },
            "network": "1 Gbps",  # placeholder
            "uptime": "99.9%"     # placeholder
        })

    return servers

# if __name__ == "__main__":
#     uvicorn.run(app, host="0.0.0.0", port=8000)