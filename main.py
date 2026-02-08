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
from redis_utils import redis_remove_edge, redis_add_edge, authenticate_edge, get_edge_id, redis_get_all_edges, redis_add_conn, redis_remove_conn, redis_get_conn, redis_isconnected


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
    # print("Current user:", user.id)
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
        "id": current_user.id,
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

# @app.post("/api/edge/assign/{edge_id}")
async def assign(edge_id: str, resources: Resources, resp: Response, db: Session = Depends(get_db)):
    ws = EDGE_CONNECTIONS.get(edge_id)
    if (ws is None):
        resp.status_code = 502
        return {"info": "bad gateway now connected"}
    
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

            if not authenticate_edge(response.auth_token, db):
                resp.status_code = 502
                return {"info": "bad gateway authentication"}

            if response.type == MessageType.ASSIGN_ACK.value:
                resp.status_code = 200
                return response.containerInfo.model_dump()
                
            else:
                print(response)
                resp.status_code = 503
                return {"info": "service unvailable from the client"}

        except ValidationError as e:
            resp.status_code = 502
            print(e)
            print(response)
            return {"info": "bad gateway validation"}

    except WebSocketDisconnect:
        pass

    resp.status_code = 502
    return {"info": "bad gateway unprocessable"}

# @app.post("/api/edge/cleanup/{edge_id}")
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

@app.post("/api/edge/getcreds/{edge_id}")
async def get_creds(edge_id: str, user_id: str, resources: Resources, resp: Response, db: Session = Depends(get_db)):

    containerInfo = redis_get_conn(edge_id, user_id)
    if containerInfo:
        return json.loads(containerInfo)
    else:
        response = await assign(edge_id, resources, resp, db)
        redis_add_conn(edge_id, user_id, ContainerInfo.model_validate(response))
        return response

@app.post("/api/edge/leavecreds/{edge_id}")
async def leave_creds(edge_id: str, user_id: str, resp: Response, db: Session = Depends(get_db)):

    if edge_id not in EDGE_CONNECTIONS:
        resp.status_code = 502
        return {"info": "bad gateway not connected"}
    
    containerInfo_str = redis_get_conn(edge_id, user_id)
    if containerInfo_str is None:
        return {"info": "connection removed"}
    
    containerInfo_dict = json.loads(containerInfo_str)
    containerInfo = ContainerInfo.model_validate(containerInfo_dict)
    redis_remove_conn(edge_id, user_id, containerInfo)

    await cleanup(edge_id, ClnReq(
        container_id=containerInfo.container_id, 
        resources=containerInfo.resources
    ), resp)

    return {"info": "connection removed"}

@app.get("/api/edge/isconnected/{user_id}")
async def is_connected(user_id: str, resp: Response):
    return {"connected": redis_isconnected(user_id)}

@app.websocket("/api/edge/ws")
async def ws_endpoint(ws: WebSocket, db: Session = Depends(get_db)):
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
            
            if authenticate_edge(auth_token, db):
                if edge_id is None:
                    edge_id = get_edge_id(auth_token, db)
                    edge_id = str(edge_id)
            else:
                payload = {
                    "type": MessageType.INCR_AUTH.value
                }
                await ws.send_text(json.dumps(payload))
                break

            EDGE_CONNECTIONS[edge_id] = ws
            redis_add_edge(edge_id, response.resources)
            await asyncio.sleep(30)
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

    cpu_cores: int
    memory_gb: int
    disk_gb: int
    nvidia_gpu: bool = False
    
    for key, val in edges.items():
        servers.append({
            "name": f"Server {key}",
            "edge_id": key,
            "price": 0.2,           # placeholder
            "cpu": val.get("cpu_cores", 1),
            "ram": f"{val.get('memory_gb', 1)} GB",
            "gpu": {
                "model": "NVIDIA GPU" if val.get("nvidia_gpu") else "No GPU"
            },
            "disk": f"{val.get('disk_gb', 5)} GB"     # placeholder
        })
    servers.append({
        "name": f"Server 1",
        "edge_id": "1",
        "price": 0.2,           # placeholder
        "cpu": 4,
        "ram": f"8 GB",
        "gpu": {
            "model": "NVIDIA GPU"
        },
        "disk": f"5 GB"     # placeholder
    })
    print(servers)
    # servers.append({
    #     "name": f"Server {key}",
    #     "price": 0.2,           # placeholder
    #     "cpu": val.get("cpu_cores", 1),
    #     "ram": f"{val.get('memory_gb', 1)}GB",
    #     "gpu": {
    #         "model": "NVIDIA GPU" if val.get("nvidia_gpu") else "No GPU"
    #     },
    #     "disk": f"{val.get('disk_gb', 5)}GB"     # placeholder
    # })
    # servers.append({
    #     "name": f"Server {key}",
    #     "price": 0.2,           # placeholder
    #     "cpu": val.get("cpu_cores", 1),
    #     "ram": f"{val.get('memory_gb', 1)}GB",
    #     "gpu": {
    #         "model": "NVIDIA GPU" if val.get("nvidia_gpu") else "No GPU"
    #     },
    #     "disk": f"{val.get('disk_gb', 5)}GB"     # placeholder
    # })
    return servers

# if __name__ == "__main__":
#     uvicorn.run(app, host="0.0.0.0", port=8000)