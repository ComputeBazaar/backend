import redis
import json
from models import Resources, ContainerInfo
from database import get_db, Base, engine
from db_model import User

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
import uuid

pool = redis.ConnectionPool(
    host='localhost',
    port=6379,
    db=0,
    max_connections=50,
    decode_responses=True
)

pool2 = redis.ConnectionPool(
    host='localhost',
    port=6379,
    db=1,
    max_connections=50,
    decode_responses=True
)

def get_edge_user(auth_token: str, db: Session) -> User | None:
    try:
        token_uuid = uuid.UUID(auth_token)  # convert string to UUID
    except ValueError:
        return None  # invalid UUID

    return db.query(User).filter(User.api_key == token_uuid).first()


def authenticate_edge(auth_token: str, db: Session) -> bool:
    return get_edge_user(auth_token, db) is not None


def get_edge_id(auth_token: str, db: Session) -> int | None:
    user = get_edge_user(auth_token, db)
    return user.id if user else None


def redis_add_edge(edge_id: str, resources: Resources):
    client = redis.Redis(connection_pool=pool)
    client.set(f"edge:{edge_id}", json.dumps(resources.model_dump()))

def redis_remove_edge(edge_id: str):
    client = redis.Redis(connection_pool=pool)
    client.delete(f"edge:{edge_id}", "resources")

def redis_add_conn(edge_id: str, user_id: str, containerInfo: ContainerInfo):
    client = redis.Redis(connection_pool=pool2)
    client.set(f"{user_id}:{edge_id}", json.dumps(containerInfo.model_dump()))

def redis_get_conn(edge_id: str, user_id: str):
    client = redis.Redis(connection_pool=pool2)
    return client.get(f"{user_id}:{edge_id}")

def redis_remove_conn(edge_id: str, user_id: str, containerInfo: ContainerInfo):
    client = redis.Redis(connection_pool=pool2)
    client.delete(f"{user_id}:{edge_id}", "containerInfo")

def redis_isconnected(user_id: str):
    client = redis.Redis(connection_pool=pool2)
    if (client.keys(f"{user_id}:*")):
        return client.keys(f"{user_id}:*")[0].split(":")[1]  # return edge_id
    return ""

def redis_get_all_edges():
    client = redis.Redis(connection_pool=pool, decode_responses=True)

    keys = client.keys("*")
    edges = {}

    for key in keys:
        if "edge:" in key:
            edge_id = key.split("edge:")[1]
            edge_data = str(client.get(key))
            edges[edge_id] = json.loads(edge_data)
    return edges
    