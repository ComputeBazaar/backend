from pydantic import BaseModel, EmailStr
from enum import Enum

class UserRegister(BaseModel):
    name: str
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class UserProfile(BaseModel):
    id: int
    name: str
    email: EmailStr
    api_key: str

class ApiKeyResponse(BaseModel):
    api_key: str


# Models for Edge Server

class MessageType(Enum):
    MONITOR_REQ = "MONITOR_REQ"
    MONITOR_ACK = "MONITOR_ACK"
    ASSIGN_REQ = "ASSIGN_REQ"
    ASSIGN_ACK = "ASSIGN_ACK"
    ASSIGN_REJ = "ASSIGN_REJ"
    CLEANUP_REQ = "CLEANUP_REQ"
    CLEANUP_ACK = "CLEANUP_ACK"
    INCR_REQ = "INCR_REQ"
    INCR_ACK = "INCR_ACK"
    INCR_AUTH = "INCR_AUTH"
    CMD_REQ = "CMD_REQ"
    CMD_ACK = "CMD_ACK"
    CMD_ERR = "CMD_ERR"
    CLN_REQ = "CLN_REQ"
    CLN_ACK = "CLN_ACK"

class Resources(BaseModel):
    cpu_cores: int
    memory_gb: int
    disk_gb: int
    nvidia_gpu: bool = False

class Credentials(BaseModel):
    host: str
    port: int
    passwd: str

class MonitorAck(BaseModel):
    type: str
    auth_token: str
    resources: Resources

class ContainerInfo(BaseModel):
    container_id: str
    resources: Resources
    credentials: Credentials

class AssignResp(BaseModel):
    type: str
    auth_token: str
    containerInfo: ContainerInfo = None

class CmdReq(BaseModel):
    container_id: str
    credentials: Credentials
    cmd: str

class ExecResp(BaseModel):
    type: str
    stdout: str

class ClnReq(BaseModel):
    container_id: str
    resources: Resources
