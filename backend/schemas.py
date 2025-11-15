from typing import Optional
from pydantic import BaseModel, Field


class VPNConnectRequest(BaseModel):
    user_id: str
    vpn_url: str
    username: Optional[str] = None
    password: Optional[str] = None
    real: bool = Field(False, description="If true and openconnect available, attempt real process")


class SSHConnectRequest(BaseModel):
    user_id: str
    session_id: str = "default"
    hostname: str
    username: str
    password: Optional[str] = None
    port: int = 22
    cluster_type: str = Field("simple", description="Cluster type: slurm, bastion, or simple")


class BastionRunRequest(BaseModel):
    user_id: str
    session_id: str = "default"
    command: str
    timeout: int = 30
