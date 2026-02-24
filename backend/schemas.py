from typing import Optional
from pydantic import BaseModel, Field


class VPNConnectRequest(BaseModel):
    # "\"\"\"VPN connection request model.
    
    # VPN DISABLED (2026-02-10): VPN fields are kept for backward compatibility
    # but are not used since the backend is on the same network as HPC clusters.
    # "\"\""
    user_id: str
    # VPN DISABLED - These fields are optional/ignored
    vpn_url: Optional[str] = None  # Kept for backward compatibility
    username: Optional[str] = None
    password: Optional[str] = None
    real: bool = Field(False, description="VPN DISABLED - This flag is ignored")


class SSHConnectRequest(BaseModel):
    user_id: Optional[str] = None  # Optional - JWT auth provides it
    session_id: str = "default"
    hostname: str
    username: str
    password: Optional[str] = None
    port: int = 22
    cluster_type: str = Field("simple", description="Cluster type: slurm, bastion, or simple")


class BastionRunRequest(BaseModel):
    user_id: Optional[str] = None  # Optional - JWT auth provides it
    session_id: str = "default"
    command: str
    timeout: int = 30
