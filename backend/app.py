"""Entry point for the Vigilink MVP backend.

This module now acts as an orchestrator: implementation details are split into
small modules under the `backend/` package. The app exposes the same endpoints
as the previous single-file app (VPN, SSH, simple SFTP stubs, one-shot commands).
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import os
import secrets
import shlex
import subprocess
import time
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, List

import jwt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from fastapi import FastAPI, HTTPException, Depends, Header, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from schemas import VPNConnectRequest, SSHConnectRequest, BastionRunRequest
from docker_utils import (
    docker_available,
    create_container_for_user,
    remove_container,
    container_is_running,
    exec_in_container,
    # VPN DISABLED - Local network access, no VPN needed
    # run_openconnect_in_container,
)
from persistence import save_connections_to_disk, load_connections_from_disk
from ssh_utils import build_paramiko_client_sync, HAS_PARAMIKO
from middleware import add_request_id
from agent_service import AgentManager

logger = logging.getLogger("vigilink.backend")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# Security Configuration - Use environment variables in production
JWT_SECRET = os.getenv("JWT_SECRET_KEY", secrets.token_urlsafe(32))  # Generate secure random key if not set
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_DAYS = 30  # Token valid for 30 days for persistent sessions

# Encryption key for storing sensitive data (passwords, tokens)
ENCRYPTION_MASTER_KEY = os.getenv("ENCRYPTION_MASTER_KEY", base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())

# Security logging
security_logger = logging.getLogger("vigilink.security")
security_handler = logging.FileHandler("security_audit.log")
security_handler.setFormatter(logging.Formatter("%(asctime)s [SECURITY] %(message)s"))
security_logger.addHandler(security_handler)
security_logger.setLevel(logging.INFO)

# Rate limiting storage
login_attempts: Dict[str, list] = {}  # {ip: [timestamp1, timestamp2, ...]}
MAX_LOGIN_ATTEMPTS = 5
LOGIN_ATTEMPT_WINDOW = 300  # 5 minutes

def get_encryption_key() -> bytes:
    """Derive encryption key from master key using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'vigilink-salt-v1',  # In production, use random salt stored securely
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(ENCRYPTION_MASTER_KEY.encode()))

cipher_suite = Fernet(get_encryption_key())

def encrypt_password(password: str) -> str:
    """Encrypt password using Fernet symmetric encryption."""
    if not password:
        return ""
    encrypted = cipher_suite.encrypt(password.encode())
    return base64.urlsafe_b64encode(encrypted).decode()

def decrypt_password(encrypted_password: str) -> str:
    """Decrypt password using Fernet symmetric encryption."""
    if not encrypted_password:
        return ""
    try:
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_password.encode())
        decrypted = cipher_suite.decrypt(encrypted_bytes)
        return decrypted.decode()
    except Exception as e:
        logger.error(f"Failed to decrypt password: {e}")
        return ""

def audit_log(user_id: str, action: str, details: str = "", ip: str = "unknown"):
    """Log security-relevant events."""
    security_logger.info(f"user={user_id} action={action} ip={ip} details={details}")

# Auth Models
class LoginRequest(BaseModel):
    # VPN DISABLED - vpn_url is now optional/deprecated (local network access)
    vpn_url: Optional[str] = None  # Kept for backward compatibility, not used
    vpn_username: str  # Used as username for identification
    vpn_password: str  # Used as password for identification
    remember_me: bool = True

class LoginResponse(BaseModel):
    token: str
    user_id: str
    expires_at: int
    container_reused: bool

# User sessions storage (persisted to disk)
user_sessions: Dict[str, Dict[str, Any]] = {}  # {user_id: {vpn_url, username_hash, last_active, container_id}}


app = FastAPI(title="Vigilink MVP Backend", version="0.1")

# Security warnings if using default keys
if not os.getenv("JWT_SECRET_KEY"):
    logger.warning("⚠️  WARNING: Using auto-generated JWT secret. Set JWT_SECRET_KEY environment variable in production!")
if not os.getenv("ENCRYPTION_MASTER_KEY"):
    logger.warning("⚠️  WARNING: Using auto-generated encryption key. Set ENCRYPTION_MASTER_KEY environment variable in production!")

# CORS - allow all for dev/mobile
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register middleware function implemented in a separate module
app.middleware("http")(add_request_id)

# In-memory store for VPN containers per user
connections: Dict[str, Dict[str, Any]] = {}  # {user_id: {"container_id": ..., "vpn_started_at": ...}}

# Multi-session SSH store: user_id -> session_id -> SSHClient
ssh_sessions: Dict[str, Dict[str, Any]] = {}  # {user_id: {session_id: {"client": SSHClient, "hostname": ..., "username": ...}}}

# Simple per-user VPN connect cooldown (seconds)
vpn_last_attempts: Dict[str, float] = {}
VPN_CONNECT_COOLDOWN_SECONDS = 10

# Initialize Agent Manager
# We pass send_to_ssh_manager function to allow agent to execute commands
agent_manager = None  # Initialized on startup


def generate_user_id(vpn_url: str, username: str) -> str:
    """Generate deterministic user_id from credentials.
    
    VPN DISABLED: Now uses only username for ID generation.
    vpn_url parameter kept for backward compatibility but ignored.
    """
    # VPN DISABLED - Use only username for user_id generation
    # credential_string = f"{vpn_url}:{username}"
    credential_string = f"local:{username}"
    hash_digest = hashlib.sha256(credential_string.encode()).hexdigest()
    return f"user_{hash_digest[:16]}"


def create_jwt_token(user_id: str, vpn_url: str, username: str) -> str:
    """Create JWT token for user session.
    
    VPN DISABLED: vpn_url kept in payload for backward compatibility but set to 'local'.
    """
    expiration = datetime.utcnow() + timedelta(days=JWT_EXPIRATION_DAYS)
    payload = {
        "user_id": user_id,
        # VPN DISABLED - Using placeholder value
        "vpn_url": vpn_url or "local",
        "username": username,
        "exp": expiration,
        "iat": datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def verify_jwt_token(token: str) -> Dict[str, Any]:
    """Verify and decode JWT token."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


async def get_current_user(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    """Dependency to get current user from JWT token."""
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header missing")
    
    try:
        scheme, token = authorization.split()
        if scheme.lower() != "bearer":
            raise HTTPException(status_code=401, detail="Invalid authentication scheme")
        
        payload = verify_jwt_token(token)
        user_id = payload["user_id"]
        
        # Update last active timestamp
        if user_id in user_sessions:
            user_sessions[user_id]["last_active"] = int(time.time())
        
        return payload
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid authorization header format")


def _exec_ssh_command(client, cmd: str, timeout: int = 20):
    """Execute command via new channel on existing SSH client (blocking, run in threadpool)."""
    import time
    stdin, stdout, stderr = client.exec_command(cmd)
    stdout.channel.settimeout(timeout)
    stderr.channel.settimeout(timeout)
    
    try:
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        
        # Wait for exit status with timeout
        deadline = time.time() + timeout
        while not stdout.channel.exit_status_ready():
            if time.time() > deadline:
                return "", "Command timeout", 124
            time.sleep(0.1)
        
        code = stdout.channel.recv_exit_status()
        return out, err, code
    except Exception as e:
        return "", str(e), 1
    finally:
        try:
            stdout.channel.close()
        except:
            pass


async def run_blocking(func, *args, **kwargs):
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, lambda: func(*args, **kwargs))


def send_to_ssh_manager(container_id: str, command_json: Dict[str, Any], timeout: int = 30) -> Dict[str, Any]:
    """Send JSON command to ssh_manager.py daemon in container via TCP and get JSON response.
    ssh_manager.py listens on port 9999 via socat for persistent SSH connection management."""
    import json
    import base64
    try:
        # Encode JSON as base64 to avoid all shell escaping issues
        cmd_line = json.dumps(command_json)
        b64_cmd = base64.b64encode(cmd_line.encode('utf-8')).decode('ascii')
        
        # Decode base64 in container and pipe to nc
        # -q 0: close immediately after EOF for faster response (ssh_manager returns full JSON in one write)
        exec_cmd = f"echo {b64_cmd} | base64 -d | nc -q 0 localhost 9999"
        
        stdout, stderr, rc = exec_in_container(container_id, exec_cmd, timeout + 5)
        
        if rc != 0 and not stdout:
            return {"success": False, "error": f"Failed to communicate with ssh_manager: {stderr}"}
        
        # Parse response - socket daemon sends only the JSON response, no ready signal
        lines = [l for l in stdout.strip().split('\n') if l.strip()]
        if not lines:
            return {"success": False, "error": f"Empty response from ssh_manager"}
        
        # Get the last non-empty line (the actual response)
        response_line = lines[-1]
        result = json.loads(response_line)
        return result
        
    except json.JSONDecodeError as e:
        return {"success": False, "error": f"Invalid JSON response: {str(e)}", "raw_output": stdout}
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


@app.on_event("startup")
def _startup():
    logger.info("startup: loading persisted connections if present")
    load_connections_from_disk(connections)
    # Initialize Agent Manager
    global agent_manager
    agent_manager = AgentManager(send_to_ssh_manager)
    # TODO: Load user_sessions from disk for session persistence


@app.on_event("shutdown")
def _shutdown():
    logger.info("shutdown: persisting connections to disk")
    save_connections_to_disk(connections)


@app.post("/auth/login")
async def login(req: LoginRequest):
    """Authenticate user and create JWT token.
    Generates deterministic user_id from credentials for session persistence.
    
    VPN DISABLED: Container is created for SSH access but VPN connection is skipped.
    The backend is now on the same network as HPC clusters.
    """
    # Get client IP for rate limiting and audit logging
    # Note: In production, use X-Forwarded-For behind proxy
    client_ip = "127.0.0.1"  # TODO: Extract from request in production
    
    # Rate limiting by IP address
    now = time.time()
    if client_ip not in login_attempts:
        login_attempts[client_ip] = []
    
    # Clean old attempts outside window
    login_attempts[client_ip] = [t for t in login_attempts[client_ip] if now - t < LOGIN_ATTEMPT_WINDOW]
    
    # Check if too many attempts
    if len(login_attempts[client_ip]) >= MAX_LOGIN_ATTEMPTS:
        audit_log("unknown", "LOGIN_RATE_LIMITED", f"Exceeded {MAX_LOGIN_ATTEMPTS} attempts", client_ip)
        raise HTTPException(status_code=429, detail=f"Too many login attempts. Try again in {int(LOGIN_ATTEMPT_WINDOW/60)} minutes")
    
    login_attempts[client_ip].append(now)
    
    # Generate deterministic user_id (VPN DISABLED - uses only username now)
    user_id = generate_user_id(req.vpn_url, req.vpn_username)
    
    # Check per-user rate limiting
    last = vpn_last_attempts.get(user_id, 0)
    if now - last < VPN_CONNECT_COOLDOWN_SECONDS:
        audit_log(user_id, "LOGIN_COOLDOWN", f"Attempted login during cooldown", client_ip)
        raise HTTPException(status_code=429, detail=f"Too many attempts; wait {int(VPN_CONNECT_COOLDOWN_SECONDS - (now-last))}s")
    vpn_last_attempts[user_id] = now
    
    # Check if user has existing session and container
    existing_session = user_sessions.get(user_id)
    container_id = None
    container_reused = False
    
    if existing_session:
        # Check if container still exists
        old_container = existing_session.get("container_id")
        if old_container and await run_blocking(container_is_running, old_container):
            container_id = old_container
            container_reused = True
            logger.info("[auth] reusing existing container %s for user %s", container_id[:12], user_id)
    
    # If no existing container, create one (VPN DISABLED - no VPN connection needed)
    if not container_id:
        try:
            container_id = await run_blocking(create_container_for_user, user_id, "vigilink-backend:latest")
            logger.info("[auth] created container %s for user %s", container_id[:12], user_id)
            
            # VPN DISABLED - Skipping VPN connection, backend is on local network
            # The following VPN connection code is commented out:
            # started = await run_blocking(run_openconnect_in_container, container_id, req.vpn_url, req.vpn_username, req.vpn_password)
            # if not started:
            #     await run_blocking(remove_container, container_id)
            #     raise HTTPException(status_code=500, detail="VPN connection failed")
            logger.info("[auth] VPN DISABLED - container ready for direct SSH access")
                
        except Exception as e:
            logger.error("Login failed for user %s: %s", user_id, e)
            if container_id:
                try:
                    await run_blocking(remove_container, container_id)
                except:
                    pass
            raise HTTPException(status_code=500, detail=f"Login failed: {str(e)}")
    
    # Store user session with encrypted password (for potential future use)
    username_hash = hashlib.sha256(req.vpn_username.encode()).hexdigest()[:16]
    encrypted_vpn_password = encrypt_password(req.vpn_password)
    
    user_sessions[user_id] = {
        # VPN DISABLED - vpn_url kept for backward compatibility
        "vpn_url": req.vpn_url or "local",
        "username_hash": username_hash,
        "container_id": container_id,
        "last_active": int(time.time()),
        "created_at": int(time.time()),
        "ssh_credentials": {},  # Store SSH connection info: {session_id: {hostname, username, encrypted_password, port, cluster_type}}
        "password_encrypted": encrypted_vpn_password,  # Encrypted password for session identification
        "ip_address": client_ip,  # Track IP for security
        "login_count": user_sessions.get(user_id, {}).get("login_count", 0) + 1
    }
    
    # Store in connections dict for backward compatibility
    connections[user_id] = {
        "container_id": container_id,
        "container_started_at": int(time.time()),
        # VPN DISABLED - Always True since we're on local network
        "vpn_connected": True  # Kept for backward compatibility
    }
    
    # Generate JWT token
    token = create_jwt_token(user_id, req.vpn_url or "local", req.vpn_username)
    expiration = datetime.utcnow() + timedelta(days=JWT_EXPIRATION_DAYS)
    
    # Clear login attempts on successful login
    if client_ip in login_attempts:
        login_attempts[client_ip] = []
    
    # Security audit log (VPN DISABLED - logging local access)
    audit_log(user_id, "LOGIN_SUCCESS", f"local_access, container: {container_id[:12]}", client_ip)
    logger.info("[auth] login successful for user %s, token expires in %d days, container_reused=%s", user_id, JWT_EXPIRATION_DAYS, container_reused)
    
    return LoginResponse(
        token=token,
        user_id=user_id,
        expires_at=int(expiration.timestamp()),
        container_reused=container_reused
    )


@app.get("/auth/verify")
async def verify_token(current_user: Dict = Depends(get_current_user)):
    """Verify JWT token and return user info."""
    user_id = current_user["user_id"]
    session = user_sessions.get(user_id)
    
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    container_id = session.get("container_id")
    container_running = False
    if container_id:
        container_running = await run_blocking(container_is_running, container_id)
    
    return {
        "valid": True,
        "user_id": user_id,
        "vpn_url": current_user["vpn_url"],
        "username": current_user["username"],
        "container_running": container_running,
        "last_active": session.get("last_active")
    }


@app.post("/auth/logout")
async def logout(current_user: Dict = Depends(get_current_user)):
    """Logout user and securely clear session data."""
    user_id = current_user["user_id"]
    
    # Get session info before removal for audit
    session = user_sessions.get(user_id)
    client_ip = session.get("ip_address", "unknown") if session else "unknown"
    
    # Securely clear credentials from memory
    if session and "ssh_credentials" in session:
        for creds in session["ssh_credentials"].values():
            if "password" in creds:
                creds["password"] = "" * len(creds["password"])  # Overwrite memory
    
    # Remove from sessions
    user_sessions.pop(user_id, None)
    conn = connections.pop(user_id, None)
    
    # Don't remove container - allow session persistence
    # Container will be reused on next login with same credentials
    
    # Security audit log
    audit_log(user_id, "LOGOUT", "Session cleared, container preserved", client_ip)
    logger.info("[auth] logout user %s (container preserved for session persistence)", user_id)
    return {"status": "logged_out", "container_preserved": True}


@app.post("/vpn/connect")
async def vpn_connect(req: VPNConnectRequest, current_user: Dict = Depends(get_current_user)):
    """VPN DISABLED - This endpoint now only manages container lifecycle.
    
    VPN functionality has been disabled since the backend is now on the same
    network as HPC clusters. The endpoint is kept for backward compatibility
    and still creates/reuses containers for SSH access.
    """
    if not req.user_id:
        raise HTTPException(status_code=400, detail="user_id required")

    now = time.time()
    last = vpn_last_attempts.get(req.user_id, 0)
    if now - last < VPN_CONNECT_COOLDOWN_SECONDS:
        raise HTTPException(status_code=429, detail=f"Too many attempts; wait {int(VPN_CONNECT_COOLDOWN_SECONDS - (now-last))}s")
    vpn_last_attempts[req.user_id] = now

    conn = connections.get(req.user_id, {})
    
    # Check if container already exists and is running
    prev_cid = conn.get("container_id")
    if prev_cid and await run_blocking(container_is_running, prev_cid):
        logger.info("[container] reusing existing container %s for %s", prev_cid[:12], req.user_id)
        # VPN DISABLED - Skip VPN connection logic
        # if req.real and not conn.get("vpn_connected"):
        #     if not req.vpn_url:
        #         raise HTTPException(status_code=400, detail="vpn_url is required when real=true")
        #     try:
        #         started = await run_blocking(run_openconnect_in_container, prev_cid, req.vpn_url, req.username, req.password)
        #         if started:
        #             conn["vpn_connected"] = True
        #             connections[req.user_id] = conn
        #     except Exception as e:
        #         logger.error("OpenConnect startup failed for user %s: %s", req.user_id, e)
        #         raise HTTPException(status_code=500, detail=f"VPN connection failed: {str(e)}")
        conn["vpn_connected"] = True  # VPN DISABLED - Always mark as connected
        connections[req.user_id] = conn
        return {"status": "reused", "user_id": req.user_id, "container_id": prev_cid}

    if not docker_available():
        raise HTTPException(status_code=500, detail="Docker is not available. Ensure Docker daemon is running.")

    try:
        container_id = await run_blocking(create_container_for_user, req.user_id, "vigilink-backend:latest")
    except Exception as e:
        logger.error("Container creation failed for user %s: %s", req.user_id, e)
        raise HTTPException(status_code=500, detail=f"Container creation failed: {str(e)}")

    conn["container_id"] = container_id
    conn["container_started_at"] = int(time.time())
    conn["vpn_connected"] = True  # VPN DISABLED - Always mark as connected
    connections[req.user_id] = conn
    logger.info("[container] started for %s container=%s (VPN DISABLED)", req.user_id, container_id)

    # VPN DISABLED - Skip openconnect connection
    # if req.real:
    #     if not req.vpn_url:
    #         await run_blocking(remove_container, container_id)
    #         raise HTTPException(status_code=400, detail="vpn_url is required when real=true")
    #     try:
    #         started = await run_blocking(run_openconnect_in_container, container_id, req.vpn_url, req.username, req.password)
    #     except Exception as e:
    #         logger.error("OpenConnect startup failed for user %s: %s", req.user_id, e)
    #         # cleanup container on failure
    #         try:
    #             await run_blocking(remove_container, container_id)
    #         except Exception:
    #             pass
    #         raise HTTPException(status_code=500, detail=f"VPN connection failed: {str(e)}")
    #     if not started:
    #         await run_blocking(remove_container, container_id)
    #         raise HTTPException(status_code=500, detail="OpenConnect process failed to start. Check VPN credentials and server URL.")

    return {"status": "started", "user_id": req.user_id, "container_id": container_id}


@app.get("/vpn/status")
async def vpn_status(current_user: Dict = Depends(get_current_user)):
    """VPN DISABLED - Returns container status instead of VPN status.
    
    Since VPN is disabled, this endpoint now just reports if the container is running.
    For backward compatibility, 'connected' is always True when container is running.
    """
    user_id = current_user["user_id"]
    conn = connections.get(user_id)
    if not conn:
        # VPN DISABLED - Return not found but with helpful message
        raise HTTPException(status_code=404, detail=f"No session found for user '{user_id}'. Please login first.")
    container_id = conn.get("container_id")
    if container_id:
        running = await run_blocking(container_is_running, container_id)
        # VPN DISABLED - 'connected' now means container is running
        return {"connected": running, "container_id": container_id, "vpn_disabled": True}
    return {"connected": False, "vpn_disabled": True}


@app.post("/vpn/disconnect")
async def vpn_disconnect(current_user: Dict = Depends(get_current_user)):
    """VPN DISABLED - This endpoint removes the user's container.
    
    Since VPN is disabled, this just cleans up the container.
    """
    user_id = current_user["user_id"]
    
    conn = connections.get(user_id)
    if not conn:
        raise HTTPException(status_code=404, detail=f"No session found for user '{user_id}'")
    container_id = conn.get("container_id")
    if container_id:
        try:
            await run_blocking(remove_container, container_id)
        except Exception:
            logger.exception("failed to remove container %s", container_id)
        conn.pop("container_id", None)
    connections[user_id] = conn
    logger.info("[container] disconnected for %s (VPN DISABLED)", user_id)
    return {"status": "stopped", "vpn_disabled": True}


@app.post("/ssh/connect")
async def ssh_connect(req: SSHConnectRequest, current_user: Dict = Depends(get_current_user)):
    """Create a new persistent SSH session using ssh_manager.py in container.
    Establishes paramiko SSHClient inside container for persistent channel-based execution.
    
    VPN DISABLED: SSH connections are made directly from the container to HPC clusters
    on the local network without VPN tunnel.
    """
    user_id = current_user["user_id"]
    if not req.user_id or req.user_id != user_id:
        req.user_id = user_id  # Override with authenticated user_id
    
    if not req.hostname:
        raise HTTPException(status_code=400, detail="hostname is required")
    
    if not req.session_id:
        raise HTTPException(status_code=400, detail="session_id is required")
    
    # Check if user has a container - SSH runs from inside container
    conn = connections.get(req.user_id, {})
    container_id = conn.get("container_id")
    
    if not container_id:
        # VPN DISABLED - Updated error message
        raise HTTPException(status_code=400, detail="No container found. Please login first.")
    
    # Get or create user SSH sessions dict (not to be confused with global user_sessions)
    user_ssh_sessions = ssh_sessions.get(req.user_id, {})
    
    # Close existing session with same session_id if exists
    if req.session_id in user_ssh_sessions:
        logger.info("Replacing existing SSH session %s/%s", req.user_id, req.session_id)
        # Send disconnect command to ssh_manager
        disconnect_cmd = {
            "command": "disconnect",
            "session_id": req.session_id
        }
        await run_blocking(send_to_ssh_manager, container_id, disconnect_cmd, 1)
    
    # Send connect command to ssh_manager.py in container
    connect_cmd = {
        "command": "connect",
        "session_id": req.session_id,
        "hostname": req.hostname,
        "username": req.username,
        "password": req.password,
        "port": req.port,
        "timeout": 30
    }
    
    result = await run_blocking(send_to_ssh_manager, container_id, connect_cmd, 35)
    
    if not result.get("success"):
        error_msg = result.get("error", "Unknown error")
        logger.error("SSH connection failed for %s/%s to %s: %s", req.user_id, req.session_id, req.hostname, error_msg)
        raise HTTPException(status_code=502, detail=f"SSH connection failed: {error_msg}")
    
    # Store session info
    if req.user_id not in ssh_sessions:
        ssh_sessions[req.user_id] = {}
    
    # Auto-detect GPUs after connection
    gpu_available = None
    gpu_count = 0
    
    try:
        if req.cluster_type == "bastion":
            # For bastion, SSH to node1 and check GPUs with reduced timeout
            detect_cmd = {
                "command": "execute",
                "session_id": req.session_id,
                "cmd": "ssh -o ConnectTimeout=2 -o StrictHostKeyChecking=no node1 'nvidia-smi --list-gpus 2>/dev/null | wc -l' 2>/dev/null || echo 0",
                "timeout": 4
            }
        else:
            # For simple/slurm, directly check GPUs on login node
            detect_cmd = {
                "command": "execute",
                "session_id": req.session_id,
                "cmd": "nvidia-smi --list-gpus 2>/dev/null | wc -l || echo 0",
                "timeout": 3
            }
        
        gpu_result = await run_blocking(send_to_ssh_manager, container_id, detect_cmd, 6)
        if gpu_result.get("success"):
            try:
                output = gpu_result.get("stdout", "0").strip()
                gpu_count = int(output) if output.isdigit() else 0
                gpu_available = gpu_count > 0
            except (ValueError, AttributeError):
                gpu_available = False
    except Exception as e:
        logger.warning("GPU detection failed for %s/%s: %s", req.user_id, req.session_id, e)
        gpu_available = False
    
    ssh_sessions[req.user_id][req.session_id] = {
        "container_id": container_id,
        "hostname": req.hostname,
        "username": req.username,
        "port": req.port,
        "connected_at": time.time(),
        "persistent": True,  # Mark as persistent paramiko connection
        "cluster_type": req.cluster_type,
        "gpu_available": gpu_available,
        "gpu_count": gpu_count,
    }
    
    # Store SSH credentials in user session for auto-reconnect (encrypted)
    logger.info(f"[ssh_connect] Storing credentials for user_id: {user_id}, session_id: {req.session_id}")
    logger.info(f"[ssh_connect] user_id in user_sessions: {user_id in user_sessions}")
    
    if user_id in user_sessions:
        if "ssh_credentials" not in user_sessions[user_id]:
            user_sessions[user_id]["ssh_credentials"] = {}
        
        encrypted_ssh_password = encrypt_password(req.password) if req.password else ""
        
        user_sessions[user_id]["ssh_credentials"][req.session_id] = {
            "hostname": req.hostname,
            "username": req.username,
            "port": req.port,
            "cluster_type": req.cluster_type,
            "password_encrypted": encrypted_ssh_password,
            "connected_at": int(time.time())
        }
        
        logger.info(f"[ssh_connect] Credentials stored. Total saved sessions: {len(user_sessions[user_id]['ssh_credentials'])}")
        
        # Security audit log
        client_ip = user_sessions[user_id].get("ip_address", "unknown")
        audit_log(user_id, "SSH_CONNECT", f"Host: {req.hostname}, user: {req.username}", client_ip)
    else:
        logger.warning(f"[ssh_connect] user_id {user_id} NOT FOUND in user_sessions! Cannot save credentials.")
    
    logger.info("[ssh] connected %s/%s to %s:%s (type=%s, gpus=%d) via persistent paramiko in container", req.user_id, req.session_id, req.hostname, req.port, req.cluster_type, gpu_count)
    return {
        "connected": True,
        "user_id": req.user_id,
        "session_id": req.session_id,
        "hostname": req.hostname,
        "port": req.port,
        "persistent": True,
        "cluster_type": req.cluster_type,
        "gpu_available": gpu_available,
        "gpu_count": gpu_count,
    }


@app.get("/ssh/credentials")
async def get_ssh_credentials(current_user: Dict = Depends(get_current_user)):
    """Get saved SSH credentials for auto-reconnect."""
    user_id = current_user["user_id"]
    session = user_sessions.get(user_id)
    
    if not session:
        return {"credentials": {}}
    
    saved_creds = session.get("ssh_credentials", {})
    # Return credentials without passwords for security (passwords stored server-side)
    safe_creds = {}
    for session_id, creds in saved_creds.items():
        safe_creds[session_id] = {
            "hostname": creds["hostname"],
            "username": creds["username"],
            "port": creds["port"],
            "cluster_type": creds["cluster_type"],
            "has_password": bool(creds.get("password"))
        }
    
    return {"credentials": safe_creds}


@app.post("/ssh/reconnect")
async def ssh_reconnect(request: dict, current_user: Dict = Depends(get_current_user)):
    """Reconnect to SSH using saved encrypted credentials."""
    user_id = current_user["user_id"]
    session_id = request.get("session_id")
    
    if not session_id:
        raise HTTPException(status_code=400, detail="session_id required")
    
    session = user_sessions.get(user_id)
    
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    saved_creds = session.get("ssh_credentials", {})
    
    # Debug logging
    logger.info(f"[ssh/reconnect] Looking for session_id: {session_id}")
    logger.info(f"[ssh/reconnect] Available sessions: {list(saved_creds.keys())}")
    
    if session_id not in saved_creds:
        raise HTTPException(status_code=404, detail=f"No saved credentials for session '{session_id}'. Available: {list(saved_creds.keys())}")
    
    creds = saved_creds[session_id]
    
    # Decrypt password
    decrypted_password = decrypt_password(creds.get("password_encrypted", ""))
    
    # Create SSHConnectRequest with saved credentials
    req = SSHConnectRequest(
        user_id=user_id,
        session_id=session_id,
        hostname=creds["hostname"],
        username=creds["username"],
        password=decrypted_password,
        port=creds["port"],
        cluster_type=creds["cluster_type"]
    )
    
    # Security audit log
    client_ip = session.get("ip_address", "unknown")
    audit_log(user_id, "SSH_RECONNECT", f"Host: {creds['hostname']}, session: {session_id}", client_ip)
    
    # Reuse ssh_connect logic
    return await ssh_connect(req, current_user)


@app.post("/ssh/update-config")
async def ssh_update_config(request: dict, current_user: Dict = Depends(get_current_user)):
    """Update SSH session configuration (cluster type, etc.) without reconnecting."""
    user_id = current_user["user_id"]
    session_id = request.get("session_id")
    cluster_type = request.get("cluster_type")
    
    if not session_id:
        raise HTTPException(status_code=400, detail="session_id required")
    if not cluster_type or cluster_type not in ["simple", "bastion", "slurm"]:
        raise HTTPException(status_code=400, detail="Invalid cluster_type. Must be: simple, bastion, or slurm")
    
    session = user_sessions.get(user_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    # Debug logging
    logger.info(f"[ssh/update-config] Looking for session_id: {session_id}")
    logger.info(f"[ssh/update-config] User session exists, checking credentials...")
    
    # Update saved credentials
    saved_creds = session.get("ssh_credentials", {})
    logger.info(f"[ssh/update-config] Available sessions: {list(saved_creds.keys())}")
    
    if session_id in saved_creds:
        old_type = saved_creds[session_id].get("cluster_type")
        saved_creds[session_id]["cluster_type"] = cluster_type
        
        # Security audit log
        client_ip = session.get("ip_address", "unknown")
        audit_log(user_id, "SSH_CONFIG_UPDATE", f"Session: {session_id}, type: {old_type} -> {cluster_type}", client_ip)
        
        logger.info("[ssh] updated config for %s/%s: cluster_type=%s -> %s", user_id, session_id, old_type, cluster_type)
    else:
        logger.warning(f"[ssh/update-config] Session {session_id} not found in saved credentials!")
        raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found in saved credentials")
    
    # Update active session if exists
    if user_id in ssh_sessions and session_id in ssh_sessions[user_id]:
        ssh_sessions[user_id][session_id]["cluster_type"] = cluster_type
        logger.info("[ssh] updated active session cluster_type")
    
    return {
        "success": True,
        "session_id": session_id,
        "cluster_type": cluster_type,
        "message": "Configuration updated. Reconnect for changes to take effect."
    }


@app.get("/ssh/status")
async def ssh_status(current_user: Dict = Depends(get_current_user)):
    user_id = current_user["user_id"]
    """Get status of all SSH sessions for a user."""
    if user_id not in ssh_sessions:
        return {"connected": False, "user_id": user_id, "sessions": []}
    
    user_ssh_sessions = ssh_sessions[user_id]
    sessions_info = []
    
    for session_id, session in user_ssh_sessions.items():
        # For persistent SSH sessions managed by ssh_manager, assume active if in dict
        # The session is only added to ssh_sessions after successful connection
        # and removed on explicit disconnect
        container_id = session.get("container_id")
        active = True  # Default to true for persistent sessions
        
        if session.get("persistent") and container_id:
            # For persistent sessions, trust they're active if they exist in the dict
            # Sessions are only added after successful connection and removed on disconnect
            # This avoids 1+ second latency from querying ssh_manager on every status check
            active = True
        else:
            # Legacy client-based check (fallback for non-persistent sessions)
            client = session.get("client")
            if client and hasattr(client, "get_transport"):
                transport = client.get_transport()
                active = transport is not None and transport.is_active()
            else:
                active = False
        
        sessions_info.append({
            "session_id": session_id,
            "hostname": session.get("hostname"),
            "username": session.get("username"),
            "port": session.get("port"),
            "active": active,
            "connected_at": session.get("connected_at"),
            "cluster_type": session.get("cluster_type", "simple"),
            "gpu_available": session.get("gpu_available"),
            "gpu_count": session.get("gpu_count", 0),
        })
    
    return {
        "connected": len(sessions_info) > 0,
        "user_id": user_id,
        "sessions": sessions_info,
        "count": len(sessions_info),
    }


@app.post("/ssh/disconnect")
async def ssh_disconnect(session_id: str, current_user: Dict = Depends(get_current_user)):
    user_id = current_user["user_id"]
    """Disconnect a persistent SSH session via ssh_manager."""
    
    # Get session info for audit (from global user_sessions)
    user_session = user_sessions.get(user_id)
    if user_session:
        client_ip = user_session.get("ip_address", "unknown")
        ssh_cred = user_session.get("ssh_credentials", {}).get(session_id, {})
        hostname = ssh_cred.get("hostname", "unknown")
        audit_log(user_id, "SSH_DISCONNECT", f"Host: {hostname}, session: {session_id}", client_ip)
    
    if user_id not in ssh_sessions:
        raise HTTPException(status_code=404, detail=f"No SSH sessions for user '{user_id}'")
    
    user_ssh_sessions = ssh_sessions[user_id]
    if session_id not in user_ssh_sessions:
        raise HTTPException(status_code=404, detail=f"No SSH session '{session_id}' for user '{user_id}'")
    
    session = user_ssh_sessions[session_id]
    container_id = session.get("container_id")
    
    # Send disconnect command to ssh_manager.py if persistent connection
    if session.get("persistent") and container_id:
        disconnect_cmd = {
            "command": "disconnect",
            "session_id": session_id
        }
        try:
            result = await run_blocking(send_to_ssh_manager, container_id, disconnect_cmd, 10)
            if not result.get("success"):
                logger.warning("ssh_manager disconnect failed for %s/%s: %s", user_id, session_id, result.get("error"))
        except Exception:
            logger.exception("Failed to send disconnect to ssh_manager for %s/%s", user_id, session_id)
    
    del user_ssh_sessions[session_id]
    if not user_ssh_sessions:  # Clean up empty user entry
        del ssh_sessions[user_id]
    
    logger.info("[ssh] disconnected %s/%s", user_id, session_id)
    return {"disconnected": True, "user_id": user_id, "session_id": session_id}


@app.post("/api/terminal/bastion/run")
async def api_terminal_bastion_run(req: BastionRunRequest):
    """Run command on remote SSH session via persistent paramiko connection in container."""
    if not req.command:
        raise HTTPException(status_code=400, detail="command is required")
    
    if not req.session_id:
        raise HTTPException(status_code=400, detail="session_id is required")
    
    # Get SSH session
    if req.user_id not in ssh_sessions:
        raise HTTPException(status_code=404, detail=f"No SSH sessions for user '{req.user_id}'. Connect via /ssh/connect first.")
    
    user_sessions = ssh_sessions[req.user_id]
    if req.session_id not in user_sessions:
        raise HTTPException(status_code=404, detail=f"No SSH session '{req.session_id}' for user '{req.user_id}'.")
    
    session = user_sessions[req.session_id]
    container_id = session.get("container_id")
    
    if not container_id:
        raise HTTPException(status_code=500, detail="Container not available")
    
    # Execute command via ssh_manager.py using persistent connection
    execute_cmd = {
        "command": "execute",
        "session_id": req.session_id,
        "cmd": req.command,
        "timeout": req.timeout
    }
    
    result = await run_blocking(send_to_ssh_manager, container_id, execute_cmd, req.timeout + 5)
    
    if not result.get("success"):
        error_msg = result.get("error", "Unknown error")
        raise HTTPException(status_code=500, detail=f"SSH command execution failed: {error_msg}")
    
    return {
        "stdout": result.get("stdout", ""),
        "stderr": result.get("stderr", ""),
        "exit_code": result.get("exit_code", 0),
        "session_id": req.session_id,
        "hostname": session.get("hostname"),
        "persistent": True,
    }


@app.get("/api/container/fs/list")
async def api_container_fs_list(user_id: str, path: Optional[str] = None):
    """List files in the VPN container filesystem."""
    conn = connections.get(user_id)
    if not conn:
        raise HTTPException(status_code=404, detail=f"No active session for user '{user_id}'.")
    
    container_id = conn.get("container_id")
    if not container_id:
        raise HTTPException(status_code=400, detail="No VPN container found. Connect via /vpn/connect first.")
    
    cmd = f"ls -la {shlex.quote(path or '.')}"
    out, err, rc = await run_blocking(exec_in_container, container_id, cmd, 20)
    if rc != 0:
        raise HTTPException(status_code=500, detail=f"Failed to list directory '{path or '.'}': {err}")
    
    entries = []
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 9:
            continue
        name = " ".join(parts[8:])
        size = int(parts[4]) if parts[4].isdigit() else None
        entries.append({"name": name, "size": size, "mode": parts[0]})
    return {"path": path or ".", "entries": entries, "location": "container"}


@app.get("/api/container/fs/read")
async def api_container_fs_read(user_id: str, path: str, offset: int = 0, length: int = 65536):
    """Read a file from the VPN container filesystem."""
    conn = connections.get(user_id)
    if not conn:
        raise HTTPException(status_code=404, detail=f"No active session for user '{user_id}'.")
    
    if not path:
        raise HTTPException(status_code=400, detail="path parameter is required")
    
    container_id = conn.get("container_id")
    if not container_id:
        raise HTTPException(status_code=400, detail="No VPN container found. Connect via /vpn/connect first.")
    
    cmd = f"if [ -f {shlex.quote(path)} ]; then dd if={shlex.quote(path)} bs=1 skip={int(offset)} count={int(length)} 2>/dev/null || true; else echo ''; fi"
    out, err, rc = await run_blocking(exec_in_container, container_id, cmd, 20)
    return {"path": path, "offset": offset, "data": out, "location": "container"}


@app.get("/api/remote/fs/list")
async def api_remote_fs_list(user_id: str, path: Optional[str] = None, session_id: str = "default"):
    """List files on the remote SSH server via persistent paramiko connection in container."""
    if user_id not in ssh_sessions:
        raise HTTPException(status_code=404, detail=f"No SSH sessions for user '{user_id}'.")
    
    user_sessions = ssh_sessions[user_id]
    if session_id not in user_sessions:
        raise HTTPException(status_code=404, detail=f"No SSH session '{session_id}' for user '{user_id}'.")
    
    session = user_sessions[session_id]
    container_id = session.get("container_id")
    hostname = session.get("hostname")
    
    if not container_id:
        raise HTTPException(status_code=500, detail="Container not available")
    
    # Execute ls command via ssh_manager.py using persistent connection
    # We use ls -la because it's the most universally available command
    remote_cmd = f"ls -la {shlex.quote(path or '~')}"
    logger.info(f"[fs_list] Executing remote command: {remote_cmd}")
    
    execute_cmd = {
        "command": "execute",
        "session_id": session_id,
        "cmd": remote_cmd,
        "timeout": 30
    }
    
    result = await run_blocking(send_to_ssh_manager, container_id, execute_cmd, 35)
    
    if not result.get("success"):
        error_msg = result.get("error", "Unknown error")
        logger.error(f"[fs_list] Command execution failed: {error_msg}")
        raise HTTPException(status_code=500, detail=f"Failed to list remote directory: {error_msg}")
    
    if result.get("exit_code", 0) != 0:
        stderr = result.get('stderr', '')
        logger.error(f"[fs_list] Command returned non-zero exit code: {result.get('exit_code')}. Stderr: {stderr}")
        raise HTTPException(status_code=500, detail=f"Failed to list remote directory: {stderr}")
    
    out = result.get("stdout", "")
    logger.info(f"[fs_list] Raw stdout length: {len(out)}")
    logger.debug(f"[fs_list] Raw stdout preview: {out[:500]}...")
    
    entries = []
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("total"):
            continue
            
        parts = line.split()
        # Typical ls -la output has at least 8-9 columns
        # drwxr-xr-x 2 user group 4096 Nov 23 00:48 .
        if len(parts) < 8:
            logger.warning(f"[fs_list] Skipping line (too few parts): {line}")
            continue
            
        # Heuristic to find the filename
        # It usually starts after the date/time columns.
        # Date/time is usually 3 columns (Month Day Time/Year)
        # Permissions Links User Group Size Month Day Time/Year Name
        # 0           1     2    3     4    5     6   7         8+
        
        # Check if parts[0] looks like permissions
        if not (parts[0].startswith('d') or parts[0].startswith('-') or parts[0].startswith('l')):
            logger.warning(f"[fs_list] Skipping line (invalid permissions): {line}")
            continue
            
        try:
            # Size is usually at index 4
            size = int(parts[4])
        except (ValueError, IndexError):
            logger.warning(f"[fs_list] Failed to parse size from line: {line}")
            size = 0
            
        # Name starts at index 8 (usually)
        if len(parts) > 8:
            name = " ".join(parts[8:])
        else:
            # Fallback for weird formats
            name = parts[-1]
            
        if name == '.' or name == '..':
            continue
            
        entries.append({"name": name, "size": size, "mode": parts[0]})
    
    logger.info(f"[fs_list] Parsed {len(entries)} entries")
    return {"path": path or "~", "entries": entries, "location": "remote", "hostname": hostname}


@app.get("/api/remote/fs/read")
async def api_remote_fs_read(user_id: str, path: str, offset: int = 0, length: int = 65536, session_id: str = "default"):
    """Read a file from the remote SSH server via persistent paramiko connection in container."""
    if not path:
        raise HTTPException(status_code=400, detail="path parameter is required")
    
    if user_id not in ssh_sessions:
        raise HTTPException(status_code=404, detail=f"No SSH sessions for user '{user_id}'.")
    
    user_sessions = ssh_sessions[user_id]
    if session_id not in user_sessions:
        raise HTTPException(status_code=404, detail=f"No SSH session '{session_id}' for user '{user_id}'.")
    
    session = user_sessions[session_id]
    container_id = session.get("container_id")
    hostname = session.get("hostname")
    
    if not container_id:
        raise HTTPException(status_code=500, detail="Container not available")
    
    # Execute dd command via ssh_manager.py using persistent connection
    remote_cmd = f"dd if={shlex.quote(path)} bs=1 skip={int(offset)} count={int(length)} 2>/dev/null || true"
    execute_cmd = {
        "command": "execute",
        "session_id": session_id,
        "cmd": remote_cmd,
        "timeout": 30
    }
    
    result = await run_blocking(send_to_ssh_manager, container_id, execute_cmd, 35)
    
    if not result.get("success"):
        error_msg = result.get("error", "Unknown error")
        raise HTTPException(status_code=500, detail=f"Failed to read remote file: {error_msg}")
    
    out = result.get("stdout", "")
    return {"path": path, "offset": offset, "data": out, "location": "remote", "hostname": hostname, "session_id": session_id}


@app.get("/api/gpu/info")
async def get_gpu_info(session_id: str, current_user: Dict = Depends(get_current_user)):
    user_id = current_user["user_id"]
    """Get comprehensive GPU information optimized for low latency.
    Uses nvidia-smi with minimal fields for fastest response.
    Handles bastion clusters by SSHing to node1."""
    if user_id not in ssh_sessions:
        raise HTTPException(status_code=404, detail=f"No SSH sessions for user '{user_id}'.")
    
    user_sessions = ssh_sessions[user_id]
    if session_id not in user_sessions:
        raise HTTPException(status_code=404, detail=f"No SSH session '{session_id}' for user '{user_id}'.")
    
    session = user_sessions[session_id]
    container_id = session.get("container_id")
    hostname = session.get("hostname")
    cluster_type = session.get("cluster_type", "simple")
    
    if not container_id:
        raise HTTPException(status_code=500, detail="Container not available")
    
    # Optimized nvidia-smi query - only essential fields for speed
    # Added power draw, fan speed, and compute processes
    nvidia_query = "nvidia-smi --query-gpu=index,name,temperature.gpu,fan.speed,power.draw,power.limit,utilization.gpu,utilization.memory,memory.total,memory.used,memory.free --format=csv,noheader,nounits"
    
    # For bastion, SSH to node1 first
    if cluster_type == "bastion":
        remote_cmd = f"ssh -o ConnectTimeout=3 -o StrictHostKeyChecking=no node1 '{nvidia_query}' 2>/dev/null"
    else:
        remote_cmd = nvidia_query
    
    execute_cmd = {
        "command": "execute",
        "session_id": session_id,
        "cmd": remote_cmd,
        "timeout": 10
    }
    
    result = await run_blocking(send_to_ssh_manager, container_id, execute_cmd, 12)
    
    if not result.get("success"):
        error_msg = result.get("error", "Unknown error")
        raise HTTPException(status_code=500, detail=f"nvidia-smi failed: {error_msg}")
    
    if result.get("exit_code", 0) != 0:
        stderr = result.get("stderr", "")
        if "not found" in stderr.lower() or "no devices" in stderr.lower():
            return {"hostname": hostname, "gpus": [], "count": 0, "cluster_type": cluster_type}
        raise HTTPException(status_code=500, detail=f"nvidia-smi failed: {stderr}")
    
    out = result.get("stdout", "")
    
    # Parse CSV output with comprehensive metrics
    gpus = []
    for line in out.strip().split("\n"):
        if not line.strip():
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) >= 11:
            try:
                memory_total = int(parts[8]) if parts[8].isdigit() else 0
                memory_used = int(parts[9]) if parts[9].isdigit() else 0
                memory_free = int(parts[10]) if parts[10].isdigit() else 0
                
                gpu_data = {
                    "index": int(parts[0]) if parts[0].isdigit() else 0,
                    "name": parts[1],
                    "temperature": int(parts[2]) if parts[2].isdigit() else None,
                    "fan_speed": int(parts[3]) if parts[3].isdigit() else None,
                    "power_draw": float(parts[4]) if parts[4].replace('.', '').isdigit() else None,
                    "power_limit": float(parts[5]) if parts[5].replace('.', '').isdigit() else None,
                    "utilization_gpu": int(parts[6]) if parts[6].isdigit() else 0,
                    "utilization_memory": int(parts[7]) if parts[7].isdigit() else 0,
                    "memory_total": memory_total,
                    "memory_used": memory_used,
                    "memory_free": memory_free,
                    "memory_percent": round((memory_used / memory_total * 100) if memory_total > 0 else 0, 1)
                }
                gpus.append(gpu_data)
            except (ValueError, IndexError) as e:
                logger.warning("Failed to parse GPU line: %s - %s", line, e)
                continue
    
    return {
        "hostname": hostname,
        "gpus": gpus,
        "count": len(gpus),
        "cluster_type": cluster_type,
        "timestamp": int(time.time())
    }


@app.get("/api/files/list")
async def api_files_list(user_id: str, session_id: str, path: Optional[str] = None):
    """Enhanced file listing endpoint for FilesTab.
    Returns structured file information with proper type detection and formatting."""
    if user_id not in ssh_sessions:
        raise HTTPException(status_code=404, detail=f"No SSH sessions for user '{user_id}'.")
    
    user_sessions = ssh_sessions[user_id]
    if session_id not in user_sessions:
        raise HTTPException(status_code=404, detail=f"No SSH session '{session_id}' for user '{user_id}'.")
    
    session = user_sessions[session_id]
    container_id = session.get("container_id")
    hostname = session.get("hostname")
    
    if not container_id:
        raise HTTPException(status_code=500, detail="Container not available")
    
    # Use ls with detailed format and resolve path
    target_path = path or "~"
    # First resolve the path to get the actual directory
    # First resolve the path to get the actual directory
    resolve_cmd = f"cd {shlex.quote(target_path)} && pwd"
    resolve_result = await run_blocking(send_to_ssh_manager, container_id, {
        "command": "execute",
        "session_id": session_id,
        "cmd": resolve_cmd,
        "timeout": 15
    }, 20)
    
    if not resolve_result.get("success") or resolve_result.get("exit_code", 0) != 0:
        raise HTTPException(status_code=404, detail=f"Directory not found: {target_path}")
    
    current_path = resolve_result.get("stdout", "").strip()
    
    # Use ls with detailed format: permissions, size, date, time, name
    # --time-style for consistent date format
    ls_cmd = f"ls -lAh --time-style='+%Y-%m-%d %H:%M' {shlex.quote(current_path)} 2>/dev/null || ls -lA {shlex.quote(current_path)}"
    logger.info(f"[files_list] Executing: {ls_cmd}")
    
    execute_cmd = {
        "command": "execute",
        "session_id": session_id,
        "cmd": ls_cmd,
        "timeout": 20
    }
    
    result = await run_blocking(send_to_ssh_manager, container_id, execute_cmd, 25)
    
    if not result.get("success"):
        error_msg = result.get("error", "Unknown error")
        logger.error(f"[files_list] Command failed: {error_msg}")
        raise HTTPException(status_code=500, detail=f"Failed to list directory: {error_msg}")
    
    if result.get("exit_code", 0) != 0:
        stderr = result.get('stderr', '')
        logger.error(f"[files_list] Exit code {result.get('exit_code')}: {stderr}")
        raise HTTPException(status_code=500, detail=f"Failed to list directory: {stderr}")
    
    out = result.get("stdout", "")
    logger.info(f"[files_list] Output length: {len(out)}")
    logger.debug(f"[files_list] Output preview: {out[:500]}")
    
    files = []
    
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("total "):
            continue
        
        # Parse ls -l output format:
        # drwxr-xr-x 2 user group 4.0K 2024-01-15 10:30 dirname
        # -rw-r--r-- 1 user group  12K 2024-01-16 14:22 filename
        parts = line.split()
        
        # We expect at least 8 columns: perms, links, user, group, size, date, time, name
        if len(parts) < 8:
            logger.warning(f"[files_list] Skipping line (too few parts): {line}")
            continue
        
        permissions = parts[0]
        # Check if it looks like permissions
        if not (permissions.startswith('d') or permissions.startswith('-') or permissions.startswith('l')):
             logger.warning(f"[files_list] Skipping line (invalid perms): {line}")
             continue

        # Index 4 is size, 5 is date, 6 is time
        size = parts[4]
        date = parts[5]
        time_part = parts[6]
        
        # Name starts at index 7. Join the rest in case of spaces.
        name = " ".join(parts[7:])
        
        # Skip . and .. entries
        if name in (".", ".."):
            continue
        
        # Determine type from permissions
        file_type = "folder" if permissions.startswith("d") else "file"
        
        # Handle symlinks
        if permissions.startswith("l"):
            # Symlink format: name -> target
            if " -> " in name:
                name = name.split(" -> ")[0]
        
        files.append({
            "name": name,
            "type": file_type,
            "size": size if file_type == "file" else "-",
            "modified": f"{date} {time_part}",
            "permissions": permissions
        })
    
    logger.info(f"[files_list] Parsed {len(files)} files")
    
    # Sort: folders first, then alphabetically
    files.sort(key=lambda f: (f["type"] == "file", f["name"].lower()))
    
    return {
        "success": True,
        "path": current_path,
        "files": files,
        "hostname": hostname
    }


@app.get("/api/files/find_scripts")
async def api_files_find_scripts(user_id: str, session_id: str, path: Optional[str] = None):
    """Find Slurm job scripts in the user's home directory.
    Looks for files containing '#SBATCH --job-name=' recursively."""
    if user_id not in ssh_sessions:
        raise HTTPException(status_code=404, detail=f"No SSH sessions for user '{user_id}'.")
    
    user_sessions = ssh_sessions[user_id]
    if session_id not in user_sessions:
        raise HTTPException(status_code=404, detail=f"No SSH session '{session_id}' for user '{user_id}'.")
    
    session = user_sessions[session_id]
    container_id = session.get("container_id")
    
    if not container_id:
        raise HTTPException(status_code=500, detail="Container not available")
    
    # Get cluster type
    cluster_type = session.get("cluster_type", "simple")
    
    # First resolve the path to get the actual directory
    target_path = path or "~"
    
    # Use echo $HOME if target is ~ or starts with ~/
    if target_path == "~" or target_path.startswith("~/"):
        resolve_cmd = "echo $HOME"
        resolve_result = await run_blocking(send_to_ssh_manager, container_id, {
            "command": "execute",
            "session_id": session_id,
            "cmd": resolve_cmd,
            "timeout": 30
        }, 35)
        
        if resolve_result.get("success") and resolve_result.get("exit_code", 0) == 0:
            home_path = resolve_result.get("stdout", "").strip()
            if target_path == "~":
                current_path = home_path
            else:
                current_path = target_path.replace("~", home_path, 1)
        else:
            # Fallback to cd && pwd
            resolve_cmd = f"cd {shlex.quote(target_path)} && pwd"
            resolve_result = await run_blocking(send_to_ssh_manager, container_id, {
                "command": "execute",
                "session_id": session_id,
                "cmd": resolve_cmd,
                "timeout": 30
            }, 35)
            
            if resolve_result.get("success") and resolve_result.get("exit_code", 0) == 0:
                current_path = resolve_result.get("stdout", "").strip()
            else:
                current_path = target_path
    else:
        # For other paths, try to resolve absolute path
        resolve_cmd = f"cd {shlex.quote(target_path)} && pwd"
        resolve_result = await run_blocking(send_to_ssh_manager, container_id, {
            "command": "execute",
            "session_id": session_id,
            "cmd": resolve_cmd,
            "timeout": 30
        }, 35)
        
        if resolve_result.get("success") and resolve_result.get("exit_code", 0) == 0:
            current_path = resolve_result.get("stdout", "").strip()
        else:
            current_path = target_path
            
    logger.info(f"[find_scripts] Resolved path '{target_path}' to '{current_path}'")
    
    # Use find with maxdepth to prevent timeouts on large filesystems/network drives
    if cluster_type == "slurm":
        # Find files with specific extensions and grep for SBATCH
        cmd = (
            f"find {shlex.quote(current_path)} -maxdepth 5 "
            f"-type f \\( -name '*.sh' -o -name '*.slurm' -o -name '*.job' -o -name '*.batch' \\) "
            f"-exec grep -l '^#SBATCH --job-name=' {{}} + 2>/dev/null"
        )
    else:
        # For simple/bastion, find all .py and .sh scripts
        cmd = (
            f"find {shlex.quote(current_path)} -maxdepth 5 "
            f"-type f \\( -name '*.py' -o -name '*.sh' \\) "
            f"2>/dev/null"
        )
    
    logger.info(f"[find_scripts] Executing: {cmd}")
    
    execute_cmd = {
        "command": "execute",
        "session_id": session_id,
        "cmd": cmd,
        "timeout": 60  # Increased timeout
    }
    
    result = await run_blocking(send_to_ssh_manager, container_id, execute_cmd, 65)
    
    if not result.get("success"):
        # If grep finds nothing it might return exit code 1, which is fine
        if result.get("exit_code") == 1:
            return {"scripts": []}
            
        error_msg = result.get("error", "Unknown error")
        logger.error(f"[find_scripts] Command failed: {error_msg}")
        raise HTTPException(status_code=500, detail=f"Failed to find scripts: {error_msg}")
    
    out = result.get("stdout", "")
    scripts = [line.strip() for line in out.splitlines() if line.strip()]
    
    return {"scripts": scripts}


@app.get("/api/files/search")
async def api_files_search(user_id: str, session_id: str, query: Optional[str] = None, path: Optional[str] = None, limit: int = 20):
    """Search for files in the user's home directory (low latency).
    Uses 'find' with a limit to prevent timeouts."""
    if user_id not in ssh_sessions:
        raise HTTPException(status_code=404, detail=f"No SSH sessions for user '{user_id}'.")
    
    user_sessions = ssh_sessions[user_id]
    if session_id not in user_sessions:
        raise HTTPException(status_code=404, detail=f"No SSH session '{session_id}' for user '{user_id}'.")
    
    session = user_sessions[session_id]
    container_id = session.get("container_id")
    
    if not container_id:
        raise HTTPException(status_code=500, detail="Container not available")
    
    # Resolve path first
    target_path = path or "~"
    if target_path == "~" or target_path.startswith("~/"):
        resolve_cmd = "echo $HOME"
        resolve_result = await run_blocking(send_to_ssh_manager, container_id, {
            "command": "execute",
            "session_id": session_id,
            "cmd": resolve_cmd,
            "timeout": 10
        }, 15)
        
        if resolve_result.get("success") and resolve_result.get("exit_code", 0) == 0:
            home_path = resolve_result.get("stdout", "").strip()
            if target_path == "~":
                current_path = home_path
            else:
                current_path = target_path.replace("~", home_path, 1)
        else:
            current_path = target_path
    else:
        current_path = target_path
            
    # Construct find command
    # -maxdepth 4 to limit recursion
    # -type f for files only
    # -not -path '*/.*' to exclude hidden files/dirs
    base_cmd = f"find {shlex.quote(current_path)} -maxdepth 4 -not -path '*/.*' -type f"
    
    if query:
        # Case-insensitive search for filename
        base_cmd += f" -iname '*{shlex.quote(query)}*'"
    
    # Print relative path (%P) and limit results
    # We use head on the container side to minimize data transfer
    cmd = f"{base_cmd} -printf '%P\\n' | head -n {limit}"
    
    execute_cmd = {
        "command": "execute",
        "session_id": session_id,
        "cmd": cmd,
        "timeout": 10
    }
    
    result = await run_blocking(send_to_ssh_manager, container_id, execute_cmd, 15)
    
    if not result.get("success"):
        return {"files": []}
    
    out = result.get("stdout", "")
    files = [line.strip() for line in out.splitlines() if line.strip()]
    
    return {"files": files}


@app.get("/api/files/read")
async def api_files_read(user_id: str, session_id: str, path: str, max_size: int = 1048576, offset: int = 0):
    """Read file contents for preview in FilesTab.
    Returns file content with metadata. Limits size to prevent memory issues."""
    if not path:
        raise HTTPException(status_code=400, detail="path parameter is required")
    
    if user_id not in ssh_sessions:
        raise HTTPException(status_code=404, detail=f"No SSH sessions for user '{user_id}'.")
    
    user_sessions = ssh_sessions[user_id]
    if session_id not in user_sessions:
        raise HTTPException(status_code=404, detail=f"No SSH session '{session_id}' for user '{user_id}'.")
    
    session = user_sessions[session_id]
    container_id = session.get("container_id")
    
    if not container_id:
        raise HTTPException(status_code=500, detail="Container not available")
    
    # Check file size first
    stat_cmd = f"stat -c '%s' {shlex.quote(path)} 2>/dev/null || echo 'error'"
    stat_result = await run_blocking(send_to_ssh_manager, container_id, {
        "command": "execute",
        "session_id": session_id,
        "cmd": stat_cmd,
        "timeout": 5
    }, 6)
    
    if not stat_result.get("success") or "error" in stat_result.get("stdout", ""):
        raise HTTPException(status_code=404, detail=f"File not found: {path}")
    
    file_size = int(stat_result.get("stdout", "0").strip())
    
    # Limit chunk size, not total file size if offset is used
    # If offset is 0 and we are trying to read the whole file (implicit), then check max_size
    # But here max_size is used as "chunk size limit" effectively
    
    # Read file content
    # Use dd to read specific chunk
    # bs=1 skip=offset count=max_size
    read_cmd = f"dd if={shlex.quote(path)} bs=1 skip={int(offset)} count={int(max_size)} 2>/dev/null || true"
    
    read_result = await run_blocking(send_to_ssh_manager, container_id, {
        "command": "execute",
        "session_id": session_id,
        "cmd": read_cmd,
        "timeout": 10
    }, 12)
    
    if not read_result.get("success"):
        error_msg = read_result.get("error", "Unknown error")
        raise HTTPException(status_code=500, detail=f"Failed to read file: {error_msg}")
    
    # dd might exit with 0 even if it reads partial
    
    content = read_result.get("stdout", "")
    
    # Try to detect if binary
    is_binary = False
    try:
        content.encode('utf-8')
    except UnicodeDecodeError:
        is_binary = True
    
    # Check for null bytes (binary indicator)
    if '\x00' in content:
        is_binary = True
    
    return {
        "success": True,
        "path": path,
        "content": content if not is_binary else "[Binary file - cannot display]",
        "size": file_size, # Return total size
        "chunk_size": len(content),
        "is_binary": is_binary
    }


@app.websocket("/ws/terminal/{session_id}")
async def websocket_terminal(websocket: WebSocket, session_id: str):
    """WebSocket endpoint for interactive terminal with PTY support.
    Provides real-time bidirectional communication with remote SSH session."""
    await websocket.accept()
    
    # Verify JWT token from query params
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=1008, reason="Missing authentication token")
        return
    
    try:
        payload = verify_jwt_token(token)
        user_id = payload.get("user_id")
    except Exception as e:
        logger.error(f"WebSocket auth failed: {e}")
        await websocket.close(code=1008, reason="Invalid token")
        return
    
    # Get SSH session
    if user_id not in ssh_sessions or session_id not in ssh_sessions[user_id]:
        await websocket.close(code=1003, reason="SSH session not found")
        return
    
    session = ssh_sessions[user_id][session_id]
    container_id = session.get("container_id")
    
    if not container_id:
        await websocket.close(code=1011, reason="Container not available")
        return
    
    logger.info(f"[ws/terminal] Client connected to session {session_id}")
    
    # Send initial connection message
    await websocket.send_json({
        "type": "connected",
        "session_id": session_id,
        "hostname": session.get("hostname"),
        "username": session.get("username")
    })
    
    # Initialize shell buffer
    shell_buffer = ""
    shell_active = False
    
    try:
        # Try to start interactive PTY shell (for new containers with updated ssh_manager)
        shell_cmd = {
            "command": "shell_start",
            "session_id": session_id,
            "rows": 24,
            "cols": 80
        }
        logger.info(f"[ws/terminal] Attempting PTY shell for {session_id}")
        
        shell_result = await run_blocking(send_to_ssh_manager, container_id, shell_cmd, 2)
        logger.info(f"[ws/terminal] PTY result: {shell_result}")
        
        if shell_result.get("success"):
            shell_active = True
            logger.info(f"[ws/terminal] Started PTY shell for session {session_id}")
            
            # Read initial shell prompt/output
            await asyncio.sleep(0.2)  # Brief delay for shell initialization
            read_cmd = {"command": "shell_read", "session_id": session_id}
            read_result = await run_blocking(send_to_ssh_manager, container_id, read_cmd, 1)
            
            if read_result.get("success") and read_result.get("output"):
                await websocket.send_json({
                    "type": "output",
                    "data": read_result.get("output")
                })
        else:
            # Fallback to command-based mode for old containers
            logger.info(f"[ws/terminal] PTY not available, using command mode for session {session_id}")
            await websocket.send_json({
                "type": "output",
                "data": "$ "
            })
        
        # WebSocket communication loop
        while True:
            try:
                # Receive data from client
                data = await asyncio.wait_for(websocket.receive(), timeout=0.1)
                
                if "text" in data:
                    msg = data["text"]
                    
                    # Handle JSON messages
                    try:
                        import json
                        parsed = json.loads(msg)
                        msg_type = parsed.get("type")
                        
                        if msg_type == "input":
                            input_data = parsed.get("data", "")
                            
                            if shell_active:
                                # PTY mode: Send input directly to interactive shell
                                input_cmd = {
                                    "command": "shell_input",
                                    "session_id": session_id,
                                    "data": input_data
                                }
                                input_result = await run_blocking(send_to_ssh_manager, container_id, input_cmd, 1)
                                if input_result.get("success"):
                                    output = input_result.get("output", "")
                                    if output:
                                        await websocket.send_json({
                                            "type": "output",
                                            "data": output
                                        })
                                continue
                            
                            # Command mode fallback (for old containers without PTY support)
                            # Handle Ctrl+C (ASCII 3)
                            if input_data == '\x03':
                                shell_buffer = ""
                                await websocket.send_json({
                                    "type": "output",
                                    "data": "^C\\r\\n$ "
                                })
                                continue
                            
                            # Handle Ctrl+D (ASCII 4) - logout/exit
                            if input_data == '\x04':
                                await websocket.send_json({
                                    "type": "output",
                                    "data": "\\r\\nlogout\\r\\n"
                                })
                                await websocket.close(code=1000, reason="User logout")
                                return
                            
                            # Handle backspace (ASCII 127 or 8)
                            if input_data in ['\\x7f', '\\x08']:
                                if shell_buffer:
                                    shell_buffer = shell_buffer[:-1]
                                    await websocket.send_json({
                                        "type": "output",
                                        "data": "\\b \\b"
                                    })
                                continue
                            
                            # Don't add Enter/Return to buffer or echo it
                            if '\r' not in input_data and '\n' not in input_data:
                                shell_buffer += input_data
                                await websocket.send_json({
                                    "type": "output",
                                    "data": input_data
                                })
                            
                            # Execute command on Enter (CR or LF)
                            if '\r' in input_data or '\n' in input_data:
                                cmd_to_exec = shell_buffer.replace('\r', '').replace('\n', '').strip()
                                shell_buffer = ""
                                
                                if cmd_to_exec:
                                    exec_cmd = {
                                        "command": "execute",
                                        "session_id": session_id,
                                        "cmd": cmd_to_exec,
                                        "timeout": 15
                                    }
                                    
                                    exec_result = await run_blocking(send_to_ssh_manager, container_id, exec_cmd, 18)
                                    
                                    if exec_result.get("success"):
                                        # Send output with newline after command
                                        await websocket.send_json({
                                            "type": "output",
                                            "data": "\r\n"
                                        })
                                        
                                        stdout = exec_result.get("stdout", "")
                                        stderr = exec_result.get("stderr", "")
                                        
                                        if stdout:
                                            await websocket.send_json({
                                                "type": "output",
                                                "data": stdout
                                            })
                                        if stderr:
                                            await websocket.send_json({
                                                "type": "output",
                                                "data": f"\x1b[31m{stderr}\x1b[0m"
                                            })
                                        
                                        # Send prompt on new line
                                        await websocket.send_json({
                                            "type": "output",
                                            "data": "\r\n$ " if stdout or stderr else "$ "
                                        })
                                    else:
                                        error_msg = exec_result.get('error', 'Unknown error')
                                        if 'timeout' in error_msg.lower():
                                            await websocket.send_json({
                                                "type": "output",
                                                "data": f"\r\n\x1b[33mCommand timed out (15s limit). Use Ctrl+C to cancel long-running commands.\x1b[0m\r\n$ "
                                            })
                                        else:
                                            await websocket.send_json({
                                                "type": "output",
                                                "data": f"\r\n\x1b[31mError: {error_msg}\x1b[0m\r\n$ "
                                            })
                                else:
                                    # Empty command, just show prompt on new line
                                    await websocket.send_json({
                                        "type": "output",
                                        "data": "\r\n$ "
                                    })
                        
                        elif msg_type == "resize":
                            cols = parsed.get("cols", 80)
                            rows = parsed.get("rows", 24)
                            logger.info(f"[ws/terminal] Resize request: {cols}x{rows} for session {session_id}")
                            
                            if shell_active:
                                # PTY mode: Send resize to interactive shell
                                resize_cmd = {
                                    "command": "shell_resize",
                                    "session_id": session_id,
                                    "cols": cols,
                                    "rows": rows
                                }
                                resize_result = await run_blocking(send_to_ssh_manager, container_id, resize_cmd, 2)
                                logger.info(f"[ws/terminal] Resize result: {resize_result}")
                            # Command mode: Resize not applicable
                        
                        elif msg_type == "ping":
                            # Keep-alive ping
                            await websocket.send_json({"type": "pong"})
                    
                    except json.JSONDecodeError:
                        # Plain text input - treat as command input
                        command_buffer += msg
                        
                        # Echo back
                        await websocket.send_json({
                            "type": "output",
                            "data": msg
                        })
                
                elif "bytes" in data:
                    # Binary data (raw terminal input)
                    input_data = data["bytes"].decode('utf-8', errors='replace')
                    
                    if shell_active:
                        # PTY mode: Send binary input directly
                        input_cmd = {
                            "command": "shell_input",
                            "session_id": session_id,
                            "data": input_data
                        }
                        input_result = await run_blocking(send_to_ssh_manager, container_id, input_cmd, 1)
                        if input_result.get("success"):
                            output = input_result.get("output", "")
                            if output:
                                await websocket.send_json({
                                    "type": "output",
                                    "data": output
                                })
                    else:
                        # Command mode: Buffer and echo
                        shell_buffer += input_data
                        await websocket.send_json({
                            "type": "output",
                            "data": input_data
                        })
            
            except asyncio.TimeoutError:
                # Periodic output polling for PTY mode
                if shell_active:
                    read_cmd = {
                        "command": "shell_read",
                        "session_id": session_id
                    }
                    read_result = await run_blocking(send_to_ssh_manager, container_id, read_cmd, 1)
                    if read_result.get("success"):
                        output = read_result.get("output", "")
                        if output:
                            await websocket.send_json({
                                "type": "output",
                                "data": output
                            })
                continue
    
    except WebSocketDisconnect:
        logger.info(f"[ws/terminal] Client disconnected from session {session_id}")
    except Exception as e:
        logger.error(f"[ws/terminal] Error: {e}")
        try:
            await websocket.send_json({
                "type": "error",
                "message": str(e)
            })
        except:
            pass
    finally:
        # Cleanup shell if PTY mode was active
        if shell_active:
            try:
                stop_cmd = {
                    "command": "shell_stop",
                    "session_id": session_id
                }
                await run_blocking(send_to_ssh_manager, container_id, stop_cmd, 2)
            except Exception as e:
                logger.error(f"[ws/terminal] Error stopping shell: {e}")
        
        try:
            await websocket.close()
        except:
            pass


# --- Agent Endpoints ---

class AgentChatRequest(BaseModel):
    message: str
    session_id: str
    context_files: Optional[List[str]] = None

class AgentContextRequest(BaseModel):
    session_id: str
    file_path: str
    action: str  # "add" or "remove"

class FileWriteRequest(BaseModel):
    path: str
    content: str
    session_id: str

@app.post("/api/agent/chat")
async def agent_chat(req: AgentChatRequest, current_user: Dict = Depends(get_current_user)):
    """Send a message to the agent."""
    user_id = current_user["user_id"]
    
    # Get SSH session info
    if user_id not in ssh_sessions or req.session_id not in ssh_sessions[user_id]:
        raise HTTPException(status_code=404, detail="SSH session not found. Connect to a cluster first.")
    
    ssh_session = ssh_sessions[user_id][req.session_id]
    container_id = ssh_session.get("container_id")
    
    if not container_id:
        raise HTTPException(status_code=500, detail="Container not available")
    
    # Get or create agent session
    session = agent_manager.get_or_create_session(user_id, container_id, req.session_id)
    
    # Update context files if provided
    if req.context_files:
        for file in req.context_files:
            session.add_context_file(file)
            
    # Process message in background (or await if fast enough? For now await to keep it simple)
    # In a real app, we might want to use WebSocket or background tasks
    response = await session.process_message(req.message)
    
    return response

@app.get("/api/agent/history")
async def agent_history(session_id: str, current_user: Dict = Depends(get_current_user)):
    """Get agent conversation history."""
    user_id = current_user["user_id"]
    
    # Get session key
    session_key = f"{user_id}:{session_id}"
    session = agent_manager.get_session(session_key)
    
    if not session:
        return {"history": []}
    
    return {"history": session.get_history()}

@app.post("/api/agent/context")
async def agent_context(req: AgentContextRequest, current_user: Dict = Depends(get_current_user)):
    """Add or remove files from agent context."""
    user_id = current_user["user_id"]
    
    if user_id not in ssh_sessions or req.session_id not in ssh_sessions[user_id]:
        raise HTTPException(status_code=404, detail="SSH session not found")
    
    ssh_session = ssh_sessions[user_id][req.session_id]
    container_id = ssh_session.get("container_id")
    
    session = agent_manager.get_or_create_session(user_id, container_id, req.session_id)
    
    if req.action == "add":
        session.add_context_file(req.file_path)
    elif req.action == "remove":
        session.remove_context_file(req.file_path)
    
    return {"context_files": session.context_files}

@app.post("/api/files/write")
async def api_files_write(req: FileWriteRequest, current_user: Dict = Depends(get_current_user)):
    """Write content to a file (exposed for agent/user convenience)."""
    user_id = current_user["user_id"]
    
    if user_id not in ssh_sessions or req.session_id not in ssh_sessions[user_id]:
        raise HTTPException(status_code=404, detail="SSH session not found")
    
    ssh_session = ssh_sessions[user_id][req.session_id]
    container_id = ssh_session.get("container_id")
    
    if not container_id:
        raise HTTPException(status_code=500, detail="Container not available")
        
    # Use ToolExecutor logic directly or via a helper
    # We can reuse the logic from tools.py but we need to instantiate it
    # Or just use the agent's tool executor if a session exists
    
    session = agent_manager.get_or_create_session(user_id, container_id, req.session_id)
    result = session.tool_executor._write_file(req.path, req.content)
    
    if not result["success"]:
        raise HTTPException(status_code=500, detail=result.get("error", "Write failed"))
        
    return {"success": True, "path": req.path}


if __name__ == "__main__":
    print("Run with: uvicorn backend.app:app --host 0.0.0.0 --port 8000 --reload")
