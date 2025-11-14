"""Entry point for the Vigilink MVP backend.

This module now acts as an orchestrator: implementation details are split into
small modules under the `backend/` package. The app exposes the same endpoints
as the previous single-file app (VPN, SSH, simple SFTP stubs, one-shot commands).
"""
from __future__ import annotations

import asyncio
import logging
import shlex
import subprocess
import time
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from schemas import VPNConnectRequest, SSHConnectRequest, BastionRunRequest
from docker_utils import (
    docker_available,
    create_container_for_user,
    remove_container,
    container_is_running,
    exec_in_container,
    run_openconnect_in_container,
)
from persistence import save_connections_to_disk, load_connections_from_disk
from ssh_utils import build_paramiko_client_sync, HAS_PARAMIKO
from middleware import add_request_id

logger = logging.getLogger("vigilink.backend")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


app = FastAPI(title="Vigilink MVP Backend", version="0.1")

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
        # -q 1: wait 1 second after EOF before closing, ensuring we read full response
        exec_cmd = f"echo {b64_cmd} | base64 -d | nc -q 1 localhost 9999"
        
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


@app.on_event("shutdown")
def _shutdown():
    logger.info("shutdown: persisting connections to disk")
    save_connections_to_disk(connections)


@app.post("/vpn/connect")
async def vpn_connect(req: VPNConnectRequest):
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
        logger.info("[vpn->container] reusing existing container %s for %s", prev_cid[:12], req.user_id)
        # If real VPN requested and not already connected, start openconnect
        if req.real and not conn.get("vpn_connected"):
            if not req.vpn_url:
                raise HTTPException(status_code=400, detail="vpn_url is required when real=true")
            try:
                started = await run_blocking(run_openconnect_in_container, prev_cid, req.vpn_url, req.username, req.password)
                if started:
                    conn["vpn_connected"] = True
                    connections[req.user_id] = conn
            except Exception as e:
                logger.error("OpenConnect startup failed for user %s: %s", req.user_id, e)
                raise HTTPException(status_code=500, detail=f"VPN connection failed: {str(e)}")
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
    connections[req.user_id] = conn
    logger.info("[vpn->container] started for %s container=%s", req.user_id, container_id)

    # If the client requested a "real" vpn connection, start openconnect inside the container
    if req.real:
        if not req.vpn_url:
            await run_blocking(remove_container, container_id)
            raise HTTPException(status_code=400, detail="vpn_url is required when real=true")
        try:
            started = await run_blocking(run_openconnect_in_container, container_id, req.vpn_url, req.username, req.password)
        except Exception as e:
            logger.error("OpenConnect startup failed for user %s: %s", req.user_id, e)
            # cleanup container on failure
            try:
                await run_blocking(remove_container, container_id)
            except Exception:
                pass
            raise HTTPException(status_code=500, detail=f"VPN connection failed: {str(e)}")
        if not started:
            await run_blocking(remove_container, container_id)
            raise HTTPException(status_code=500, detail="OpenConnect process failed to start. Check VPN credentials and server URL.")

    return {"status": "started", "user_id": req.user_id, "container_id": container_id}


@app.get("/vpn/status")
async def vpn_status(user_id: str):
    conn = connections.get(user_id)
    if not conn:
        raise HTTPException(status_code=404, detail=f"No VPN session found for user '{user_id}'")
    container_id = conn.get("container_id")
    if container_id:
        running = await run_blocking(container_is_running, container_id)
        return {"connected": running, "container_id": container_id}
    return {"connected": False}


@app.post("/vpn/disconnect")
async def vpn_disconnect(user_id: str):
    conn = connections.get(user_id)
    if not conn:
        raise HTTPException(status_code=404, detail=f"No VPN session found for user '{user_id}'")
    container_id = conn.get("container_id")
    if container_id:
        try:
            await run_blocking(remove_container, container_id)
        except Exception:
            logger.exception("failed to remove container %s", container_id)
        conn.pop("container_id", None)
    connections[user_id] = conn
    logger.info("[vpn->container] disconnected for %s", user_id)
    return {"status": "stopped"}


@app.post("/ssh/connect")
async def ssh_connect(req: SSHConnectRequest):
    """Create a new persistent SSH session using ssh_manager.py in container.
    Establishes paramiko SSHClient inside VPN container for persistent channel-based execution."""
    if not req.user_id:
        raise HTTPException(status_code=400, detail="user_id required")
    
    if not req.hostname:
        raise HTTPException(status_code=400, detail="hostname is required")
    
    if not req.session_id:
        raise HTTPException(status_code=400, detail="session_id is required")
    
    # Check if user has a VPN container - SSH MUST run from inside container
    conn = connections.get(req.user_id, {})
    container_id = conn.get("container_id")
    
    if not container_id:
        raise HTTPException(status_code=400, detail="No VPN container found. Connect via /vpn/connect first to access private network.")
    
    # Get or create user sessions dict
    user_sessions = ssh_sessions.get(req.user_id, {})
    
    # Close existing session with same session_id if exists
    if req.session_id in user_sessions:
        logger.info("Replacing existing SSH session %s/%s", req.user_id, req.session_id)
        # Send disconnect command to ssh_manager
        disconnect_cmd = {
            "command": "disconnect",
            "session_id": req.session_id
        }
        await run_blocking(send_to_ssh_manager, container_id, disconnect_cmd, 10)
    
    # Send connect command to ssh_manager.py in container
    connect_cmd = {
        "command": "connect",
        "session_id": req.session_id,
        "hostname": req.hostname,
        "username": req.username,
        "password": req.password,
        "port": req.port,
        "timeout": 10
    }
    
    result = await run_blocking(send_to_ssh_manager, container_id, connect_cmd, 15)
    
    if not result.get("success"):
        error_msg = result.get("error", "Unknown error")
        logger.error("SSH connection failed for %s/%s to %s: %s", req.user_id, req.session_id, req.hostname, error_msg)
        raise HTTPException(status_code=502, detail=f"SSH connection failed: {error_msg}")
    
    # Store session info
    if req.user_id not in ssh_sessions:
        ssh_sessions[req.user_id] = {}
    
    ssh_sessions[req.user_id][req.session_id] = {
        "container_id": container_id,
        "hostname": req.hostname,
        "username": req.username,
        "port": req.port,
        "connected_at": time.time(),
        "persistent": True,  # Mark as persistent paramiko connection
    }
    
    logger.info("[ssh] connected %s/%s to %s:%s via persistent paramiko in container", req.user_id, req.session_id, req.hostname, req.port)
    return {
        "connected": True,
        "user_id": req.user_id,
        "session_id": req.session_id,
        "hostname": req.hostname,
        "port": req.port,
        "persistent": True,
    }


@app.get("/ssh/status")
async def ssh_status(user_id: str):
    """Get status of all SSH sessions for a user."""
    if user_id not in ssh_sessions:
        return {"connected": False, "user_id": user_id, "sessions": []}
    
    user_sessions = ssh_sessions[user_id]
    sessions_info = []
    
    for session_id, session in user_sessions.items():
        client = session.get("client")
        active = False
        if client and hasattr(client, "get_transport"):
            transport = client.get_transport()
            active = transport is not None and transport.is_active()
        
        sessions_info.append({
            "session_id": session_id,
            "hostname": session.get("hostname"),
            "username": session.get("username"),
            "port": session.get("port"),
            "active": active,
            "connected_at": session.get("connected_at"),
        })
    
    return {
        "connected": len(sessions_info) > 0,
        "user_id": user_id,
        "sessions": sessions_info,
        "count": len(sessions_info),
    }


@app.post("/ssh/disconnect")
async def ssh_disconnect(user_id: str, session_id: str = "default"):
    """Disconnect a specific SSH session via ssh_manager.py."""
    if user_id not in ssh_sessions:
        raise HTTPException(status_code=404, detail=f"No SSH sessions for user '{user_id}'")
    
    user_sessions = ssh_sessions[user_id]
    if session_id not in user_sessions:
        raise HTTPException(status_code=404, detail=f"No SSH session '{session_id}' for user '{user_id}'")
    
    session = user_sessions[session_id]
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
    
    del user_sessions[session_id]
    if not user_sessions:  # Clean up empty user entry
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
    remote_cmd = f"ls -la {shlex.quote(path or '~')}"
    execute_cmd = {
        "command": "execute",
        "session_id": session_id,
        "cmd": remote_cmd,
        "timeout": 30
    }
    
    result = await run_blocking(send_to_ssh_manager, container_id, execute_cmd, 35)
    
    if not result.get("success"):
        error_msg = result.get("error", "Unknown error")
        raise HTTPException(status_code=500, detail=f"Failed to list remote directory: {error_msg}")
    
    if result.get("exit_code", 0) != 0:
        raise HTTPException(status_code=500, detail=f"Failed to list remote directory: {result.get('stderr', '')}")
    
    out = result.get("stdout", "")
    entries = []
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 9:
            continue
        name = " ".join(parts[8:])
        size = int(parts[4]) if parts[4].isdigit() else None
        entries.append({"name": name, "size": size, "mode": parts[0]})
    
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
async def api_gpu_info(user_id: str, session_id: str = "default"):
    """Get GPU information using nvidia-smi from remote SSH host via persistent paramiko connection in container."""
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
    
    # Execute nvidia-smi via ssh_manager.py using persistent connection
    remote_cmd = "nvidia-smi --query-gpu=index,name,temperature.gpu,utilization.gpu,utilization.memory,memory.total,memory.used,memory.free --format=csv,noheader,nounits"
    execute_cmd = {
        "command": "execute",
        "session_id": session_id,
        "cmd": remote_cmd,
        "timeout": 30
    }
    
    result = await run_blocking(send_to_ssh_manager, container_id, execute_cmd, 35)
    
    if not result.get("success"):
        error_msg = result.get("error", "Unknown error")
        raise HTTPException(status_code=500, detail=f"nvidia-smi failed: {error_msg}")
    
    if result.get("exit_code", 0) != 0:
        raise HTTPException(status_code=500, detail=f"nvidia-smi failed: {result.get('stderr', '')}")
    
    out = result.get("stdout", "")
    
    # Parse CSV output
    gpus = []
    for line in out.strip().split("\n"):
        if not line.strip():
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) >= 8:
            gpus.append({
                "index": int(parts[0]) if parts[0].isdigit() else parts[0],
                "name": parts[1],
                "temperature": int(parts[2]) if parts[2].isdigit() else None,
                "utilization_gpu": int(parts[3]) if parts[3].isdigit() else None,
                "utilization_memory": int(parts[4]) if parts[4].isdigit() else None,
                "memory_total": int(parts[5]) if parts[5].isdigit() else None,
                "memory_used": int(parts[6]) if parts[6].isdigit() else None,
                "memory_free": int(parts[7]) if parts[7].isdigit() else None,
            })
    
    return {"hostname": hostname, "gpus": gpus, "count": len(gpus)}


if __name__ == "__main__":
    print("Run with: uvicorn backend.app:app --host 0.0.0.0 --port 8000 --reload")
