"""
main.py with CORS support for mobile access

Minimal async FastAPI backend for a mobile GPU cluster monitoring app.
Enhanced with nohup job monitoring and mobile-optimized endpoints.
"""
# curl -s -X POST http://localhost:8000/vpn/connect \
#   -H "Content-Type: application/json" \
#   -d '{
#     "user_id": "test_1757085072", 
#     "vpn_url": "vpn.iisc.ac.in", 
#     "username": "debarpanb@iisc.ac.in", 
#     "password": "supsay@1998"
#   }' | python -m json.tool 2>/dev/null || curl -s -X POST http://localhost:8000/vpn/connect -H "Content-Type: application/json" -d '{"user_id": "test_1757085072", "vpn_url": "vpn.iisc.ac.in", "username": "debarpanb@iisc.ac.in", "password": "supsay@1998
# "}'

# curl -s -X POST http://localhost:8000/ssh/connect \
#   -H "Content-Type: application/json" \
#   -d '{
#     "user_id": "test_1757085072",
#     "hostname": "10.64.18.58", 
#     "username": "debarpanb",
#     "password": "ee@123"
#   }' | python -m json.tool 2>/dev/null

# curl -s http://localhost:8000/ssh/status?user_id=test_1757085072 | python -m json.tool

# curl -s http://localhost:8000/ssh/list-dirs?user_id=test_1757085072 | python -m json.tool

import asyncio
import json
import random
import subprocess
import os
import select
import shutil
import stat
import re
import shlex
import io
import socket
import time
from typing import Dict, Optional

# Configuration Notes:
# - Default target compute node is 'node1' - can be overridden via hop_target_host
# - SSH hop credentials are provided via the frontend connection form
# - All paths are dynamic based on SSH username from connection settings

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

# Helper function for improved SSH execution
async def execute_command_with_hop(client, command, target_node=None, hop_config=None, timeout=30):
    """
    Execute a command either directly on bastion or via SSH hop to target node.
    
    Args:
        client: paramiko.SSHClient connected to bastion
        command: command to execute
        target_node: target node name (e.g., "node1") or None for bastion
        hop_config: dict with hop configuration
        timeout: command timeout
    
    Returns:
        dict with success, stdout, stderr, and execution details
    """
    if not target_node or target_node == "bastion":
        # Execute directly on bastion host
        print(f"[SSH_EXEC] Executing on bastion host: {command[:100]}...")
        try:
            stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
            stdout_content = stdout.read().decode()
            stderr_content = stderr.read().decode()
            
            return {
                "success": True,
                "stdout": stdout_content,
                "stderr": stderr_content,
                "execution_location": "bastion",
                "command": command
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "execution_location": "bastion",
                "command": command
            }
    
    # Execute on target node via SSH hop
    print(f"[SSH_EXEC] Executing on target node '{target_node}': {command[:100]}...")
    
    # Get hop configuration
    if not hop_config:
        hop_config = {}
    
    hop_username = hop_config.get("target_username")  # default username
    
    # Validate hop configuration when target node is specified
    if not hop_username:
        return {
            "success": False,
            "error": f"No username configured for target node {target_node}",
            "details": "Please configure hop target username in the frontend form",
            "execution_location": target_node,
            "command": command
        }
    hop_password = hop_config.get("target_password")
    
    # Try different SSH approaches based on password availability
    ssh_attempts = []
    
    if not hop_password:
        # Try without password first (key-based or passwordless)
        ssh_cmd = f'ssh -o StrictHostKeyChecking=no -o PasswordAuthentication=no -o ConnectTimeout=10 {hop_username}@{target_node} "{command}"'
        ssh_attempts.append(("no_password", ssh_cmd))
        
        # If that fails, try with password prompt detection
        ssh_cmd_with_prompt = f'ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 {hop_username}@{target_node} "{command}"'
        ssh_attempts.append(("prompt_detection", ssh_cmd_with_prompt))
    else:
        # Use sshpass if password is provided
        escaped_password = hop_password.replace("'", "'\"'\"'")  # Escape single quotes
        ssh_cmd = f"sshpass -p '{escaped_password}' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 {hop_username}@{target_node} \"{command}\""
        ssh_attempts.append(("with_password", ssh_cmd))
    
    last_error = None
    
    for attempt_type, ssh_cmd in ssh_attempts:
        try:
            print(f"[SSH_EXEC] Attempting {attempt_type} SSH to {hop_username}@{target_node}")
            stdin, stdout, stderr = client.exec_command(ssh_cmd, timeout=timeout)
            
            stdout_content = stdout.read().decode()
            stderr_content = stderr.read().decode()
            
            # Check if password was requested in stderr
            if "password:" in stderr_content.lower() or "password for" in stderr_content.lower():
                print(f"[SSH_EXEC] Password requested for {hop_username}@{target_node}")
                if attempt_type == "no_password":
                    print(f"[SSH_EXEC] SSH to {target_node} requires password but none provided")
                    continue  # Try next attempt
                
            # Check exit status through stderr patterns
            ssh_failed = any(pattern in stderr_content.lower() for pattern in [
                "connection refused", "host unreachable", "permission denied", 
                "could not resolve hostname", "connection timed out"
            ])
            
            if ssh_failed and not stdout_content:
                last_error = f"SSH failed ({attempt_type}): {stderr_content}"
                continue
            
            return {
                "success": True,
                "stdout": stdout_content,
                "stderr": stderr_content,
                "execution_location": target_node,
                "ssh_method": attempt_type,
                "command": command,
                "ssh_command": ssh_cmd
            }
            
        except Exception as e:
            last_error = f"SSH attempt {attempt_type} failed: {str(e)}"
            print(f"[SSH_EXEC] {last_error}")
            continue
    
    return {
        "success": False,
        "error": last_error or "All SSH attempts failed",
        "execution_location": target_node,
        "command": command,
        "attempted_methods": [attempt[0] for attempt in ssh_attempts]
    }

from pydantic import BaseModel, Field
import paramiko
from paramiko.agent import AgentRequestHandler

# Optional: use psutil if available for more realistic host metrics
try:
    import psutil  # type: ignore
    HAS_PSUTIL = True
except Exception:
    HAS_PSUTIL = False

app = FastAPI(title="Vigilink GPU Cluster Monitor", version="2.0")

# Add CORS middleware for mobile access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory store for active connections keyed by user_id
connections: Dict[str, Dict[str, object]] = {}

# TUN device management for non-root VPN connections
import threading
import hashlib

# Track VPN connections by credential hash instead of just user_id
vpn_connections = {}  # credential_hash -> {"user_id": user, "tun_device": device, "process": proc}
allocated_tun_devices = {}  # device -> credential_hash
tun_lock = threading.Lock()

def get_vpn_credential_hash(vpn_url: str, username: str) -> str:
    """Generate a hash for VPN credentials to identify unique connections."""
    credential_string = f"{vpn_url}:{username}"
    return hashlib.md5(credential_string.encode()).hexdigest()[:16]

def get_or_allocate_tun_device(vpn_url: str, username: str, user_id: str):
    """Get existing or allocate new TUN device for VPN credentials."""
    with tun_lock:
        cred_hash = get_vpn_credential_hash(vpn_url, username)
        
        # Check if this VPN connection already exists
        if cred_hash in vpn_connections:
            existing = vpn_connections[cred_hash]
            print(f"[TUN] Reusing existing connection for {username}@{vpn_url}")
            print(f"[TUN] Device {existing['tun_device']} already allocated to {existing['user_id']}")
            return existing['tun_device'], True  # device, is_reused
        
        # Find an available TUN device
        for i in range(3):  # vpn0, vpn1, vpn2
            device_name = f"vpn{i}"
            if device_name not in allocated_tun_devices:
                # Allocate this device
                allocated_tun_devices[device_name] = cred_hash
                vpn_connections[cred_hash] = {
                    "user_id": user_id,
                    "tun_device": device_name,
                    "process": None  # Will be set when process starts
                }
                print(f"[TUN] Allocated new device {device_name} for {username}@{vpn_url}")
                return device_name, False  # device, is_reused
        
        return None, False  # No devices available

def update_vpn_process(vpn_url: str, username: str, process):
    """Update the process for an existing VPN connection."""
    with tun_lock:
        cred_hash = get_vpn_credential_hash(vpn_url, username)
        if cred_hash in vpn_connections:
            vpn_connections[cred_hash]["process"] = process

def release_vpn_connection(vpn_url: str, username: str):
    """Release VPN connection and TUN device."""
    with tun_lock:
        cred_hash = get_vpn_credential_hash(vpn_url, username)
        if cred_hash in vpn_connections:
            connection = vpn_connections[cred_hash]
            device = connection["tun_device"]
            
            # Terminate process if still running
            if connection["process"]:
                try:
                    connection["process"].terminate()
                    print(f"[TUN] Terminated VPN process for {device}")
                except Exception as e:
                    print(f"[TUN] Error terminating process: {e}")
            
            # Clean up device allocation
            if device in allocated_tun_devices:
                del allocated_tun_devices[device]
            del vpn_connections[cred_hash]
            
            print(f"[TUN] Released device {device} and cleaned up connection {username}@{vpn_url}")
            return device
        return None

def get_active_vpn_connections():
    """Get list of active VPN connections for debugging."""
    with tun_lock:
        active = []
        for cred_hash, conn in vpn_connections.items():
            # Check if process is still running
            process_running = False
            if conn["process"]:
                try:
                    process_running = conn["process"].poll() is None
                except:
                    pass
            
            active.append({
                "credential_hash": cred_hash,
                "user_id": conn["user_id"],
                "tun_device": conn["tun_device"],
                "process_running": process_running
            })
        return active

def cleanup_dead_connections():
    """Clean up connections where the process has died."""
    with tun_lock:
        dead_connections = []
        for cred_hash, conn in vpn_connections.items():
            if conn["process"] and conn["process"].poll() is not None:
                dead_connections.append(cred_hash)
        
        for cred_hash in dead_connections:
            conn = vpn_connections[cred_hash]
            device = conn["tun_device"]
            if device in allocated_tun_devices:
                del allocated_tun_devices[device]
            del vpn_connections[cred_hash]
            print(f"[TUN] Cleaned up dead connection on device {device}")

def release_tun_device(user_id: str):
    """Legacy function for compatibility - now finds by user_id and releases."""
    with tun_lock:
        # Find connection by user_id
        for cred_hash, conn in list(vpn_connections.items()):
            if conn["user_id"] == user_id:
                device = conn["tun_device"]
                if conn["process"]:
                    try:
                        conn["process"].terminate()
                    except Exception:
                        pass
                if device in allocated_tun_devices:
                    del allocated_tun_devices[device]
                del vpn_connections[cred_hash]
                print(f"[TUN] Released device {device} for user {user_id}")
                return device
        return None

"""
main.py

Minimal async FastAPI backend for a mobile GPU cluster monitoring app.
Single-file implementation with:
 - VPN and SSH connection management
 - REST health endpoints
 - Focused terminal run APIs (bastion and GPU hop)

Notes:
 - paramiko is used for SSH; blocking calls are run in an executor to keep async semantics.
 - openconnect and nvidia-smi/top are mocked/simulated so this runs without a real VPN or GPU cluster.
 - No external database; connections are stored in-memory.
"""

import asyncio
import json
import random
import subprocess
import os
import select
import shutil
import stat
import re
import shlex
import io
import socket
import time
from typing import Dict, Optional

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field
import paramiko
from paramiko.agent import AgentRequestHandler

# Optional: use psutil if available for more realistic host metrics
try:
    import psutil  # type: ignore
    HAS_PSUTIL = True
except Exception:
    HAS_PSUTIL = False


# In-memory store for active connections keyed by user_id
# Each entry: {"vpn_proc": subprocess.Popen, "ssh_client": paramiko.SSHClient, "hop_channel": paramiko.Channel}


# -----------------------
# Pydantic models
# -----------------------
class ConnectionData(BaseModel):
    user_id: str = Field(..., description="Unique user identifier for this connection session")
    vpn_url: Optional[str] = Field(None, description="VPN gateway URL")
    vpn_user: Optional[str] = Field(None, description="VPN username (optional)")
    vpn_creds: Optional[str] = Field(None, description="VPN password/creds (optional)")
    real_vpn: bool = Field(False, description="If true, attempt to run openconnect (may require privileges)")
    ssh_ip: str = Field(..., description="SSH target IP address")
    ssh_user: str = Field(..., description="SSH username")
    ssh_creds: str = Field(..., description="SSH password (mocked or real)")
    real_ssh: bool = Field(False, description="If true, attempt a real SSH connect using paramiko")


# -----------------------
# Helper utilities
# -----------------------
async def run_blocking(func, *args, **kwargs):
    """Run a blocking function in the default ThreadPoolExecutor."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, lambda: func(*args, **kwargs))

def read_stream_nonblocking(proc: subprocess.Popen, timeout: float = 0.2) -> Dict[str, str]:
    """Try to read any available stdout/stderr from a subprocess without blocking too long."""
    out = b""
    err = b""
    fds = []
    if proc.stdout:
        fds.append(proc.stdout)
    if proc.stderr:
        fds.append(proc.stderr)

    rlist = []
    try:
        rlist, _, _ = select.select([f.fileno() for f in fds], [], [], timeout)
    except Exception:
        rlist = []

    for fdno in rlist:
        try:
            if proc.stdout and proc.stdout.fileno() == fdno:
                out += os.read(fdno, 4096)
        except Exception:
            pass
        try:
            if proc.stderr and proc.stderr.fileno() == fdno:
                err += os.read(fdno, 4096)
        except Exception:
            pass

    return {"stdout": out.decode("utf-8", errors="replace"), "stderr": err.decode("utf-8", errors="replace")}


def start_vpn_process(
    vpn_url: Optional[str],
    vpn_user: Optional[str],
    vpn_pass: Optional[str],
    real: bool = True,
    protocol: str = "anyconnect",
    sudo: bool = False,
    sudo_password: Optional[str] = None,
    user_id: str = "default",
) -> subprocess.Popen:
    """
    Start openconnect process using smart TUN device allocation based on credentials.
    """
    # Clean up any dead connections first
    cleanup_dead_connections()
    
    # Get or allocate TUN device based on VPN credentials
    tun_device, is_reused = get_or_allocate_tun_device(vpn_url or "", vpn_user or "", user_id)
    if not tun_device:
        raise Exception("No available TUN devices. All vpn0-vpn2 devices are in use.")
    
    if is_reused:
        print(f"[start_vpn_process] Reusing existing device {tun_device} for {vpn_user}@{vpn_url}")
        # If reusing, check if the existing process is still running
        cred_hash = get_vpn_credential_hash(vpn_url or "", vpn_user or "")
        if cred_hash in vpn_connections:
            existing_proc = vpn_connections[cred_hash]["process"]
            if existing_proc and existing_proc.poll() is None:
                print(f"[start_vpn_process] Existing VPN process still active (PID: {existing_proc.pid})")
                return existing_proc
            else:
                print(f"[start_vpn_process] Existing process died, starting new connection")
    else:
        print(f"[start_vpn_process] Allocated new device {tun_device} for {vpn_user}@{vpn_url}")
    
    # Build openconnect args with allocated TUN device
    args = [
        "openconnect", 
        vpn_url or "", 
        "--protocol", protocol, 
        "--passwd-on-stdin", 
        "--timestamp", 
        "--verbose",
        "--interface", tun_device,  # Use allocated TUN device
        "--script", "sudo -E /etc/vpnc/vpnc-script"  # Use sudo only for network config script
    ]
    
    if vpn_user:
        args.extend(["--user", vpn_user])

    print(f"[start_vpn_process] Command: {args}")
    
    # Start process without sudo - TUN device is pre-configured
    proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    # Update the process in our tracking
    update_vpn_process(vpn_url or "", vpn_user or "", proc)
    
    if proc.stdin:
        try:
            # Send password to openconnect
            if vpn_pass:
                proc.stdin.write(f"{vpn_pass}\n".encode())
                proc.stdin.flush()
        except Exception as e:
            print(f"[start_vpn_process] Failed to send password: {e}")
            try:
                proc.terminate()
            except Exception:
                pass
            # Release the device if process failed
            release_vpn_connection(vpn_url or "", vpn_user or "")
            raise

    return proc


def build_paramiko_client_sync(
    ssh_ip: str,
    ssh_user: str,
    password: Optional[str] = None,
    timeout: int = 10,
    port: int = 22,
    allow_agent: bool = True,
    look_for_keys: bool = True,
    pkey_path: Optional[str] = None,
    pkey_data: Optional[str] = None,
    pkey_type: Optional[str] = None,
) -> paramiko.SSHClient:
    """Blocking creation + connection of a paramiko.SSHClient supporting password, key files, and agent."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    pkey_obj = None
    if pkey_data:
        buf = io.StringIO(pkey_data)
        try:
            if (pkey_type or "").lower() == "ed25519":
                pkey_obj = paramiko.Ed25519Key.from_private_key(buf)
            elif (pkey_type or "").lower() == "ecdsa":
                pkey_obj = paramiko.ECDSAKey.from_private_key(buf)
            else:
                pkey_obj = paramiko.RSAKey.from_private_key(buf)
        except Exception:
            buf.close()
            raise
    elif pkey_path:
        try:
            pkey_obj = paramiko.Ed25519Key.from_private_key_file(pkey_path)
        except Exception:
            try:
                pkey_obj = paramiko.ECDSAKey.from_private_key_file(pkey_path)
            except Exception:
                pkey_obj = paramiko.RSAKey.from_private_key_file(pkey_path)

    try:
        client.connect(
            hostname=ssh_ip,
            username=ssh_user,
            password=password,
            timeout=timeout,
            port=port,
            allow_agent=allow_agent,
            look_for_keys=look_for_keys,
            pkey=pkey_obj,
        )
    except Exception as exc:
        try:
            client.close()
        except Exception:
            pass
        raise exc
    return client


# -----------------------
# Helpers: run remote command via Paramiko and read all output
# -----------------------
def _exec_and_read_all_sync(client: paramiko.SSHClient, command: str, timeout: int = 15):
    stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    rc = stdout.channel.recv_exit_status()
    return out, err, rc


# Execute a single command on an existing interactive hop channel and capture output + rc
def _exec_on_hop_channel_sync(chan: paramiko.Channel, command: str, timeout: int = 30):
    if chan.closed:
        return "", "channel closed", 1
    # Append sentinel to retrieve exit code reliably
    sentinel = "__VIGI_RC__"
    # Run within a clean non-interactive bash to avoid shell aliases/prompts interfering
    import shlex as _shlex
    wrapped = f"{command}; rc=$?; printf '\n{sentinel}%d\n' \"$rc\""
    full = f"bash -lc {_shlex.quote(wrapped)}\r\n"
    try:
        chan.send(full)
    except Exception as e:
        return "", f"send failed: {e}", 1
    out_buf = ""
    err_buf = ""
    import time
    import re as _re
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            while chan.recv_ready():
                out_buf += chan.recv(4096).decode("utf-8", errors="replace")
        except Exception:
            pass
        try:
            while chan.recv_stderr_ready():
                err_buf += chan.recv_stderr(4096).decode("utf-8", errors="replace")
        except Exception:
            pass
        # Regex search for sentinel anywhere in buffer
        m = _re.search(rf"{sentinel}(\d+)", out_buf)
        if m:
            try:
                rc = int(m.group(1))
            except Exception:
                rc = 1
            clean = _re.sub(rf"\n?{sentinel}\d+\n?", "", out_buf)
            return clean, err_buf, rc
        time.sleep(0.05)
    return out_buf, err_buf or "timeout waiting for sentinel", 1

async def ssh_exec_read_all(client: paramiko.SSHClient, command: str, timeout: int = 15):
    return await run_blocking(_exec_and_read_all_sync, client, command, timeout)


# Execute one nested-SSH command with PTY and optional agent forwarding, and read all output
def _exec_hop_once_sync(client: paramiko.SSHClient, command: str, timeout: int = 15, forward_agent: bool = True):
    # Open a PTY-backed exec channel so remote ssh -t behaves properly
    stdin, stdout, stderr = client.exec_command(command, get_pty=True, timeout=timeout)
    chan: paramiko.Channel = stdout.channel
    if forward_agent:
        try:
            AgentRequestHandler(chan)
        except Exception:
            pass
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    rc = stdout.channel.recv_exit_status()
    return out, err, rc

# # -----------------------
# # POST /connect endpoint
# # -----------------------
# @app.post("/connect")
# async def connect(data: ConnectionData):
#     """Simulate connecting to VPN (mock) and establish SSH client via paramiko.
#     Stores client + process in the in-memory `connections` dict under data.user_id.
#     """
#     user_id = data.user_id
#     if not user_id:
#         raise HTTPException(status_code=400, detail="user_id is required")

#     # Clean up previous connection if exists
#     prev = connections.get(user_id)
#     if prev:
#         sshc = prev.get("ssh_client")
#         if isinstance(sshc, paramiko.SSHClient):
#             try:
#                 await run_blocking(sshc.close)
#             except Exception:
#                 pass
#         vpnp = prev.get("vpn_proc")
#         if isinstance(vpnp, subprocess.Popen):
#             try:
#                 vpnp.terminate()
#             except Exception:
#                 pass
#         connections.pop(user_id, None)

#     # Start VPN process - mocked or real
#     try:
#         vpn_proc = await run_blocking(start_vpn_process, data.vpn_url, data.vpn_user, data.vpn_creds, data.real_vpn)
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=f"Failed to start VPN process: {e}")

#     # Capture any immediate output from the VPN process
#     try:
#         vpn_io = await run_blocking(read_stream_nonblocking, vpn_proc, 0.2)
#     except Exception:
#         vpn_io = {"stdout": "", "stderr": ""}

#     # Establish SSH client using paramiko in executor if real_ssh requested
#     ssh_client = None
#     ssh_msg = None
#     if data.real_ssh:
#         try:
#             ssh_client = await run_blocking(build_paramiko_client_sync, data.ssh_ip, data.ssh_user, data.ssh_creds)
#             ssh_msg = "ssh_connected"
#         except Exception as e:
#             try:
#                 vpn_proc.terminate()
#             except Exception:
#                 pass
#             raise HTTPException(status_code=502, detail=f"Failed to establish SSH connection: {e}")
#     else:
#         # Provide an unconnected SSHClient instance for API compatibility
#         ssh_client = paramiko.SSHClient()
#         ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
#         ssh_msg = "ssh_client_not_connected_mock"

#     connections[user_id] = {"vpn_proc": vpn_proc, "ssh_client": ssh_client, "ssh_channel": None}

#     return {
#         "status": "connected",
#         "user_id": user_id,
#         "vpn": {"real": bool(data.real_vpn), "stdout": vpn_io.get("stdout"), "stderr": vpn_io.get("stderr")},
#         "ssh": {"real": bool(data.real_ssh), "message": ssh_msg},
#     }


# -----------------------
# Simple REST APIs for VPN and SSH (mobile-friendly)
# -----------------------
class VPNConnectRequest(BaseModel):
    user_id: str
    vpn_url: str
    username: Optional[str] = None
    password: Optional[str] = None
    protocol: str = Field("anyconnect", description="openconnect protocol, e.g. anyconnect, gp")
    sudo: bool = Field(False, description="Use sudo -n to run openconnect (may be required)")
    sudo_password: Optional[str] = Field(None, description="If provided, use sudo -S and feed this password via stdin")
    # Optional: wait until a host:port becomes reachable over VPN before returning
    wait_host: Optional[str] = Field(None, description="Host to probe for readiness, e.g., bastion IP")
    wait_port: int = Field(22, description="Port to probe on wait_host")
    wait_timeout: int = Field(60, description="Seconds to wait for reachability before giving up")


@app.post("/vpn/connect")
async def vpn_connect(req: VPNConnectRequest):
    user_id = req.user_id
    # Simple rate limiting - track attempts per user
    import time
    if not hasattr(vpn_connect, 'last_attempts'):
        vpn_connect.last_attempts = {}
    
    current_time = time.time()
    last_attempt = vpn_connect.last_attempts.get(user_id, 0)
    
    # Prevent attempts more frequent than every 10 seconds
    if current_time - last_attempt < 10:
        remaining = int(10 - (current_time - last_attempt))
        print(f"[VPN] Rate limiting {user_id}: {remaining}s remaining")
        raise HTTPException(status_code=429, detail=f"Please wait {remaining} seconds before trying again")
    
    vpn_connect.last_attempts[user_id] = current_time

    if not user_id:
        raise HTTPException(status_code=400, detail="user_id is required")

    # Ensure user slot exists
    conn = connections.get(user_id) or {}

    # If an existing VPN proc exists, terminate it first
    old = conn.get("vpn_proc")
    if isinstance(old, subprocess.Popen):
        try:
            old.terminate()
        except Exception:
            pass
        
    # Find and release VPN connection by user_id  
    for cred_hash, vpn_conn in list(vpn_connections.items()):
        if vpn_conn["user_id"] == user_id:
            # Extract credentials to properly release
            # This is a bit hacky but necessary for cleanup
            conn_info = None
            for stored_conn in connections.values():
                vpn_proc = stored_conn.get("vpn_proc")
                if vpn_proc == old:
                    conn_info = stored_conn
                    break
            
            # Try to release by finding matching process
            release_tun_device(user_id)
            break

    # Validate openconnect availability
    if shutil.which("openconnect") is None:
        raise HTTPException(status_code=400, detail="'openconnect' not found in PATH. Please install it or adjust PATH.")

    try:
        proc = await run_blocking(
            start_vpn_process,
            req.vpn_url,
            req.username,
            req.password,
            True,
            req.protocol,
            False,  # Never use sudo
            None,   # No sudo password needed
            user_id,  # Pass user_id for TUN allocation
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start VPN: {e}")

    # Tail output briefly to surface immediate failures/success
    out_accum = ""
    err_accum = ""
    try:
        for _ in range(20):  # ~5s
            await asyncio.sleep(0.25)
            io = await run_blocking(read_stream_nonblocking, proc, 0.1)
            out_accum += io.get("stdout", "")
            err_accum += io.get("stderr", "")
            rc_now = proc.poll()
            if rc_now is not None:
                break
    except Exception:
        pass

    # If the process already exited, report explicit error
    rc = proc.poll()
    if rc is not None and rc != 0:
        try:
            proc.terminate()
        except Exception:
            pass
        detail = {
            "message": "openconnect failed to start",
            "returncode": rc,
            "stdout": out_accum,
            "stderr": err_accum,
        }
        # Also print to server logs for terminal visibility
        print(f"[vpn/connect] Error: {detail}")
        raise HTTPException(status_code=502, detail=detail)

    # Non-root warning (some setups require root); only on POSIX with no sudo
    try:
        if not req.sudo and hasattr(os, "geteuid") and os.geteuid() != 0:
            if "TUNSETIFF" in err_accum or "permission" in err_accum.lower():
                print("[vpn/connect] Permission issue likely: try enabling sudo option.")
    except Exception:
        pass

    conn["vpn_proc"] = proc
    connections[user_id] = conn
    # Optionally wait for reachability (actual tunnel usability)
    reachable = None
    reached_in = None
    if req.wait_host:
        start_ts = time.time()
        deadline = start_ts + max(1, req.wait_timeout)
        while time.time() < deadline:
            # If process died, stop waiting
            if proc.poll() is not None:
                break
            try:
                with socket.create_connection((req.wait_host, req.wait_port), timeout=3):
                    reachable = True
                    reached_in = round(time.time() - start_ts, 2)
                    break
            except Exception:
                reachable = False
            await asyncio.sleep(1.0)

    print(f"request: {req}")
    resp = {
        "status": "started",
        "user_id": user_id,
        "pid": proc.pid,
        "running": True,
        "stdout": out_accum,
        "stderr": err_accum,
        "reachable": reachable,
        "reached_in_seconds": reached_in,
        "notes": "Process started; logs show initial handshake. /vpn/status reports reachability as well.",
    }
    print(f"response: {resp}")

    return {
        "status": "started",
        "user_id": user_id,
        "pid": proc.pid,
        "running": True,
        "stdout": out_accum,
        "stderr": err_accum,
        "reachable": reachable,
        "reached_in_seconds": reached_in,
        "notes": "Process started; logs show initial handshake. /vpn/status reports reachability as well.",
    }


@app.get("/vpn/status")
async def vpn_status(user_id: str, host: Optional[str] = None, port: int = 22, probe_timeout: int = 3):
    print(f"[VPN_STATUS] Request: user_id={user_id}, host={host}, port={port}")
    conn = connections.get(user_id)
    if not conn:
        print(f"[VPN_STATUS] No session found for user {user_id}")
        print(f"[VPN_STATUS] Available sessions: {list(connections.keys())}")
        return {"connected": False, "message": "no session"}
    proc = conn.get("vpn_proc")
    if not isinstance(proc, subprocess.Popen):
        return {"connected": False, "message": "vpn not started"}
    running = proc.poll() is None
    result = {"connected": running}
    if running and host:
        try:
            with socket.create_connection((host, port), timeout=max(1, probe_timeout)):
                result["reachable"] = True
        except Exception:
            result["reachable"] = False
        result["probe"] = {"host": host, "port": port}

    print(f"VPN status for {user_id}: {result}")
    return result


@app.get("/vpn/logs")
async def vpn_logs(user_id: str):
    """Fetch any available stdout/stderr from the running openconnect process."""
    conn = connections.get(user_id)
    if not conn:
        raise HTTPException(status_code=404, detail="no session")
    proc = conn.get("vpn_proc")
    if not isinstance(proc, subprocess.Popen):
        raise HTTPException(status_code=400, detail="vpn not started")

    try:
        io = await run_blocking(read_stream_nonblocking, proc, 0.2)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"failed to read logs: {e}")

    rc = proc.poll()
    return {
        "running": rc is None,
        "returncode": rc,
        "stdout": io.get("stdout", ""),
        "stderr": io.get("stderr", ""),
    }


@app.post("/vpn/disconnect")
async def vpn_disconnect(user_id: str):
    conn = connections.get(user_id)
    if not conn:
        return {"status": "ok", "message": "no session"}
    proc = conn.get("vpn_proc")
    if isinstance(proc, subprocess.Popen):
        try:
            proc.terminate()
        except Exception:
            pass
        conn["vpn_proc"] = None
    connections[user_id] = conn
    return {"status": "stopped"}


class SSHConnectRequest(BaseModel):
    user_id: str
    hostname: str
    username: str
    # One of password or key-based auth (via pkey_*) may be provided. Agent and look_for_keys are enabled by default.
    password: Optional[str] = None
    port: int = 22
    timeout: int = 10
    allow_agent: bool = True
    look_for_keys: bool = True
    pkey_path: Optional[str] = Field(None, description="Path to private key file on server side")
    pkey_data: Optional[str] = Field(None, description="PEM private key contents (do not log)")
    pkey_type: Optional[str] = Field(None, description="rsa|ed25519|ecdsa (optional; auto-detect if omitted)")
    
    # SSH hop configuration for accessing compute nodes
    hop_target_host: Optional[str] = Field(None, description="Target host to hop to (e.g., 'node1')")
    hop_target_username: Optional[str] = Field(None, description="Username for the target host")
    hop_target_password: Optional[str] = Field(None, description="Password for the target host")


@app.post("/ssh/connect")
async def ssh_connect(req: SSHConnectRequest):
    user_id = req.user_id
    if not user_id:
        raise HTTPException(status_code=400, detail="user_id is required")

    conn = connections.get(user_id) or {}

    # Close any existing client first
    oldc = conn.get("ssh_client")
    if isinstance(oldc, paramiko.SSHClient):
        try:
            await run_blocking(oldc.close)
        except Exception:
            pass

    try:
        client = await run_blocking(
            build_paramiko_client_sync,
            req.hostname,
            req.username,
            req.password,
            req.timeout,
            req.port,
            req.allow_agent,
            req.look_for_keys,
            req.pkey_path,
            req.pkey_data,
            req.pkey_type,
        )
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"SSH connect failed: {e}")

    conn["ssh_client"] = client
    
    # Store SSH hop configuration if provided
    if req.hop_target_host and req.hop_target_username and req.hop_target_password:
        conn["ssh_hop_config"] = {
            "target_host": req.hop_target_host,
            "target_username": req.hop_target_username,  
            "target_password": req.hop_target_password
        }
        print(f"[SSH_CONNECT] Stored hop config for {user_id}: {req.hop_target_username}@{req.hop_target_host}")
    
    connections[user_id] = conn
    return {"connected": True, "user_id": user_id}


@app.get("/ssh/status")
async def ssh_status(user_id: str):
    conn = connections.get(user_id)
    if not conn:
        return {"connected": False, "message": "no session"}
    client = conn.get("ssh_client")
    if not isinstance(client, paramiko.SSHClient):
        return {"connected": False}
    try:
        transport = client.get_transport()
        alive = bool(transport and transport.is_active())
    except Exception:
        alive = False
    return {"connected": alive}


@app.get("/ssh/list-dirs")
async def ssh_list_dirs(user_id: str, path: Optional[str] = None):
    """List directories and files on the remote SSH host for the given user_id.
    If path is not provided, uses the user's default directory (sftp.normalize('.'))."""
    conn = connections.get(user_id)
    if not conn:
        raise HTTPException(status_code=404, detail="no session for user_id")
    client = conn.get("ssh_client")
    if not isinstance(client, paramiko.SSHClient):
        raise HTTPException(status_code=400, detail="ssh not connected")
    try:
        transport = client.get_transport()
        if not (transport and transport.is_active()):
            raise HTTPException(status_code=400, detail="ssh transport not active")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"ssh transport error: {e}")

    # Open SFTP (blocking) in executor
    try:
        sftp = await run_blocking(client.open_sftp)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"failed to open sftp: {e}")

    try:
        # Resolve base path
        def _normalize(p):
            try:
                return sftp.normalize(p)
            except Exception:
                return p

        base = path or "/home"  # Default to /home if no path provided

        # Handle tilde expansion and relative paths
        if base.startswith('~'):
            base = base.replace('~', '/home')
        elif not base.startswith('/'):
            base = '/' + base
        norm = await run_blocking(_normalize, base)

        # List attributes and categorize directories vs files
        def _list_entries(p):
            directories = []
            files = []
            print(f"[SSH_LIST_DIRS] Listing directory: {p}")
            for attr in sftp.listdir_attr(p):
                try:
                    entry_data = {
                        "name": attr.filename,
                        "size": attr.st_size or 0,
                        "modified": attr.st_mtime or 0,
                        "permissions": oct(attr.st_mode)[-3:] if attr.st_mode else "---"
                    }
                    
                    if stat.S_ISDIR(attr.st_mode):
                        directories.append(entry_data)
                    else:
                        files.append(entry_data)
                except Exception as e:
                    print(f"Error processing {attr.filename}: {e}")
                    continue
            return directories, files

        directories, files = await run_blocking(_list_entries, norm)
        total_items = len(directories) + len(files)
        
        return {
            "path": norm,
            "directories": directories,
            "files": files,
            "total_items": total_items
        }
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"path not found: {path}")
    except PermissionError:
        raise HTTPException(status_code=403, detail=f"permission denied: {path}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"sftp error: {e}")
    finally:
        try:
            await run_blocking(sftp.close)
        except Exception:
            pass


@app.post("/ssh/disconnect")
async def ssh_disconnect(user_id: str):
    conn = connections.get(user_id)
    if not conn:
        return {"status": "ok", "message": "no session"}
    client = conn.get("ssh_client")
    if isinstance(client, paramiko.SSHClient):
        try:
            await run_blocking(client.close)
        except Exception:
            pass
        conn["ssh_client"] = None
    connections[user_id] = conn
    return {"status": "disconnected"}


# -----------------------
# REST: Remote Filesystem Utilities
# -----------------------
class FSFindRequest(BaseModel):
    user_id: str
    filename: str  # can be exact name or a glob pattern like "*.log"
    start_path: Optional[str] = "/"  # default search from root
    timeout: int = 60




@app.post("/ssh/cleanup-hop")
async def cleanup_hop_session(user_id: str):
    """Clean up the persistent hop session for a user"""
    conn = connections.get(user_id)
    if not conn:
        return {"message": "No session found"}
    
    hop_channel = conn.get("hop_channel")
    if hop_channel:
        try:
            hop_channel.close()
            print(f"[CLEANUP] Closed hop session for user {user_id}")
        except Exception as e:
            print(f"[CLEANUP] Error closing hop session: {e}")
        finally:
            del conn["hop_channel"]
    
    return {"message": "Hop session cleaned up"}
@app.post("/api/fs/find")
async def api_fs_find(req: FSFindRequest):
    """Find files by name/pattern on the remote server using 'find'.
    Returns absolute paths. Suppresses permission errors.
    """
    conn = connections.get(req.user_id)
    if not conn:
        raise HTTPException(status_code=404, detail="no session for user_id")
    client = conn.get("ssh_client")
    if not isinstance(client, paramiko.SSHClient):
        raise HTTPException(status_code=400, detail="ssh not connected")
    transport = client.get_transport()
    if not (transport and transport.is_active()):
        raise HTTPException(status_code=400, detail="ssh transport not active")

    # Build safe find command
    sp = req.start_path or "/"
    pattern = req.filename
    cmd = f"find {shlex.quote(sp)} -type f -name {shlex.quote(pattern)} 2>/dev/null"
    out, err, rc = await ssh_exec_read_all(client, cmd, timeout=max(1, req.timeout))
    if rc != 0:
        # Even if rc!=0 due to some errors, we still try to parse output
        pass
    paths = [line.strip() for line in out.splitlines() if line.strip()]
    return {"paths": paths}


@app.get("/api/fs/list")
async def api_fs_list(user_id: str, path: Optional[str] = None):
    """List files and directories at 'path' via SFTP, including basic metadata."""
    conn = connections.get(user_id)
    if not conn:
        raise HTTPException(status_code=404, detail="no session for user_id")
    client = conn.get("ssh_client")
    if not isinstance(client, paramiko.SSHClient):
        raise HTTPException(status_code=400, detail="ssh not connected")
    transport = client.get_transport()
    if not (transport and transport.is_active()):
        raise HTTPException(status_code=400, detail="ssh transport not active")

    try:
        sftp = await run_blocking(client.open_sftp)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"failed to open sftp: {e}")

    try:
        base = path or "."
        def _normalize(p):
            try:
                return sftp.normalize(p)
            except Exception:
                return p
        norm = await run_blocking(_normalize, base)

        def _list(p):
            items = []
            for attr in sftp.listdir_attr(p):
                mode = attr.st_mode
                items.append({
                    "name": attr.filename,
                    "is_dir": bool(stat.S_ISDIR(mode)),
                    "size": getattr(attr, 'st_size', None),
                    "mode": mode,
                    "mtime": getattr(attr, 'st_mtime', None),
                })
            return items
        items = await run_blocking(_list, norm)
        return {"path": norm, "items": items}
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"path not found: {path}")
    except PermissionError:
        raise HTTPException(status_code=403, detail=f"permission denied: {path}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"sftp error: {e}")
    finally:
        try:
            await run_blocking(sftp.close)
        except Exception:
            pass


@app.get("/api/fs/read")
async def api_fs_read(user_id: str, path: str, offset: int = 0, length: int = 65536):
    """Read a slice of a remote file via SFTP. Offset and length are in bytes."""
    if not path:
        raise HTTPException(status_code=400, detail="path is required")
    conn = connections.get(user_id)
    if not conn:
        raise HTTPException(status_code=404, detail="no session for user_id")
    client = conn.get("ssh_client")
    if not isinstance(client, paramiko.SSHClient):
        raise HTTPException(status_code=400, detail="ssh not connected")
    transport = client.get_transport()
    if not (transport and transport.is_active()):
        raise HTTPException(status_code=400, detail="ssh transport not active")

    try:
        sftp = await run_blocking(client.open_sftp)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"failed to open sftp: {e}")

    try:
        def _read_slice(p: str, off: int, n: int):
            with sftp.open(p, 'r') as f:
                if off > 0:
                    f.seek(off)
                data = f.read(n)
                return data.decode('utf-8', errors='replace')
        text = await run_blocking(_read_slice, path, max(0, offset), max(1, length))
        return {"path": path, "offset": max(0, offset), "length": len(text.encode('utf-8', errors='replace')), "content": text}
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"file not found: {path}")
    except PermissionError:
        raise HTTPException(status_code=403, detail=f"permission denied: {path}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"sftp error: {e}")
    finally:
        try:
            await run_blocking(sftp.close)
        except Exception:
            pass
# -----------------------
# REST: Specific Terminal Run APIs
# -----------------------
class BastionRunRequest(BaseModel):
    user_id: str
    command: str
    timeout: int = 30


@app.post("/api/terminal/bastion/run")
async def api_terminal_bastion_run(req: BastionRunRequest):
    """Execute a command on the bastion (initial SSH host)."""
    conn = connections.get(req.user_id)
    if not conn:
        raise HTTPException(status_code=404, detail="no session for user_id")
    client = conn.get("ssh_client")
    if not isinstance(client, paramiko.SSHClient):
        raise HTTPException(status_code=400, detail="ssh not connected")
    transport = client.get_transport()
    if not (transport and transport.is_active()):
        raise HTTPException(status_code=400, detail="ssh transport not active")

    out, err, rc = await ssh_exec_read_all(client, req.command, timeout=max(1, req.timeout))
    return {"stdout": out, "stderr": err, "exit_code": rc}


class GPUHopRunRequest(BaseModel):
    user_id: str
    command: str
    target_node: Optional[str] = None
    forward_agent: bool = True
    extra_args: Optional[str] = None
    password: Optional[str] = None
    timeout: int = 30


@app.post("/api/terminal/gpu/run")
async def api_terminal_gpu_run(req: GPUHopRunRequest):
    """Execute a command on the GPU master (node1 by default) via a hop."""
    conn = connections.get(req.user_id)
    if not conn:
        raise HTTPException(status_code=404, detail="no session for user_id")
    client = conn.get("ssh_client")
    if not isinstance(client, paramiko.SSHClient):
        raise HTTPException(status_code=400, detail="ssh not connected")
    transport = client.get_transport()
    if not (transport and transport.is_active()):
        raise HTTPException(status_code=400, detail="ssh transport not active")

    if not req.target_node:
        # If target_node is empty, run on bastion
        out, err, rc = await ssh_exec_read_all(client, req.command, timeout=max(1, req.timeout))
        return {"stdout": out, "stderr": err, "exit_code": rc}

    base = f"ssh -t {req.target_node}"
    if req.forward_agent:
        base += " -A"

    if req.password:
        # Interactive hop allowing password; do not force BatchMode
        if req.extra_args:
            base = f"{base} {req.extra_args}"
        cmd = f"{base} {shlex.quote(req.command)}"
        chan, _stdin, _stdout, _stderr, out, err, rc = await run_blocking(
            _jump_to_node_sync, client, cmd, req.password, max(1, req.timeout), req.forward_agent
        )
        try:
            chan.close()
        except Exception:
            pass
    else:
        # One-shot hop; fail fast if auth requires password
        defaults = "-o BatchMode=yes -o StrictHostKeyChecking=no"
        base = f"{base} {defaults}" if not req.extra_args else f"{base} {defaults} {req.extra_args}"
        cmd = f"{base} {shlex.quote(req.command)}"
        out, err, rc = await run_blocking(_exec_hop_once_sync, client, cmd, max(1, req.timeout), req.forward_agent)

    return {"stdout": out, "stderr": err, "exit_code": rc}


# -----------------------
# REST: Health endpoints for dashboard
# -----------------------
@app.get("/api/health/system")
async def api_health_system(user_id: str):
    """Return CPU and memory percent from the remote host via SSH."""
    conn = connections.get(user_id)
    if not conn:
        raise HTTPException(status_code=404, detail="no session for user_id")
    client = conn.get("ssh_client")
    if not isinstance(client, paramiko.SSHClient):
        raise HTTPException(status_code=400, detail="ssh not connected")
    transport = client.get_transport()
    if not (transport and transport.is_active()):
        raise HTTPException(status_code=400, detail="ssh transport not active")

    # Use top to gather CPU and Mem quickly. Force C locale for consistent parsing.
    cmd = 'LANG=C top -b -n 1 | head -n 10'
    out, err, rc = await ssh_exec_read_all(client, cmd, timeout=10)
    if rc != 0:
        raise HTTPException(status_code=502, detail={"message": "top failed", "stderr": err})

    cpu_percent = None
    mem_percent = None
    # Parse lines like: "%Cpu(s):  5.5 us,  2.3 sy,  0.0 ni, 90.9 id, ..."
    cpu_match = re.search(r"%?Cpu\(s\):\s*([0-9]+\.?[0-9]*)\s*us,\s*([0-9]+\.?[0-9]*)\s*sy", out)
    if cpu_match:
        try:
            us = float(cpu_match.group(1))
            sy = float(cpu_match.group(2))
            cpu_percent = round(us + sy, 1)
        except Exception:
            cpu_percent = None
    # Parse Mem line examples:
    # "MiB Mem :  15937.3 total,  10851.5 free,   1522.5 used,   3563.3 buff/cache"
    # "KiB Mem :  16319752 total,  103..."
    mem_match = re.search(r"MiB Mem\s*:\s*([0-9]+\.?[0-9]*) total,\s*([0-9]+\.?[0-9]*) free,\s*([0-9]+\.?[0-9]*) used", out)
    if not mem_match:
        mem_match = re.search(r"KiB Mem\s*:\s*([0-9]+) total,\s*([0-9]+) free,\s*([0-9]+) used", out)
        if mem_match:
            try:
                total = float(mem_match.group(1))
                used = float(mem_match.group(3))
                mem_percent = round((used / total) * 100.0, 1)
            except Exception:
                mem_percent = None
    else:
        try:
            total = float(mem_match.group(1))
            used = float(mem_match.group(3))
            mem_percent = round((used / total) * 100.0, 1)
        except Exception:
            mem_percent = None

    if cpu_percent is None and mem_percent is None:
        raise HTTPException(status_code=500, detail={"message": "failed to parse top", "sample": out.splitlines()[:10]})

    return {"cpu_percent": cpu_percent, "mem_percent": mem_percent}


#@app.get("/api/health/gpu")
async def get_gpu_health(user_id: str):
    """Get GPU health information via SSH, with persistent session management for hop connections"""
    conn = connections.get(user_id)
    if not conn:
        raise HTTPException(status_code=404, detail="No session found")
    
    client = conn.get("ssh_client")
    if not isinstance(client, paramiko.SSHClient):
        raise HTTPException(status_code=400, detail="SSH not connected")
    
    try:
        # Check if we need to hop to node1 for GPU access
        hop_config = conn.get("ssh_hop_config", {})
        target_node = hop_config.get("target_host", "node1")
        hop_password = hop_config.get("target_password")
        
        print(f"[GPU_HEALTH] Getting GPU info from {target_node}")
        
        # Try direct nvidia-smi first (in case we're already on the compute node)
        def run_nvidia_smi_direct():
            stdin, stdout, stderr = client.exec_command("nvidia-smi --query-gpu=index,name,temperature.gpu,utilization.gpu,memory.used,memory.total,power.draw --format=csv,noheader,nounits")
            stdout_str = stdout.read().decode().strip()
            stderr_str = stderr.read().decode().strip()
            exit_code = stdout.channel.recv_exit_status()
            return stdout_str, stderr_str, exit_code
        
        stdout_str, stderr_str, exit_code = await run_blocking(run_nvidia_smi_direct)
        
        # If direct nvidia-smi failed and we have hop config, try persistent hop session
        if exit_code != 0 and hop_password:
            print(f"[GPU_HEALTH] Direct nvidia-smi failed, using hop session to {target_node}")
            
            # Check if we already have a persistent hop channel
            hop_channel = conn.get("hop_channel")
            
            # If no hop channel exists or it's closed, create a new one
            if not hop_channel or hop_channel.closed:
                print(f"[GPU_HEALTH] Creating new hop session to {target_node}")
                
                def create_hop_session():
                    try:
                        transport = client.get_transport()
                        channel = transport.open_session()
                        channel.get_pty()
                        
                        # Execute SSH to target node
                        hop_command = f"ssh {target_node}"
                        print(f"[GPU_HEALTH] Executing: {hop_command}")
                        channel.exec_command(hop_command)
                        
                        # Handle password authentication
                        import time
                        time.sleep(1)  # Wait for prompt
                        
                        output = ""
                        max_wait = 10  # Maximum 10 seconds to wait for password prompt
                        start_time = time.time()
                        
                        while time.time() - start_time < max_wait:
                            if channel.recv_ready():
                                data = channel.recv(1024).decode()
                                output += data
                                print(f"[GPU_HEALTH] Received: {data.strip()}")
                                
                                # Check for password prompt
                                if "password:" in data.lower() or "Password:" in data:
                                    print(f"[GPU_HEALTH] Sending password for {target_node}")
                                    channel.send(hop_password + "\n")
                                    time.sleep(2)  # Wait for login to complete
                                    break
                            
                            if channel.exit_status_ready():
                                print("[GPU_HEALTH] SSH session ended unexpectedly")
                                break
                                
                            time.sleep(0.1)
                        
                        # Verify the session is established
                        time.sleep(1)
                        if not channel.closed and not channel.exit_status_ready():
                            print(f"[GPU_HEALTH] Hop session to {target_node} established successfully")
                            return channel
                        else:
                            print(f"[GPU_HEALTH] Failed to establish hop session to {target_node}")
                            if channel:
                                channel.close()
                            return None
                            
                    except Exception as e:
                        print(f"[GPU_HEALTH] Error creating hop session: {str(e)}")
                        return None
                
                hop_channel = await run_blocking(create_hop_session)
                
                if hop_channel:
                    # Store the hop channel for reuse
                    conn["hop_channel"] = hop_channel
                    print(f"[GPU_HEALTH] Stored hop session for reuse")
                else:
                    return {
                        "gpus": [],
                        "message": f"Failed to establish hop connection to {target_node}",
                        "target_node": target_node
                    }
            else:
                print(f"[GPU_HEALTH] Reusing existing hop session to {target_node}")
            
            # Use the hop channel to run nvidia-smi
            def run_nvidia_smi_hop():
                try:
                    if hop_channel.closed:
                        print("[GPU_HEALTH] Hop channel is closed, cannot run command")
                        return "", "Hop session closed", 1
                    
                    # Send nvidia-smi command
                    nvidia_command = "nvidia-smi --query-gpu=index,name,temperature.gpu,utilization.gpu,memory.used,memory.total,power.draw --format=csv,noheader,nounits\n"
                    print(f"[GPU_HEALTH] Sending nvidia-smi command via hop session")
                    hop_channel.send(nvidia_command)
                    
                    # Read the output
                    import time
                    time.sleep(2)  # Give nvidia-smi time to execute
                    
                    final_output = ""
                    max_wait = 10
                    start_time = time.time()
                    
                    while time.time() - start_time < max_wait:
                        if hop_channel.recv_ready():
                            data = hop_channel.recv(4096).decode()
                            final_output += data
                            
                            # Stop reading when we see the next prompt or end of output
                            if "$" in data or ">" in data:
                                break
                        else:
                            time.sleep(0.1)
                    
                    print(f"[GPU_HEALTH] Hop command output: {final_output[:200]}...")
                    return final_output, "", 0 if final_output.strip() else 1
                    
                except Exception as e:
                    print(f"[GPU_HEALTH] Error running command via hop: {str(e)}")
                    # If the hop session failed, remove it so it can be recreated
                    if "hop_channel" in conn:
                        del conn["hop_channel"]
                    return "", str(e), 1
            
            stdout_str, stderr_str, exit_code = await run_blocking(run_nvidia_smi_hop)
            
            if exit_code != 0:
                print(f"[GPU_HEALTH] Hop command failed: {stderr_str}")
                # Clean up failed session
                if "hop_channel" in conn:
                    try:
                        conn["hop_channel"].close()
                    except:
                        pass
                    del conn["hop_channel"]
                
                return {
                    "gpus": [],
                    "message": f"Command failed on {target_node}: {stderr_str}",
                    "target_node": target_node
                }
        elif exit_code != 0:
            print(f"[GPU_HEALTH] nvidia-smi failed and no hop config: {stderr_str}")
            return {
                "gpus": [],
                "message": f"nvidia-smi failed: {stderr_str}",
                "target_node": "local"
            }
        
        print(f"[GPU_HEALTH] Parsing nvidia-smi output...")
        
        # Parse nvidia-smi output
        gpus = []
        if stdout_str.strip():
            lines = stdout_str.strip().split('\n')
            for line in lines:
                if line.strip() and ',' in line and not line.startswith('index'):
                    try:
                        parts = [p.strip() for p in line.split(',')]
                        if len(parts) >= 7:
                            gpu_data = {
                                "index": int(parts[0]),
                                "name": parts[1],
                                "temperature": float(parts[2]) if parts[2] not in ['[Not Supported]', '[N/A]', '', 'N/A'] else None,
                                "utilization": float(parts[3]) if parts[3] not in ['[Not Supported]', '[N/A]', '', 'N/A'] else None,
                                "memory_used": int(parts[4]) if parts[4] not in ['[Not Supported]', '[N/A]', '', 'N/A'] else None,
                                "memory_total": int(parts[5]) if parts[5] not in ['[Not Supported]', '[N/A]', '', 'N/A'] else None,
                                "power_draw": float(parts[6]) if parts[6] not in ['[Not Supported]', '[N/A]', '', 'N/A'] else None
                            }
                            gpus.append(gpu_data)
                            print(f"[GPU_HEALTH] Parsed GPU {gpu_data['index']}: {gpu_data['name']}")
                    except (ValueError, IndexError) as e:
                        print(f"[GPU_HEALTH] Error parsing line '{line}': {e}")
                        continue
        
        result = {
            "gpus": gpus,
            "processes": [],
            "target_node": target_node,
            "message": f"Successfully retrieved {len(gpus)} GPU(s) from {target_node}" if gpus else "No GPUs found"
        }
        
        print(f"[GPU_HEALTH] Returning {len(gpus)} GPUs from {target_node}")
        return result
    
    except Exception as e:
        print(f"[GPU_HEALTH] Error: {e}")
        import traceback
        traceback.print_exc()
        return {
            "error": str(e),
            "gpus": [],
            "target_node": hop_config.get("target_host", "unknown") if 'hop_config' in locals() else "unknown"
        }
class GPUHealthConnectParams(BaseModel):
    hostname: str
    username: str
    password: Optional[str] = None
    port: int = 22
    timeout: int = 10
    allow_agent: bool = True
    look_for_keys: bool = True
    pkey_path: Optional[str] = None
    pkey_data: Optional[str] = None
    pkey_type: Optional[str] = None


class GPUHealthRequest(BaseModel):
    user_id: str
    target_node: Optional[str] = None
    forward_agent: bool = True
    extra_args: Optional[str] = None
    password: Optional[str] = None
    connect: Optional[GPUHealthConnectParams] = None


@app.post("/api/health/gpu")
async def api_health_gpu_post(req: GPUHealthRequest):
    # Ensure connection exists or auto-connect if connect params provided
    conn = connections.get(req.user_id) or {}
    client = conn.get("ssh_client") if conn else None

    def _transport_alive(c: Optional[paramiko.SSHClient]) -> bool:
        try:
            if not isinstance(c, paramiko.SSHClient):
                return False
            t = c.get_transport()
            return bool(t and t.is_active())
        except Exception:
            return False

    if not _transport_alive(client):
        if not req.connect:
            raise HTTPException(status_code=400, detail="ssh not connected; provide 'connect' parameters in POST body to auto-connect")
        try:
            client = await run_blocking(
                build_paramiko_client_sync,
                req.connect.hostname,
                req.connect.username,
                req.connect.password,
                req.connect.timeout,
                req.connect.port,
                req.connect.allow_agent,
                req.connect.look_for_keys,
                req.connect.pkey_path,
                req.connect.pkey_data,
                req.connect.pkey_type,
            )
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"auto-connect failed: {e}")
        conn["ssh_client"] = client
        connections[req.user_id] = conn

    # Build and run the GPU command (reuse GET logic)
    query = "index,utilization.gpu,memory.used,temperature.gpu"
    inner_cmd = f"nvidia-smi --query-gpu={query} --format=csv,noheader,nounits"

    if req.target_node:
        hop_chan: Optional[paramiko.Channel] = conn.get("hop_channel") if conn else None  # type: ignore
        if isinstance(hop_chan, paramiko.Channel) and not hop_chan.closed:
            out, err, rc = await run_blocking(_exec_on_hop_channel_sync, hop_chan, inner_cmd, 60)
        else:
            base = f"ssh -t {req.target_node}"
            if req.forward_agent:
                base += " -A"
            if req.password:
                if req.extra_args:
                    base = f"{base} {req.extra_args}"
                cmd = f"{base} {shlex.quote(inner_cmd)}"
                chan, _stdin, _stdout, _stderr, out, err, rc = await run_blocking(
                    _jump_to_node_sync, client, cmd, req.password, 20, req.forward_agent
                )
                try:
                    chan.close()
                except Exception:
                    pass
            else:
                defaults = "-o BatchMode=yes -o StrictHostKeyChecking=no"
                base = f"{base} {defaults}" if not req.extra_args else f"{base} {defaults} {req.extra_args}"
                cmd = f"{base} {shlex.quote(inner_cmd)}"
                out, err, rc = await run_blocking(_exec_hop_once_sync, client, cmd, 15, req.forward_agent)
    else:
        out, err, rc = await ssh_exec_read_all(client, inner_cmd, timeout=10)

    if rc != 0:
        return {"gpus": [], "message": err.strip() or out.strip(), "target_node": req.target_node or "bastion"}

    gpus = []
    for line in out.splitlines():
        parts = [p.strip() for p in line.split(',')]
        if len(parts) < 4:
            continue
        try:
            idx = int(parts[0])
            util = int(float(parts[1]))
            mem_used = int(float(parts[2]))
            temp = int(float(parts[3]))
            gpus.append({
                "index": idx,
                "utilization_percent": util,
                "memory_used_mb": mem_used,
                "temp_c": temp,
            })
        except Exception:
            continue

    return gpus

# -----------------------
# REST: SSH hop (nested SSH)
# -----------------------
class SSHJumpRequest(BaseModel):
    user_id: str
    target_node: str
    password: Optional[str] = None
    extra_args: Optional[str] = Field(None, description="Additional args appended to ssh command")
    timeout: int = Field(30, description="Overall timeout seconds for establishing hop")
    forward_agent: bool = Field(True, description="Enable SSH agent forwarding (-A)")


def _jump_to_node_sync(client: paramiko.SSHClient, command: str, password: Optional[str], timeout: int, forward_agent: bool = True):
    """Execute nested ssh with PTY, respond to hostkey and password prompts, return channel and buffers.
    Works with agent-forwarded or key-based auth (no password) as well.
    """
    # Start command with PTY
    stdin, stdout, stderr = client.exec_command(command, get_pty=True, timeout=timeout)
    chan: paramiko.Channel = stdout.channel
    chan.settimeout(0.5)
    # Enable agent forwarding on this channel if requested
    if forward_agent:
        try:
            AgentRequestHandler(chan)
        except Exception:
            pass

    out_buf = ""
    err_buf = ""
    sent_yes = False
    sent_pw = False

    import time
    deadline = time.time() + timeout
    while time.time() < deadline:
        # Drain stdout/stderr
        try:
            while chan.recv_ready():
                out_buf += chan.recv(4096).decode("utf-8", errors="replace")
        except Exception:
            pass
        try:
            while chan.recv_stderr_ready():
                err_buf += chan.recv_stderr(4096).decode("utf-8", errors="replace")
        except Exception:
            pass

        low = (out_buf + err_buf).lower()
        if not sent_yes and "(yes/no)" in low:
            try:
                stdin.write("yes\n"); stdin.flush()
                sent_yes = True
            except Exception:
                pass

        if (not sent_pw) and password and ("password:" in low or "password for" in low):
            try:
                stdin.write(password + "\n"); stdin.flush()
                sent_pw = True
            except Exception:
                pass

        # Failure detection
        if "permission denied" in low or "authentication failed" in low:
            break

        # Success heuristic: got shell prompt after auth or channel open without exit
        if (sent_pw or password is None) and out_buf.splitlines():
            last = out_buf.splitlines()[-1]
            if re.search(r"[a-z0-9_.-]+@[a-z0-9_.-]+.*[#$] ?$", last, re.IGNORECASE) or re.search(r"[#$] ?$", last):
                return chan, stdin, stdout, stderr, out_buf, err_buf, 0

        if chan.exit_status_ready():
            rc = chan.recv_exit_status()
            return chan, stdin, stdout, stderr, out_buf, err_buf, rc

        time.sleep(0.1)

    rc = chan.recv_exit_status() if chan.exit_status_ready() else 1
    return chan, stdin, stdout, stderr, out_buf, err_buf, rc


@app.post("/ssh/hop")
async def api_ssh_hop(req: SSHJumpRequest):
    conn = connections.get(req.user_id)
    if not conn:
        raise HTTPException(status_code=404, detail="no session for user_id")
    client = conn.get("ssh_client")
    if not isinstance(client, paramiko.SSHClient):
        raise HTTPException(status_code=400, detail="ssh not connected")
    transport = client.get_transport()
    if not (transport and transport.is_active()):
        raise HTTPException(status_code=400, detail="ssh transport not active")

    # Build command. Force pseudo-terminal with -t and keep it simple.
    base = f"ssh -t {req.target_node}"
    if req.forward_agent and " -A" not in base and not (req.extra_args and " -A" in req.extra_args):
        base += " -A"
    # If no password is provided, avoid getting stuck at password prompt
    defaults = "-o BatchMode=yes -o StrictHostKeyChecking=no"
    if req.password:
        base = f"{base} {req.extra_args}" if req.extra_args else base
    else:
        base = f"{base} {defaults}" if not req.extra_args else f"{base} {defaults} {req.extra_args}"

    try:
        chan, stdin, stdout, stderr, out, err, rc = await run_blocking(_jump_to_node_sync, client, base, req.password, req.timeout, req.forward_agent)
    except Exception as e:
        raise HTTPException(status_code=502, detail={"status": "error", "message": f"jump exec failed: {e}"})

    if rc == 0:
        # Persist channel for interactive use
        conn["hop_channel"] = chan
        connections[req.user_id] = conn
        return {"status": "success", "message": f"Successfully hopped to {req.target_node}.", "stdout": out}
    else:
        return {"status": "error", "message": f"Failed to hop to {req.target_node}", "stdout": out, "stderr": err, "returncode": rc}

# Simple status endpoint
@app.get("/_status")
async def status():
    return {"status": "ok", "connected_sessions": list(connections.keys())}


# Uvicorn startup instructions (commented)
# To run:
# pip install fastapi "uvicorn[standard]" paramiko pydantic
# uvicorn main:app --host 0.0.0.0 --port 8000 --reload

if __name__ == "__main__":
    print("Run with: uvicorn main:app --host 0.0.0.0 --port 8000 --reload")


# -----------------------
# Nohup Job Monitoring APIs
# -----------------------
class ProcessInfo(BaseModel):
    pid: int
    command: str
    status: str
    cpu_percent: Optional[float] = None
    memory_mb: Optional[float] = None
    runtime_seconds: Optional[int] = None
    gpu_processes: Optional[list] = None

class JobStartRequest(BaseModel):
    user_id: str
    command: str
    working_dir: Optional[str] = None
    target_node: Optional[str] = None
    job_name: Optional[str] = None
    output_file: Optional[str] = None


# Enhanced nohup job endpoints with better script execution and log management

# Improved job list endpoint with better filtering and status detection
@app.get("/api/jobs/list")
async def api_jobs_list(user_id: str, target_node: Optional[str] = None):
    """List all nohup jobs with dynamic script detection and comprehensive logging."""
    print(f"[JOBS LIST API] Request: user_id={user_id}, target_node={target_node}")
    """List all running nohup jobs with dynamic script and log detection."""
    conn = connections.get(user_id)
    if not conn:
        print(f"[JOBS LIST API] Error: No connection found for user_id={user_id}")
        raise HTTPException(status_code=404, detail="no session for user_id")
    client = conn.get("ssh_client")
    if not isinstance(client, paramiko.SSHClient):
        print(f"[JOBS LIST API] Error: SSH not connected for user_id={user_id}")
        raise HTTPException(status_code=400, detail="ssh not connected")
    
    # Enhanced command to find all nohup processes with flexible parsing
    cmd = r"""
    ps aux | grep -v grep | grep nohup | while read user pid cpu mem vsz rss tty stat start time cmdline; do
        # Extract the full command line
        full_cmd=$(ps -p $pid -o args= 2>/dev/null | head -1)
        
        # Get working directory
        cwd=$(pwdx $pid 2>/dev/null | cut -d: -f2- | xargs 2>/dev/null || echo "unknown")
        
        # Get runtime in seconds
        runtime_sec=$(ps -o etimes= -p $pid 2>/dev/null | tr -d ' ' || echo "0")
        
        # Initialize variables
        script_name=""
        script_args=""
        log_file=""
        
        # Dynamic parsing of nohup commands
        if echo "$full_cmd" | grep -q "nohup"; then
            # Remove 'nohup' and any leading/trailing whitespace
            cmd_without_nohup=$(echo "$full_cmd" | sed 's/^[[:space:]]*nohup[[:space:]]*//' | sed 's/[[:space:]]*&[[:space:]]*$//')
            
            # Check if there's output redirection
            if echo "$cmd_without_nohup" | grep -q ">"; then
                # Split into command part and redirection part
                cmd_part=$(echo "$cmd_without_nohup" | sed 's/[[:space:]]*>[[:space:]]*.*//')
                redirect_part=$(echo "$cmd_without_nohup" | sed -n 's/.*>[[:space:]]*\([^[:space:]]*\).*/\1/p')
                
                # Extract log file (remove 2>&1 if present)
                log_file=$(echo "$redirect_part" | sed 's/[[:space:]]*2>&1.*//')
            else
                # No redirection, use full command
                cmd_part="$cmd_without_nohup"
            fi
            
            # Extract script/executable and arguments
            script_name=$(echo "$cmd_part" | awk '{print $1}')
            script_args=$(echo "$cmd_part" | cut -d' ' -f2- 2>/dev/null || echo "")
            
            # Handle different script patterns
            case "$script_name" in
                ./*)
                    # Relative path with ./
                    if [ "$cwd" != "unknown" ]; then
                        full_script_path="$cwd/${script_name:2}"
                        script_display="${script_name:2}"
                    else
                        full_script_path="$script_name"
                        script_display="$script_name"
                    fi
                    ;;
                /*)
                    # Absolute path
                    full_script_path="$script_name"
                    script_display=$(basename "$script_name")
                    ;;
                python*|python3*)
                    # Python with script as argument
                    if [ -n "$script_args" ]; then
                        py_script=$(echo "$script_args" | awk '{print $1}')
                        remaining_args=$(echo "$script_args" | cut -d' ' -f2- 2>/dev/null || echo "")
                        script_display=$(basename "$py_script")
                        full_script_path="$py_script"
                        script_args="$remaining_args"
                        script_name="$py_script"
                    else
                        script_display="python"
                        full_script_path="python"
                    fi
                    ;;
                *)
                    # Plain script name or other executable
                    if [ "$cwd" != "unknown" ] && [ -f "$cwd/$script_name" ]; then
                        full_script_path="$cwd/$script_name"
                    else
                        full_script_path="$script_name"
                    fi
                    script_display=$(basename "$script_name")
                    ;;
            esac
        fi
        
        # Convert log file path to absolute if needed
        if [ -n "$log_file" ] && [ "${log_file:0:1}" != "/" ] && [ "$cwd" != "unknown" ]; then
            log_file="$cwd/$log_file"
        fi
        
        # Fallback log file detection if no explicit redirection
        if [ -z "$log_file" ] && [ "$cwd" != "unknown" ]; then
            # Look for recently modified log files in working directory
            for ext in "txt" "log" "out"; do
                found_log=$(find "$cwd" -maxdepth 1 -name "*.$ext" -type f -newer "/proc/$pid/stat" 2>/dev/null | head -1)
                if [ -n "$found_log" ]; then
                    log_file="$found_log"
                    break
                fi
            done
            
            # Check for common log file names
            if [ -z "$log_file" ]; then
                for logname in "nohup.out" "output.txt" "log.txt" "script.log"; do
                    if [ -f "$cwd/$logname" ]; then
                        log_file="$cwd/$logname"
                        break
                    fi
                done
            fi
        fi
        
        # Get memory info
        mem_kb=$(cat /proc/$pid/status 2>/dev/null | grep "VmRSS:" | awk '{print $2}' || echo "0")
        
        # Check GPU usage
        gpu_info=$(nvidia-smi pmon -c 1 2>/dev/null | grep -E "^[[:space:]]*[0-9]+[[:space:]]+$pid" | head -1 || echo "")
        
        # Determine job type dynamically
        job_type="nohup"
        case "$full_cmd" in
            *python*) job_type="python" ;;
            *\.sh*) job_type="shell" ;;
            *\.py*) job_type="python" ;;
            *train*) job_type="training" ;;
            *inference*|*predict*) job_type="inference" ;;
            *jupyter*) job_type="jupyter" ;;
            *tensorboard*) job_type="tensorboard" ;;
        esac
        
        # Output structured data
        echo "$pid|$user|$cpu|$mem|$runtime_sec|$cwd|$script_display|$full_script_path|$log_file|$script_args|$full_cmd|$gpu_info|$mem_kb|$job_type"
    done
    """
    
    print(f"[JOBS LIST API] Executing command on target_node={target_node}")
    if target_node:
        hop_chan = conn.get("hop_channel")
        print(f"[JOBS LIST API] Using hop channel for target_node={target_node}")
        if isinstance(hop_chan, paramiko.Channel) and not hop_chan.closed:
            out, err, rc = await run_blocking(_exec_on_hop_channel_sync, hop_chan, cmd, 30)
        else:
            ssh_cmd = f"ssh -t {target_node} -o BatchMode=yes -o StrictHostKeyChecking=no"
            out, err, rc = await run_blocking(_exec_hop_once_sync, client, f'{ssh_cmd} {shlex.quote(cmd)}', 30)
    else:
        print(f"[JOBS LIST API] Executing on bastion host")
        out, err, rc = await ssh_exec_read_all(client, cmd, timeout=30)
    
    jobs = []
    for line in out.splitlines():
        if "|" not in line or line.strip() == "":
            continue
        parts = line.split("|", 13)
        if len(parts) < 10:
            continue
        try:
            job = {
                "pid": int(parts[0]),
                "user": parts[1],
                "cpu_percent": float(parts[2]) if parts[2] else 0.0,
                "memory_percent": float(parts[3]) if parts[3] else 0.0,
                "runtime_seconds": int(parts[4]) if parts[4] else 0,
                "working_dir": parts[5] if parts[5] != "unknown" else None,
                "script_name": parts[6] if parts[6] else None,
                "script_path": parts[7] if parts[7] else None,
                "log_file": parts[8] if parts[8] else None,
                "script_args": parts[9] if parts[9] else None,
                "command": parts[10] if len(parts) > 10 else "",
                "gpu_info": parts[11] if len(parts) > 11 and parts[11].strip() else None,
                "memory_mb": int(parts[12]) // 1024 if len(parts) > 12 and parts[12].isdigit() else 0,
                "job_type": parts[13] if len(parts) > 13 else "unknown",
                "target_node": target_node or "bastion",
                "status": "running",
                "has_log_file": bool(parts[8] and parts[8].strip()),
                "has_args": bool(parts[9] and parts[9].strip())
            }
            
            jobs.append(job)
        except Exception as e:
            print(f"Error parsing job line: {line}, error: {e}")
            continue
    
    return {"jobs": jobs, "target_node": target_node or "bastion", "total_jobs": len(jobs)}
@app.post("/api/jobs/start")
async def api_job_start(req: JobStartRequest):
    """Start a nohup job with comprehensive logging."""
    print(f"[JOB START API] Request: user_id={user_id}, command={request.command}, target_node={request.target_node}")
    """Start a new nohup job with enhanced script execution and logging."""
    conn = connections.get(req.user_id)
    if not conn:
        print(f"[JOB START API] Error: No connection found for user_id={user_id}")
        raise HTTPException(status_code=404, detail="no session for user_id")
    client = conn.get("ssh_client")
    if not isinstance(client, paramiko.SSHClient):
        print(f"[JOB START API] Error: SSH not connected for user_id={user_id}")
        raise HTTPException(status_code=400, detail="ssh not connected")
    
    # Enhanced job setup
    job_name = req.job_name or f"job_{int(time.time())}"
    working_dir = req.working_dir or "~"
    output_file = req.output_file or f"{job_name}.log"
    
    # Create a comprehensive job start script
    cmd = f'''
    cd {shlex.quote(working_dir)} || exit 1
    
    # Create job directory structure
    mkdir -p .vigilink_jobs
    
    # Set up logging with both stdout and file output
    exec > >(tee -a {shlex.quote(output_file)}) 2>&1
    
    echo "=== Job Started: {job_name} ===" 
    echo "Timestamp: $(date)"
    echo "Working Directory: $(pwd)"
    echo "Command: {req.command}"
    echo "Log File: {output_file}"
    echo "================================="
    echo ""
    
    # Start the actual job with nohup
    nohup bash -c '{req.command}' &
    job_pid=$!
    
    # Save job metadata
    cat > .vigilink_jobs/{job_name}.json << END_JSON
{{
    "job_name": "{job_name}",
    "pid": $job_pid,
    "command": "{req.command}",
    "working_dir": "$(pwd)",
    "log_file": "{output_file}",
    "start_time": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "user_id": "{req.user_id}",
    "target_node": "{req.target_node or 'bastion'}"
}}
END_JSON
    
    echo "Job {job_name} started with PID: $job_pid"
    echo "PID:$job_pid"  # For parsing
    echo "LOG_FILE:{output_file}"  # For parsing
    '''
    
    if req.target_node:
        hop_chan = conn.get("hop_channel")
        if isinstance(hop_chan, paramiko.Channel) and not hop_chan.closed:
            out, err, rc = await run_blocking(_exec_on_hop_channel_sync, hop_chan, cmd, 30)
        else:
            ssh_cmd = f"ssh -t {req.target_node} -o BatchMode=yes -o StrictHostKeyChecking=no"
            out, err, rc = await run_blocking(_exec_hop_once_sync, client, f'{ssh_cmd} {shlex.quote(cmd)}', 30)
    else:
        out, err, rc = await ssh_exec_read_all(client, cmd, timeout=30)
    
    # Enhanced parsing of output
    pid = None
    log_file_path = None
    
    for line in out.splitlines():
        if line.startswith("PID:"):
            try:
                pid = int(line.split(":", 1)[1].strip())
            except:
                pass
        elif line.startswith("LOG_FILE:"):
            log_file_path = line.split(":", 1)[1].strip()
    
    return {
        "status": "started" if rc == 0 else "failed",
        "job_name": job_name,
        "pid": pid,
        "log_file": log_file_path,
        "working_dir": working_dir,
        "output": out,
        "error": err if rc != 0 else None,
        "target_node": req.target_node or "bastion",
        "command": req.command
    }


# Enhanced logs endpoint with better file detection
async def api_job_start(req: JobStartRequest):
    """Start a new nohup job with enhanced script execution and logging."""
    conn = connections.get(req.user_id)
    if not conn:
        raise HTTPException(status_code=404, detail="no session for user_id")
    client = conn.get("ssh_client")
    if not isinstance(client, paramiko.SSHClient):
        raise HTTPException(status_code=400, detail="ssh not connected")
    
    # Enhanced job setup
    job_name = req.job_name or f"job_{int(time.time())}"
    working_dir = req.working_dir or "~"
    output_file = req.output_file or f"{job_name}.log"
    
    # Create a comprehensive job start script
    cmd = f'''
    cd {shlex.quote(working_dir)} || exit 1
    
    # Create job directory structure
    mkdir -p .vigilink_jobs
    
    # Set up logging with both stdout and file output
    exec > >(tee -a {shlex.quote(output_file)}) 2>&1
    
    echo "=== Job Started: {job_name} ===" 
    echo "Timestamp: $(date)"
    echo "Working Directory: $(pwd)"
    echo "Command: {req.command}"
    echo "Log File: {output_file}"
    echo "================================="
    echo ""
    
    # Start the actual job with nohup
    nohup bash -c '{req.command}' &
    job_pid=$!
    
    # Save job metadata
    cat > .vigilink_jobs/{job_name}.json << END_JSON
{{
    "job_name": "{job_name}",
    "pid": $job_pid,
    "command": "{req.command}",
    "working_dir": "$(pwd)",
    "log_file": "{output_file}",
    "start_time": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "user_id": "{req.user_id}",
    "target_node": "{req.target_node or 'bastion'}"
}}
END_JSON
    
    echo "Job {job_name} started with PID: $job_pid"
    echo "PID:$job_pid"  # For parsing
    echo "LOG_FILE:{output_file}"  # For parsing
    '''
    
    if req.target_node:
        hop_chan = conn.get("hop_channel")
        if isinstance(hop_chan, paramiko.Channel) and not hop_chan.closed:
            out, err, rc = await run_blocking(_exec_on_hop_channel_sync, hop_chan, cmd, 30)
        else:
            ssh_cmd = f"ssh -t {req.target_node} -o BatchMode=yes -o StrictHostKeyChecking=no"
            out, err, rc = await run_blocking(_exec_hop_once_sync, client, f'{ssh_cmd} {shlex.quote(cmd)}', 30)
    else:
        out, err, rc = await ssh_exec_read_all(client, cmd, timeout=30)
    
    # Enhanced parsing of output
    pid = None
    log_file_path = None
    
    for line in out.splitlines():
        if line.startswith("PID:"):
            try:
                pid = int(line.split(":", 1)[1].strip())
            except:
                pass
        elif line.startswith("LOG_FILE:"):
            log_file_path = line.split(":", 1)[1].strip()
    
    return {
        "status": "started" if rc == 0 else "failed",
        "job_name": job_name,
        "pid": pid,
        "log_file": log_file_path,
        "working_dir": working_dir,
        "output": out,
        "error": err if rc != 0 else None,
        "target_node": req.target_node or "bastion",
        "command": req.command
    }


# Enhanced logs endpoint with better file detection
@app.get("/api/jobs/{pid}/logs")
async def api_job_logs(
    user_id: str, 
    pid: int, 
    target_node: Optional[str] = None, 
    lines: int = Query(100, description="Number of tail lines"),
    log_file: Optional[str] = Query(None, description="Specific log file path"),
    follow: bool = Query(False, description="Follow mode (live tail)")
):
    """Get logs for a specific job process with dynamic log detection and comprehensive logging."""
    print(f"[LOGS API] Request: user_id={user_id}, pid={pid}, target_node={target_node}, lines={lines}, log_file={log_file}")
    
    conn = connections.get(user_id)
    if not conn:
        print(f"[LOGS API] Error: No connection found for user_id={user_id}")
        raise HTTPException(status_code=404, detail="no session for user_id")
    client = conn.get("ssh_client")
    if not isinstance(client, paramiko.SSHClient):
        print(f"[LOGS API] Error: SSH not connected for user_id={user_id}")
        raise HTTPException(status_code=400, detail="ssh not connected")
    
    if log_file:
        # Use specific log file
        print(f"[LOGS API] Using specific log file: {log_file}")
        cmd = f"tail -n {lines} {shlex.quote(log_file)} 2>/dev/null || echo 'Log file not accessible: {log_file}'"
    else:
        # Dynamic log file detection
        print(f"[LOGS API] Performing dynamic log detection for PID {pid}")
        cmd = f"""
echo "=== Dynamic Log Detection for PID {pid} ==="
# Get process info
ps -p {pid} -o pid,cmd --no-headers 2>/dev/null || echo "Process {pid} not found"

# Get working directory
cwd=$(pwdx {pid} 2>/dev/null | cut -d: -f2- | xargs 2>/dev/null || echo ".")
echo "Working directory: $cwd"

# Get the full command to analyze
full_cmd=$(ps -p {pid} -o args= 2>/dev/null | head -1)
echo "Full command: $full_cmd"
echo ""

# Initialize log file variable
found_log=""

# Method 1: Extract from nohup command redirection
if echo "$full_cmd" | grep -q "nohup.*>"; then
    echo "Method 1: Extracting from command redirection..."
    # Remove nohup and everything after &
    cmd_clean=$(echo "$full_cmd" | sed 's/^[[:space:]]*nohup[[:space:]]*//' | sed 's/[[:space:]]*&[[:space:]]*$//')
    
    # Extract output redirection
    if echo "$cmd_clean" | grep -q ">"; then
        redirect_file=$(echo "$cmd_clean" | sed -n 's/.*>[[:space:]]*\([^[:space:]]*\).*/\1/p' | sed 's/[[:space:]]*2>&1.*//')
        
        # Convert to absolute path if relative
        if [ -n "$redirect_file" ] && [ "${redirect_file:0:1}" != "/" ]; then
            redirect_file="$cwd/$redirect_file"
        fi
        
        # Check if file exists and is readable
        if [ -n "$redirect_file" ] && [ -f "$redirect_file" ]; then
            found_log="$redirect_file"
            echo "Found log from redirection: $found_log"
        fi
    fi
fi

# Method 2: Look for recently modified files with common extensions
if [ -z "$found_log" ]; then
    echo "Method 2: Searching for recent log files..."
    for ext in "txt" "log" "out" "logs"; do
        recent_log=$(find "$cwd" -maxdepth 1 -name "*.$ext" -type f -newer "/proc/{pid}/stat" 2>/dev/null | head -1)
        if [ -n "$recent_log" ]; then
            found_log="$recent_log"
            echo "Found recent log file: $found_log"
            break
        fi
    done
fi

# Method 3: Look for common log file patterns
if [ -z "$found_log" ]; then
    echo "Method 3: Checking common log file names..."
    for logname in "nohup.out" "output.txt" "log.txt" "script.log" "scriptlogs.txt" "*.log" "*.txt"; do
        if [ "$logname" = "*.log" ] || [ "$logname" = "*.txt" ]; then
            # Use find for wildcard patterns
            pattern_log=$(find "$cwd" -maxdepth 1 -name "$logname" -type f 2>/dev/null | head -1)
            if [ -n "$pattern_log" ]; then
                found_log="$pattern_log"
                echo "Found pattern log file: $found_log"
                break
            fi
        else
            # Direct file check
            if [ -f "$cwd/$logname" ]; then
                found_log="$cwd/$logname"
                echo "Found common log file: $found_log"
                break
            fi
        fi
    done
fi

# Method 4: Look for any .txt or .log files modified around the same time
if [ -z "$found_log" ]; then
    echo "Method 4: Looking for any recent txt/log files..."
    # Find files modified in the last hour
    recent_any=$(find "$cwd" -maxdepth 1 \( -name "*.txt" -o -name "*.log" -o -name "*.out" \) -type f -mmin -60 2>/dev/null | head -1)
    if [ -n "$recent_any" ]; then
        found_log="$recent_any"
        echo "Found recent file: $found_log"
    fi
fi

# Display results and show log content
if [ -n "$found_log" ] && [ -f "$found_log" ]; then
    echo ""
    echo "=== Successfully found log file: $found_log ==="
    echo "File size: $(stat -c%s "$found_log" 2>/dev/null || echo "unknown") bytes"
    echo "Last modified: $(stat -c%y "$found_log" 2>/dev/null || echo "unknown")"
    echo ""
    echo "=== Log Content (last {lines} lines) ==="
    tail -n {lines} "$found_log"
else
    echo ""
    echo "=== No log file found ==="
    echo "Searched in directory: $cwd"
    echo "Available files:"
    ls -la "$cwd" 2>/dev/null | head -20
    echo ""
    echo "Process may not have log redirection or log file may not exist yet."
fi
"""
    
    print(f"[LOGS API] Executing log detection command on target_node={target_node}")
    
    if target_node:
        hop_chan = conn.get("hop_channel")
        if isinstance(hop_chan, paramiko.Channel) and not hop_chan.closed:
            print(f"[LOGS API] Using hop channel for target_node={target_node}")
            out, err, rc = await run_blocking(_exec_on_hop_channel_sync, hop_chan, cmd, 30)
        else:
            print(f"[LOGS API] Using SSH hop for target_node={target_node}")
            ssh_cmd = f"ssh -t {target_node} -o BatchMode=yes -o StrictHostKeyChecking=no"
            out, err, rc = await run_blocking(_exec_hop_once_sync, client, f'{ssh_cmd} {shlex.quote(cmd)}', 30)
    else:
        print(f"[LOGS API] Executing on bastion host")
        out, err, rc = await ssh_exec_read_all(client, cmd, timeout=30)
    
    print(f"[LOGS API] Command completed: rc={rc}, output_length={len(out) if out else 0}")
    if err:
        print(f"[LOGS API] Command stderr: {err[:200]}...")
    
    result = {
        "pid": pid,
        "logs": out,
        "error": err if rc != 0 else None,
        "target_node": target_node or "bastion",
        "timestamp": int(time.time()),
        "lines_requested": lines
    }
    
    print(f"[LOGS API] Response summary: pid={pid}, logs_length={len(result['logs']) if result['logs'] else 0}, has_error={bool(result['error'])}")
    
    return result
@app.get("/api/jobs/metadata")
async def api_jobs_metadata(user_id: str, target_node: Optional[str] = None):
    """Get metadata for all vigilink-managed jobs."""
    conn = connections.get(user_id)
    if not conn:
        raise HTTPException(status_code=404, detail="no session for user_id")
    client = conn.get("ssh_client")
    if not isinstance(client, paramiko.SSHClient):
        raise HTTPException(status_code=400, detail="ssh not connected")
    
    cmd = '''
    echo "=== Vigilink Jobs Metadata ==="
    find . -name ".vigilink_jobs" -type d 2>/dev/null | while read job_dir; do
        echo "Directory: $(dirname $job_dir)"
        ls -la "$job_dir"/*.json 2>/dev/null | while read -r perm links owner group size date time file; do
            echo "File: $file"
            cat "$file" 2>/dev/null | jq -c . 2>/dev/null || cat "$file"
            echo "---"
        done
    done
    '''
    
    if target_node:
        hop_chan = conn.get("hop_channel")
        if isinstance(hop_chan, paramiko.Channel) and not hop_chan.closed:
            out, err, rc = await run_blocking(_exec_on_hop_channel_sync, hop_chan, cmd, 20)
        else:
            ssh_cmd = f"ssh -t {target_node} -o BatchMode=yes -o StrictHostKeyChecking=no"
            out, err, rc = await run_blocking(_exec_hop_once_sync, client, f'{ssh_cmd} {shlex.quote(cmd)}', 20)
    else:
        out, err, rc = await ssh_exec_read_all(client, cmd, timeout=20)
    
    return {
        "metadata_output": out,
        "target_node": target_node or "bastion",
        "timestamp": int(time.time())
    }

# -----------------------
# Enhanced GPU Monitoring with Process Details
# -----------------------
@app.get("/api/gpu/detailed")
async def api_gpu_detailed(
    user_id: str,
    target_node: Optional[str] = Query(None, description="target node; empty for bastion"),
    include_processes: bool = Query(True, description="include per-GPU process information")
):
    """Enhanced GPU monitoring with memory details and process information."""
    conn = connections.get(user_id)
    if not conn:
        raise HTTPException(status_code=404, detail="no session for user_id")
    client = conn.get("ssh_client")
    if not isinstance(client, paramiko.SSHClient):
        raise HTTPException(status_code=400, detail="ssh not connected")
    
    # Enhanced nvidia-smi query for detailed information
    queries = [
        "index,name,utilization.gpu,utilization.memory",
        "memory.total,memory.used,memory.free",
        "temperature.gpu,power.draw,power.limit",
        "fan.speed,compute_mode,persistence_mode"
    ]
    
    cmd = f"nvidia-smi --query-gpu={','.join(queries)} --format=csv,noheader,nounits"
    
    if target_node:
        hop_chan = conn.get("hop_channel")
        if isinstance(hop_chan, paramiko.Channel) and not hop_chan.closed:
            out, err, rc = await run_blocking(_exec_on_hop_channel_sync, hop_chan, cmd, 30)
        else:
            ssh_cmd = f"ssh -t {target_node} -o BatchMode=yes -o StrictHostKeyChecking=no"
            out, err, rc = await run_blocking(_exec_hop_once_sync, client, f'{ssh_cmd} {shlex.quote(cmd)}', 30)
    else:
        out, err, rc = await ssh_exec_read_all(client, cmd, timeout=15)
    
    if rc != 0:
        return {"gpus": [], "error": err, "target_node": target_node or "bastion"}
    
    gpus = []
    for line in out.splitlines():
        parts = [p.strip() for p in line.split(',')]
        if len(parts) < 12:  # We expect 12+ fields from our query
            continue
        try:
            gpu = {
                "index": int(parts[0]),
                "name": parts[1],
                "utilization_gpu": int(float(parts[2])),
                "utilization_memory": int(float(parts[3])),
                "memory_total_mb": int(float(parts[4])),
                "memory_used_mb": int(float(parts[5])),
                "memory_free_mb": int(float(parts[6])),
                "temperature_c": int(float(parts[7])),
                "power_draw_w": float(parts[8]) if parts[8] != "N/A" else None,
                "power_limit_w": float(parts[9]) if parts[9] != "N/A" else None,
                "fan_speed_percent": int(float(parts[10])) if parts[10] != "N/A" else None,
                "compute_mode": parts[11],
                "memory_usage_percent": round((int(float(parts[5])) / int(float(parts[4]))) * 100, 1)
            }
            gpus.append(gpu)
        except Exception:
            continue
    
    # Get process information if requested
    if include_processes and gpus:
        processes_cmd = "nvidia-smi pmon -c 1 2>/dev/null || echo 'No process monitoring available'"
        
        if target_node:
            hop_chan = conn.get("hop_channel")
            if isinstance(hop_chan, paramiko.Channel) and not hop_chan.closed:
                proc_out, proc_err, proc_rc = await run_blocking(_exec_on_hop_channel_sync, hop_chan, processes_cmd, 15)
            else:
                ssh_cmd = f"ssh -t {target_node} -o BatchMode=yes -o StrictHostKeyChecking=no"
                proc_out, proc_err, proc_rc = await run_blocking(_exec_hop_once_sync, client, f'{ssh_cmd} {shlex.quote(processes_cmd)}', 15)
        else:
            proc_out, proc_err, proc_rc = await ssh_exec_read_all(client, processes_cmd, timeout=15)
        
        # Parse process information and associate with GPUs
        for gpu in gpus:
            gpu["processes"] = []
        
        for line in proc_out.splitlines():
            if line.startswith("#") or "No process monitoring" in line:
                continue
            parts = line.split()
            if len(parts) >= 4:
                try:
                    gpu_idx = int(parts[0])
                    pid = int(parts[1])
                    mem_usage = parts[3]
                    
                    # Find the GPU and add process info
                    for gpu in gpus:
                        if gpu["index"] == gpu_idx:
                            gpu["processes"].append({
                                "pid": pid,
                                "memory_usage": mem_usage,
                                "type": "compute"  # Could be enhanced to detect inference vs training
                            })
                except Exception:
                    continue
    
    return {"gpus": gpus, "target_node": target_node or "bastion"}


# -----------------------
# System Resource Monitoring
# -----------------------
@app.get("/api/resources/summary")
async def api_resources_summary(user_id: str, target_node: Optional[str] = None):
    """Get comprehensive system resource summary including CPU, memory, disk, and GPU."""
    conn = connections.get(user_id)
    if not conn:
        raise HTTPException(status_code=404, detail="no session for user_id")
    client = conn.get("ssh_client")
    if not isinstance(client, paramiko.SSHClient):
        raise HTTPException(status_code=400, detail="ssh not connected")
    
    cmd = '''
    echo "=== CPU_INFO ==="
    grep "cpu cores" /proc/cpuinfo | head -1
    cat /proc/loadavg
    echo "=== MEMORY_INFO ==="
    free -h
    echo "=== DISK_INFO ==="
    df -h / /home /tmp 2>/dev/null
    echo "=== GPU_SUMMARY ==="
    nvidia-smi --query-gpu=count,memory.total,memory.used --format=csv,noheader,nounits 2>/dev/null | head -1 || echo "No GPU found"
    echo "=== UPTIME ==="
    uptime
    '''
    
    if target_node:
        hop_chan = conn.get("hop_channel")
        if isinstance(hop_chan, paramiko.Channel) and not hop_chan.closed:
            out, err, rc = await run_blocking(_exec_on_hop_channel_sync, hop_chan, cmd, 20)
        else:
            ssh_cmd = f"ssh -t {target_node} -o BatchMode=yes -o StrictHostKeyChecking=no"
            out, err, rc = await run_blocking(_exec_hop_once_sync, client, f'{ssh_cmd} {shlex.quote(cmd)}', 20)
    else:
        out, err, rc = await ssh_exec_read_all(client, cmd, timeout=20)
    
    # Parse the structured output
    sections = {}
    current_section = None
    
    for line in out.splitlines():
        if line.startswith("=== ") and line.endswith(" ==="):
            current_section = line[4:-4].lower()
            sections[current_section] = []
        elif current_section:
            sections[current_section].append(line)
    
    # Parse specific metrics
    result = {"target_node": target_node or "bastion", "raw_sections": sections}
    
    # Parse load average
    if "cpu_info" in sections:
        for line in sections["cpu_info"]:
            if "load average" in line:
                load_match = re.search(r"load average: ([0-9.]+)", line)
                if load_match:
                    result["load_average"] = float(load_match.group(1))
    
    # Parse memory
    if "memory_info" in sections:
        for line in sections["memory_info"]:
            if "Mem:" in line:
                result["memory_summary"] = line.strip()
    
    return result



# -----------------------
# Mobile-Optimized Dashboard APIs
# -----------------------
@app.get("/api/dashboard/mobile")
async def api_dashboard_mobile(user_id: str, target_node: Optional[str] = None):
    """Mobile-optimized dashboard endpoint that returns all key metrics in a single call."""
    conn = connections.get(user_id)
    if not conn:
        raise HTTPException(status_code=404, detail="no session for user_id")
    client = conn.get("ssh_client")
    if not isinstance(client, paramiko.SSHClient):
        raise HTTPException(status_code=400, detail="ssh not connected")
    
    # Single command that gathers all essential information
    cmd = '''
    echo "=== SYSTEM_LOAD ==="
    cat /proc/loadavg
    echo "=== MEMORY ==="
    free | grep Mem:
    echo "=== GPU_QUICK ==="
    nvidia-smi --query-gpu=index,utilization.gpu,memory.used,memory.total,temperature.gpu --format=csv,noheader,nounits 2>/dev/null || echo "No GPU"
    echo "=== ACTIVE_JOBS ==="
    ps aux | grep -E "(nohup|python.*train|python.*inference)" | grep -v grep | head -10
    echo "=== DISK_USAGE ==="
    df -h / | tail -1
    echo "=== UPTIME ==="
    uptime
    '''
    
    if target_node:
        hop_chan = conn.get("hop_channel")
        if isinstance(hop_chan, paramiko.Channel) and not hop_chan.closed:
            out, err, rc = await run_blocking(_exec_on_hop_channel_sync, hop_chan, cmd, 25)
        else:
            ssh_cmd = f"ssh -t {target_node} -o BatchMode=yes -o StrictHostKeyChecking=no"
            out, err, rc = await run_blocking(_exec_hop_once_sync, client, f'{ssh_cmd} {shlex.quote(cmd)}', 25)
    else:
        out, err, rc = await ssh_exec_read_all(client, cmd, timeout=25)
    
    # Parse sections
    sections = {}
    current_section = None
    for line in out.splitlines():
        if line.startswith("=== ") and line.endswith(" ==="):
            current_section = line[4:-4].lower()
            sections[current_section] = []
        elif current_section:
            sections[current_section].append(line)
    
    # Create mobile-friendly summary
    dashboard = {
        "timestamp": int(time.time()),
        "target_node": target_node or "bastion",
        "system": {},
        "gpus": [],
        "active_jobs": [],
        "storage": {}
    }
    
    # Parse load average
    if "system_load" in sections and sections["system_load"]:
        load_line = sections["system_load"][0]
        load_parts = load_line.split()
        if len(load_parts) >= 3:
            dashboard["system"]["load_1m"] = float(load_parts[0])
            dashboard["system"]["load_5m"] = float(load_parts[1])
            dashboard["system"]["load_15m"] = float(load_parts[2])
    
    # Parse memory
    if "memory" in sections and sections["memory"]:
        mem_line = sections["memory"][0]
        mem_parts = mem_line.split()
        if len(mem_parts) >= 3:
            try:
                total = int(mem_parts[1])
                used = int(mem_parts[2])
                dashboard["system"]["memory_total_mb"] = total // 1024
                dashboard["system"]["memory_used_mb"] = used // 1024
                dashboard["system"]["memory_percent"] = round((used / total) * 100, 1)
            except Exception:
                pass
    
    # Parse GPUs
    if "gpu_quick" in sections:
        for line in sections["gpu_quick"]:
            if "No GPU" in line:
                continue
            parts = [p.strip() for p in line.split(',')]
            if len(parts) >= 5:
                try:
                    gpu = {
                        "index": int(parts[0]),
                        "utilization": int(float(parts[1])),
                        "memory_used": int(float(parts[2])),
                        "memory_total": int(float(parts[3])),
                        "memory_percent": round((int(float(parts[2])) / int(float(parts[3]))) * 100, 1),
                        "temperature": int(float(parts[4]))
                    }
                    dashboard["gpus"].append(gpu)
                except Exception:
                    continue
    
    # Parse active jobs
    if "active_jobs" in sections:
        for line in sections["active_jobs"]:
            parts = line.split(None, 10)
            if len(parts) >= 11:
                try:
                    dashboard["active_jobs"].append({
                        "pid": int(parts[1]),
                        "cpu_percent": float(parts[2]),
                        "memory_percent": float(parts[3]),
                        "command": " ".join(parts[10:])[:100] + "..." if len(" ".join(parts[10:])) > 100 else " ".join(parts[10:])
                    })
                except Exception:
                    continue
    
    # Parse disk usage
    if "disk_usage" in sections and sections["disk_usage"]:
        disk_line = sections["disk_usage"][0]
        disk_parts = disk_line.split()
        if len(disk_parts) >= 5:
            dashboard["storage"] = {
                "filesystem": disk_parts[0],
                "total": disk_parts[1],
                "used": disk_parts[2],
                "available": disk_parts[3],
                "use_percent": disk_parts[4]
            }
    
    return dashboard


# -----------------------
# Log Streaming API
# -----------------------
@app.get("/api/logs/stream")
async def api_logs_stream(
    user_id: str, 
    file_path: str,
    target_node: Optional[str] = None,
    lines: int = Query(50, description="Number of lines to fetch"),
    follow: bool = Query(False, description="Whether to follow the log (single fetch for now)")
):
    """Stream log file contents - mobile optimized for nohup outputs."""
    conn = connections.get(user_id)
    if not conn:
        raise HTTPException(status_code=404, detail="no session for user_id")
    client = conn.get("ssh_client")
    if not isinstance(client, paramiko.SSHClient):
        raise HTTPException(status_code=400, detail="ssh not connected")
    
    cmd = f"tail -n {lines} {shlex.quote(file_path)} 2>/dev/null || echo 'Log file not found'"
    
    if target_node:
        hop_chan = conn.get("hop_channel")
        if isinstance(hop_chan, paramiko.Channel) and not hop_chan.closed:
            out, err, rc = await run_blocking(_exec_on_hop_channel_sync, hop_chan, cmd, 15)
        else:
            ssh_cmd = f"ssh -t {target_node} -o BatchMode=yes -o StrictHostKeyChecking=no"
            out, err, rc = await run_blocking(_exec_hop_once_sync, client, f'{ssh_cmd} {shlex.quote(cmd)}', 15)
    else:
        out, err, rc = await ssh_exec_read_all(client, cmd, timeout=15)
    
    return {
        "file_path": file_path,
        "content": out,
        "lines_returned": len(out.splitlines()),
        "target_node": target_node or "bastion",
        "timestamp": int(time.time())
    }


# -----------------------
# Quick Actions for Mobile
# -----------------------
@app.post("/api/quick/restart-job")
async def api_quick_restart_job(
    user_id: str,
    pid: int,
    target_node: Optional[str] = None,
    restart_command: Optional[str] = None
):
    """Quick restart a job by killing it and starting again."""
    # First stop the job
    stop_result = await api_job_stop(user_id, pid, target_node, force=False)
    
    if not stop_result["success"]:
        return {"status": "failed", "message": "Could not stop job", "stop_result": stop_result}
    
    # Wait a moment for cleanup
    await asyncio.sleep(2)
    
    # If restart command provided, start it
    if restart_command:
        start_req = JobStartRequest(
            user_id=user_id,
            command=restart_command,
            target_node=target_node,
            job_name=f"restarted_{pid}"
        )
        start_result = await api_job_start(start_req)
        return {
            "status": "restarted",
            "old_pid": pid,
            "new_pid": start_result.get("pid"),
            "stop_result": stop_result,
            "start_result": start_result
        }
    
    return {"status": "stopped", "old_pid": pid, "stop_result": stop_result}



# -----------------------
# Enhanced Job Analysis with Custom Logs and Results Detection
# -----------------------
def parse_command_for_outputs(command: str) -> dict:
    """Parse a command to extract likely log files and result output paths."""
    import re
    
    outputs = {
        "log_files": [],
        "result_files": [],
        "output_dirs": [],
        "working_dir": None
    }
    
    # Common patterns for log files
    log_patterns = [
        r'--log[_-]?file[=\s]+([^\s]+)',
        r'--output[_-]?log[=\s]+([^\s]+)',
        r'>\s*([^\s]+\.log)',
        r'>\s*([^\s]+\.txt)',
        r'2>&1\s*>\s*([^\s]+)',
        r'--log[=\s]+([^\s]+)',
    ]
    
    # Common patterns for result/output files
    result_patterns = [
        r'--output[_-]?file[=\s]+([^\s]+)',
        r'--results?[_-]?dir[=\s]+([^\s]+)',
        r'--save[_-]?path[=\s]+([^\s]+)',
        r'--checkpoint[_-]?dir[=\s]+([^\s]+)',
        r'--model[_-]?dir[=\s]+([^\s]+)',
        r'--export[_-]?path[=\s]+([^\s]+)',
    ]
    
    # Working directory patterns
    working_dir_patterns = [
        r'cd\s+([^\s&;]+)',
        r'--work[_-]?dir[=\s]+([^\s]+)',
    ]
    
    # Extract log files
    for pattern in log_patterns:
        matches = re.findall(pattern, command, re.IGNORECASE)
        outputs["log_files"].extend(matches)
    
    # Extract result files/directories
    for pattern in result_patterns:
        matches = re.findall(pattern, command, re.IGNORECASE)
        outputs["result_files"].extend(matches)
    
    # Extract working directory
    for pattern in working_dir_patterns:
        matches = re.findall(pattern, command, re.IGNORECASE)
        if matches:
            outputs["working_dir"] = matches[0]
            break
    
    # If no explicit log file found, look for common inference patterns
    if not outputs["log_files"]:
        # Check for python script names that might generate logs
        python_match = re.search(r'python3?\s+([^\s]+\.py)', command)
        if python_match:
            script_name = python_match.group(1).replace('.py', '')
            # Generate likely log file names
            outputs["log_files"].extend([
                f"{script_name}.log",
                f"{script_name}_output.txt",
                f"inference_{script_name}.log"
            ])
    
    # Remove duplicates and clean paths
    outputs["log_files"] = list(set([f.strip('"\'') for f in outputs["log_files"]]))
    outputs["result_files"] = list(set([f.strip('"\'') for f in outputs["result_files"]]))
    
    return outputs


@app.get("/api/jobs/{pid}/analysis")
async def api_job_analysis(user_id: str, pid: int, target_node: Optional[str] = None):
    """Analyze a job's command to find log files, result files, and current status."""
    conn = connections.get(user_id)
    if not conn:
        raise HTTPException(status_code=404, detail="no session for user_id")
    client = conn.get("ssh_client")
    if not isinstance(client, paramiko.SSHClient):
        raise HTTPException(status_code=400, detail="ssh not connected")
    
    # Get full command line and process info
    cmd = f'''
    if ps -p {pid} > /dev/null 2>&1; then
        echo "=== COMMAND ==="
        ps -p {pid} -o args= --no-headers
        echo ""
        echo "=== WORKING_DIR ==="
        pwdx {pid} 2>/dev/null | cut -d: -f2 | tr -d ' ' || echo "unknown"
        echo ""
        echo "=== PROCESS_INFO ==="
        ps -p {pid} -o pid,ppid,pcpu,pmem,etime,state --no-headers
        echo ""
        echo "=== OPEN_FILES ==="
        lsof -p {pid} 2>/dev/null | grep -E "\.log|\.txt|\.json|\.csv|\.out" | head -10 || echo "No relevant files"
    else
        echo "Process {pid} not found"
        exit 1
    fi
    '''
    
    if target_node:
        hop_chan = conn.get("hop_channel")
        if isinstance(hop_chan, paramiko.Channel) and not hop_chan.closed:
            out, err, rc = await run_blocking(_exec_on_hop_channel_sync, hop_chan, cmd, 20)
        else:
            ssh_cmd = f"ssh -t {target_node} -o BatchMode=yes -o StrictHostKeyChecking=no"
            out, err, rc = await run_blocking(_exec_hop_once_sync, client, f'{ssh_cmd} {shlex.quote(cmd)}', 20)
    else:
        out, err, rc = await ssh_exec_read_all(client, cmd, timeout=20)
    
    if rc != 0:
        return {"pid": pid, "running": False, "message": "Process not found"}
    
    # Parse the output sections
    sections = {}
    current_section = None
    for line in out.splitlines():
        if line.startswith("=== ") and line.endswith(" ==="):
            current_section = line[4:-4].lower()
            sections[current_section] = []
        elif current_section:
            sections[current_section].append(line)
    
    # Extract command and analyze it
    command = "\n".join(sections.get("command", [""])).strip()
    working_dir = "\n".join(sections.get("working_dir", [""])).strip()
    
    # Parse command for outputs
    parsed_outputs = parse_command_for_outputs(command)
    if working_dir and working_dir != "unknown":
        parsed_outputs["working_dir"] = working_dir
    
    # Get actual open files
    open_files = []
    for line in sections.get("open_files", []):
        if "No relevant files" not in line and line.strip():
            parts = line.split()
            if len(parts) >= 9:  # lsof output format
                file_path = parts[8] if len(parts) > 8 else parts[-1]
                file_type = parts[4] if len(parts) > 4 else "unknown"
                open_files.append({"path": file_path, "type": file_type})
    
    # Process info
    process_info = {}
    if "process_info" in sections and sections["process_info"]:
        ps_parts = sections["process_info"][0].split()
        if len(ps_parts) >= 6:
            process_info = {
                "pid": int(ps_parts[0]),
                "ppid": int(ps_parts[1]),
                "cpu_percent": float(ps_parts[2]),
                "memory_percent": float(ps_parts[3]),
                "runtime": ps_parts[4],
                "state": ps_parts[5]
            }
    
    return {
        "pid": pid,
        "running": True,
        "command": command,
        "working_dir": working_dir,
        "parsed_outputs": parsed_outputs,
        "open_files": open_files,
        "process_info": process_info,
        "target_node": target_node or "bastion"
    }


@app.get("/api/jobs/{pid}/logs/smart")
async def api_job_logs_smart(
    user_id: str, 
    pid: int, 
    target_node: Optional[str] = None,
    lines: int = Query(100, description="Number of tail lines")
):
    """Smart log fetching that analyzes the command to find actual log files."""
    # First get job analysis to find log files
    analysis = await api_job_analysis(user_id, pid, target_node)
    
    if not analysis["running"]:
        return analysis
    
    conn = connections.get(user_id)
    client = conn.get("ssh_client")
    
    # Try to find actual log files
    log_candidates = []
    
    # Add parsed log files
    log_candidates.extend(analysis["parsed_outputs"]["log_files"])
    
    # Add open files that look like logs
    for open_file in analysis["open_files"]:
        if any(ext in open_file["path"].lower() for ext in ['.log', '.txt', '.out']):
            log_candidates.append(open_file["path"])
    
    # If no specific logs found, try common patterns in working directory
    if not log_candidates:
        working_dir = analysis["working_dir"] or "."
        common_logs = ["*.log", "*.txt", "output.txt", "inference.log", "training.log"]
        log_candidates = [f"{working_dir}/{log}" for log in common_logs]
    
    # Try each log candidate
    logs_found = {}
    for log_path in log_candidates[:5]:  # Limit to 5 attempts
        cmd = f'''
        if [ -f "{log_path}" ]; then
            echo "=== LOG_FOUND: {log_path} ==="
            ls -lh "{log_path}"
            echo "=== CONTENT ==="
            tail -n {lines} "{log_path}"
        else
            # Try glob expansion for wildcards
            for file in {log_path}; do
                if [ -f "$file" ]; then
                    echo "=== LOG_FOUND: $file ==="
                    ls -lh "$file"
                    echo "=== CONTENT ==="
                    tail -n {lines} "$file"
                    break
                fi
            done 2>/dev/null
        fi
        '''
        
        if target_node:
            hop_chan = conn.get("hop_channel")
            if isinstance(hop_chan, paramiko.Channel) and not hop_chan.closed:
                out, err, rc = await run_blocking(_exec_on_hop_channel_sync, hop_chan, cmd, 15)
            else:
                ssh_cmd = f"ssh -t {target_node} -o BatchMode=yes -o StrictHostKeyChecking=no"
                out, err, rc = await run_blocking(_exec_hop_once_sync, client, f'{ssh_cmd} {shlex.quote(cmd)}', 15)
        else:
            out, err, rc = await ssh_exec_read_all(client, cmd, timeout=15)
        
        # Parse output to extract found logs
        current_log = None
        content_section = False
        
        for line in out.splitlines():
            if line.startswith("=== LOG_FOUND:"):
                current_log = line.split(":", 1)[1].strip().split()[0]
                logs_found[current_log] = {"info": "", "content": ""}
                content_section = False
            elif line.startswith("=== CONTENT ===") and current_log:
                content_section = True
            elif current_log:
                if not content_section:
                    logs_found[current_log]["info"] += line + "\n"
                else:
                    logs_found[current_log]["content"] += line + "\n"
    
    return {
        "pid": pid,
        "logs_found": logs_found,
        "log_candidates_tried": log_candidates,
        "analysis_summary": analysis["parsed_outputs"],
        "target_node": target_node or "bastion"
    }


@app.get("/api/jobs/{pid}/results")
async def api_job_results(user_id: str, pid: int, target_node: Optional[str] = None):
    """Find and analyze result files generated by a job."""
    # Get job analysis first
    analysis = await api_job_analysis(user_id, pid, target_node)
    
    if not analysis["running"]:
        return analysis
    
    conn = connections.get(user_id)
    client = conn.get("ssh_client")
    
    working_dir = analysis["working_dir"] or "."
    result_candidates = analysis["parsed_outputs"]["result_files"] + analysis["parsed_outputs"]["output_dirs"]
    
    # Also look for recently modified files in working directory
    cmd = f'''
    cd {shlex.quote(working_dir)} 2>/dev/null || cd .
    echo "=== RECENT_FILES ==="
    find . -maxdepth 2 -type f -mmin -60 -name "*.json" -o -name "*.csv" -o -name "*.txt" -o -name "*.pkl" -o -name "*.pt" -o -name "*.pth" 2>/dev/null | head -10
    echo "=== RESULT_DIRS ==="
    find . -maxdepth 2 -type d -name "*result*" -o -name "*output*" -o -name "*checkpoint*" 2>/dev/null | head -5
    '''
    
    # Add specific result file candidates
    for candidate in result_candidates:
        cmd += f'''
        echo "=== CHECKING: {candidate} ==="
        if [ -f "{candidate}" ]; then
            ls -lh "{candidate}"
            echo "File type: $(file "{candidate}" 2>/dev/null || echo 'unknown')"
        elif [ -d "{candidate}" ]; then
            echo "Directory contents:"
            ls -la "{candidate}" 2>/dev/null | head -10
        else
            echo "Not found: {candidate}"
        fi
        '''
    
    if target_node:
        hop_chan = conn.get("hop_channel")
        if isinstance(hop_chan, paramiko.Channel) and not hop_chan.closed:
            out, err, rc = await run_blocking(_exec_on_hop_channel_sync, hop_chan, cmd, 25)
        else:
            ssh_cmd = f"ssh -t {target_node} -o BatchMode=yes -o StrictHostKeyChecking=no"
            out, err, rc = await run_blocking(_exec_hop_once_sync, client, f'{ssh_cmd} {shlex.quote(cmd)}', 25)
    else:
        out, err, rc = await ssh_exec_read_all(client, cmd, timeout=25)
    
    # Parse results
    sections = {}
    current_section = None
    
    for line in out.splitlines():
        if line.startswith("=== ") and line.endswith(" ==="):
            current_section = line[4:-4]
            sections[current_section] = []
        elif current_section:
            sections[current_section].append(line)
    
    recent_files = [line.strip() for line in sections.get("RECENT_FILES", []) if line.strip() and not line.startswith("./")]
    result_dirs = [line.strip() for line in sections.get("RESULT_DIRS", []) if line.strip()]
    
    # Parse specific candidate results
    candidate_results = {}
    for key, lines in sections.items():
        if key.startswith("CHECKING:"):
            candidate_name = key.split(":", 1)[1].strip()
            candidate_results[candidate_name] = "\n".join(lines)
    
    return {
        "pid": pid,
        "working_dir": working_dir,
        "recent_files": recent_files,
        "result_directories": result_dirs,
        "candidate_results": candidate_results,
        "result_file_candidates": result_candidates,
        "target_node": target_node or "bastion"
    }


# Update the existing job list endpoint to include smart analysis
@app.get("/api/jobs/list/enhanced")
async def api_jobs_list_enhanced(user_id: str, target_node: Optional[str] = None):
    """Enhanced job listing with smart log and result file detection."""
    # Get basic job list first
    basic_jobs = await api_jobs_list(user_id, target_node)
    
    # Enhance each job with smart analysis (limit to prevent timeout)
    enhanced_jobs = []
    for job in basic_jobs["jobs"][:10]:  # Limit to 10 jobs for performance
        try:
            # Quick command analysis without full file system checks
            command = job["command"]
            parsed = parse_command_for_outputs(command)
            
            job["smart_analysis"] = {
                "likely_log_files": parsed["log_files"][:3],  # Top 3 candidates
                "likely_result_files": parsed["result_files"][:3],
                "working_dir": parsed["working_dir"]
            }
            enhanced_jobs.append(job)
        except Exception:
            # Fall back to basic job info if analysis fails
            enhanced_jobs.append(job)
    
    return {
        "jobs": enhanced_jobs,
        "target_node": target_node or "bastion",
        "enhanced": True
    }


@app.get("/vpn/connections")
async def vpn_active_connections():
    """Debug endpoint to show active VPN connections and TUN device allocation."""
    active_connections = get_active_vpn_connections()
    return {
        "active_connections": active_connections,
        "total_connections": len(active_connections),
        "available_devices": [f"vpn{i}" for i in range(3) if f"vpn{i}" not in allocated_tun_devices]
    }


@app.post("/disconnect-all")
async def disconnect_all(user_id: str):
    """Disconnect both VPN and SSH for a user"""
    print(f"[DISCONNECT_ALL] Starting full disconnection for user {user_id}")
    
    results = {
        "user_id": user_id,
        "vpn_result": None,
        "ssh_result": None,
        "status": "completed"
    }
    
    conn = connections.get(user_id)
    if not conn:
        results["status"] = "no_session"
        return results
    
    # Disconnect SSH first
    ssh_client = conn.get("ssh_client")
    if ssh_client and isinstance(ssh_client, paramiko.SSHClient):
        try:
            await run_blocking(ssh_client.close)
            results["ssh_result"] = "disconnected"
            conn["ssh_client"] = None
        except Exception as e:
            results["ssh_result"] = f"error: {e}"
    else:
        results["ssh_result"] = "not_connected"
    
    # Disconnect VPN
    vpn_proc = conn.get("vpn_proc")
    if vpn_proc and isinstance(vpn_proc, subprocess.Popen):
        try:
            vpn_proc.terminate()
            try:
                vpn_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                vpn_proc.kill()
                vpn_proc.wait()
            results["vpn_result"] = "disconnected"
            conn["vpn_proc"] = None
            conn["vpn_start_time"] = None
        except Exception as e:
            results["vpn_result"] = f"error: {e}"
    else:
        results["vpn_result"] = "not_connected"
    
    connections[user_id] = conn
    print(f"[DISCONNECT_ALL] Full disconnection completed for user {user_id}: {results}")
    return results
@app.get("/ssh/read-file")
async def ssh_read_file(user_id: str, file_path: str, max_size: int = 1024*1024):
    """Read file contents via SSH (limited to prevent memory issues)"""
    print(f"[SSH_READ_FILE] Reading file {file_path} for user {user_id}")
    conn = connections.get(user_id)
    if not conn:
        raise HTTPException(status_code=404, detail="no session")
    client = conn.get("ssh_client")
    if not isinstance(client, paramiko.SSHClient):
        raise HTTPException(status_code=400, detail="ssh not connected")
    
    try:
        sftp = await run_blocking(client.open_sftp)
        
        # Check file stats first
        file_stat = await run_blocking(sftp.stat, file_path)
        file_size = file_stat.st_size
        
        # Prevent reading very large files
        if file_size > max_size:
            await run_blocking(sftp.close)
            raise HTTPException(
                status_code=413, 
                detail=f"File too large ({file_size} bytes). Maximum allowed: {max_size} bytes"
            )
        
        # Read the file
        with await run_blocking(sftp.open, file_path, 'r') as remote_file:
            content = await run_blocking(remote_file.read)
        
        await run_blocking(sftp.close)
        
        # Try to decode as text
        try:
            if isinstance(content, bytes):
                text_content = content.decode('utf-8')
            else:
                text_content = str(content)
            
            # Determine if it's likely a binary file
            is_binary = False
            if len(text_content) > 0:
                # Check for null bytes or high ratio of non-printable characters
                null_count = text_content.count('\x00')
                non_printable = sum(1 for c in text_content[:1000] if ord(c) < 32 and c not in '\n\r\t')
                if null_count > 0 or (len(text_content) > 100 and non_printable / min(len(text_content), 1000) > 0.3):
                    is_binary = True
            
            result = {
                "file_path": file_path,
                "content": text_content if not is_binary else f"<Binary file - {file_size} bytes>",
                "size": file_size,
                "is_binary": is_binary,
                "encoding": "utf-8",
                "lines": len(text_content.split('\n')) if not is_binary else 0
            }
            
            print(f"[SSH_READ_FILE] Successfully read {file_size} bytes from {file_path}")
            return result
            
        except UnicodeDecodeError:
            # If UTF-8 fails, try other encodings or treat as binary
            result = {
                "file_path": file_path,
                "content": f"<Binary or non-UTF8 file - {file_size} bytes>",
                "size": file_size,
                "is_binary": True,
                "encoding": "unknown",
                "lines": 0
            }
            return result
            
    except PermissionError as e:
        print(f"[SSH_READ_FILE] Permission denied for {file_path}: {e}")
        raise HTTPException(status_code=403, detail=f"Permission denied: {file_path}")
    except FileNotFoundError as e:
        print(f"[SSH_READ_FILE] File not found {file_path}: {e}")
        raise HTTPException(status_code=404, detail=f"File not found: {file_path}")
    except Exception as e:
        print(f"[SSH_READ_FILE] Error reading file {file_path}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to read file: {e}")
# New endpoint to view stdout/stderr of nohup jobs
@app.get("/api/jobs/view-output")
async def api_jobs_view_output(
    user_id: str, 
    pid: int, 
    target_node: Optional[str] = None,
    lines: int = Query(default=100, description="Number of lines to show from end of file"),
    stream: str = Query(default="stdout", description="stdout or stderr")
):
    """View stdout or stderr of a running process by PID."""
    print(f"[JOBS VIEW OUTPUT] Request: user_id={user_id}, pid={pid}, target_node={target_node}, lines={lines}, stream={stream}")
    
    conn = connections.get(user_id)
    if not conn:
        print(f"[JOBS VIEW OUTPUT] Error: No connection found for user_id={user_id}")
        raise HTTPException(status_code=404, detail="no session for user_id")
    
    client = conn.get("ssh_client")
    if not isinstance(client, paramiko.SSHClient):
        print(f"[JOBS VIEW OUTPUT] Error: SSH not connected for user_id={user_id}")
        raise HTTPException(status_code=400, detail="ssh not connected")
    
    try:
        # First, get the file descriptor path for the specified stream
        fd_num = "1" if stream == "stdout" else "2"
        get_fd_cmd = f'readlink /proc/{pid}/fd/{fd_num} 2>/dev/null'
        
        print(f"[JOBS VIEW OUTPUT] Executing command on target_node={target_node}")
        if target_node and target_node != "bastion":
            # Execute on target node via SSH hop
            hop_config = conn.get("hop_config", {})
            if not hop_config:
                raise HTTPException(status_code=400, detail="no hop configuration")
            
            hop_cmd = f'ssh -o StrictHostKeyChecking=no {hop_config["username"]}@{target_node} "{get_fd_cmd}"'
            stdin, stdout, stderr = client.exec_command(hop_cmd, timeout=10)
        else:
            # Execute on bastion host
            print(f"[JOBS VIEW OUTPUT] Executing on bastion host")
            stdin, stdout, stderr = client.exec_command(get_fd_cmd, timeout=10)
        
        # Get the file path
        file_path = stdout.read().decode().strip()
        error_output = stderr.read().decode().strip()
        
        if not file_path or error_output:
            return {
                "success": False,
                "error": f"Could not find {stream} file for PID {pid}",
                "details": error_output or "No file descriptor found",
                "pid": pid,
                "stream": stream
            }
        
        # Check if it's a regular file (not terminal, pipe, socket)
        if any(pattern in file_path for pattern in ["/dev/", "socket:", "pipe:", "[", "]"]):
            return {
                "success": False,
                "error": f"PID {pid} {stream} is not redirected to a file",
                "details": f"{stream} points to: {file_path}",
                "pid": pid,
                "stream": stream
            }
        
        # Now read the file content (tail -n lines)
        read_cmd = f'tail -n {lines} "{file_path}" 2>/dev/null'
        
        if target_node and target_node != "bastion":
            hop_cmd = f'ssh -o StrictHostKeyChecking=no {hop_config["username"]}@{target_node} "{read_cmd}"'
            stdin, stdout, stderr = client.exec_command(hop_cmd, timeout=15)
        else:
            stdin, stdout, stderr = client.exec_command(read_cmd, timeout=15)
        
        content = stdout.read().decode()
        read_error = stderr.read().decode().strip()
        
        if read_error:
            return {
                "success": False,
                "error": f"Could not read {stream} file",
                "details": read_error,
                "file_path": file_path,
                "pid": pid,
                "stream": stream
            }
        
        # Get file size for additional info
        stat_cmd = f'stat -c "%s" "{file_path}" 2>/dev/null'
        if target_node and target_node != "bastion":
            hop_cmd = f'ssh -o StrictHostKeyChecking=no {hop_config["username"]}@{target_node} "{stat_cmd}"'
            stdin, stdout, stderr = client.exec_command(hop_cmd, timeout=10)
        else:
            stdin, stdout, stderr = client.exec_command(stat_cmd, timeout=10)
        
        file_size_str = stdout.read().decode().strip()
        file_size = int(file_size_str) if file_size_str.isdigit() else 0
        
        return {
            "success": True,
            "pid": pid,
            "stream": stream,
            "file_path": file_path,
            "file_size_bytes": file_size,
            "lines_requested": lines,
            "content": content,
            "content_length": len(content),
            "target_node": target_node or "bastion"
        }
        
    except Exception as e:
        print(f"[JOBS VIEW OUTPUT] Exception: {str(e)}")
        return {
            "success": False,
            "error": f"Failed to view {stream} for PID {pid}",
            "details": str(e),
            "pid": pid,
            "stream": stream,
            "target_node": target_node or "bastion"
        }


@app.get("/api/jobs/discover-processes")
async def api_jobs_discover_processes(
    user_id: str, 
    target_node: Optional[str] = None
):
    """Discover all processes with file-redirected stdout/stderr (including nohup jobs)."""
    print(f"[JOBS DISCOVER] Request: user_id={user_id}, target_node={target_node}")
    
    conn = connections.get(user_id)
    if not conn:
        print(f"[JOBS DISCOVER] Error: No connection found for user_id={user_id}")
        raise HTTPException(status_code=404, detail="no session for user_id")
    
    client = conn.get("ssh_client")
    if not isinstance(client, paramiko.SSHClient):
        print(f"[JOBS DISCOVER] Error: SSH not connected for user_id={user_id}")
        raise HTTPException(status_code=400, detail="ssh not connected")
    
    # Use the exact command you provided to discover processes
    discover_cmd = '''
for d in /proc/[0-9]*/fd; do
  pid=${d%/fd}; pid=${pid#/proc/}
  out=$(readlink "$d/1" 2>/dev/null)
  err=$(readlink "$d/2" 2>/dev/null)
  # Skip terminals, pipes, sockets, etc.
  if [[ "$out$err" =~ /dev/|socket:|pipe:|\\[.*\\] ]]; then continue; fi
  # If either fd1 or fd2 points to a regular file, print it
  if [ -n "$out" ] || [ -n "$err" ]; then
    ps -p "$pid" -o pid,ppid,tty,stat,stime,cmd --no-headers 2>/dev/null
    printf "STDOUT_FD1:%s\\n" "${out:-NONE}"
    printf "STDERR_FD2:%s\\n" "${err:-NONE}"
    echo "---END_PROCESS---"
  fi
done
'''
    
    try:
        print(f"[JOBS DISCOVER] Executing command on target_node={target_node}")
        if target_node and target_node != "bastion":
            # Execute on target node via SSH hop
            hop_config = conn.get("hop_config", {})
            if not hop_config:
                raise HTTPException(status_code=400, detail="no hop configuration")
            
            hop_cmd = f'ssh -o StrictHostKeyChecking=no {hop_config["username"]}@{target_node} \'{discover_cmd}\''
            stdin, stdout, stderr = client.exec_command(hop_cmd, timeout=30)
        else:
            # Execute on bastion host
            print(f"[JOBS DISCOVER] Executing on bastion host")
            stdin, stdout, stderr = client.exec_command(discover_cmd, timeout=30)
        
        output = stdout.read().decode()
        error_output = stderr.read().decode().strip()
        
        if error_output:
            print(f"[JOBS DISCOVER] Command stderr: {error_output}")
        
        # Parse the output
        processes = []
        current_process = {}
        
        for line in output.split('\n'):
            line = line.strip()
            if not line:
                continue
            
            if line == "---END_PROCESS---":
                if current_process:
                    processes.append(current_process)
                    current_process = {}
            elif line.startswith("STDOUT_FD1:"):
                current_process["stdout_file"] = line[11:] if line[11:] != "NONE" else None
            elif line.startswith("STDERR_FD2:"):
                current_process["stderr_file"] = line[11:] if line[11:] != "NONE" else None
            else:
                # This should be the ps output line
                parts = line.split(None, 5)  # Split into max 6 parts
                if len(parts) >= 6:
                    current_process.update({
                        "pid": int(parts[0]),
                        "ppid": int(parts[1]),
                        "tty": parts[2],
                        "stat": parts[3], 
                        "stime": parts[4],
                        "cmd": parts[5]
                    })
        
        # Add the last process if exists
        if current_process:
            processes.append(current_process)
        
        return {
            "success": True,
            "processes_found": len(processes),
            "processes": processes,
            "target_node": target_node or "bastion"
        }
        
    except Exception as e:
        print(f"[JOBS DISCOVER] Exception: {str(e)}")
        return {
            "success": False,
            "error": "Failed to discover processes",
            "details": str(e),
            "target_node": target_node or "bastion"
        }


# Convenience endpoint to view output of a discovered process
@app.get("/api/jobs/quick-view")
async def api_jobs_quick_view(
    user_id: str,
    pid: int,
    target_node: Optional[str] = None,
    lines: int = Query(default=50, description="Number of lines to show")
):
    """Quick view of both stdout and stderr for a process."""
    print(f"[JOBS QUICK VIEW] Request: user_id={user_id}, pid={pid}, target_node={target_node}, lines={lines}")
    
    # Get both stdout and stderr
    stdout_result = await api_jobs_view_output(user_id, pid, target_node, lines, "stdout")
    stderr_result = await api_jobs_view_output(user_id, pid, target_node, lines, "stderr")
    
    return {
        "pid": pid,
        "target_node": target_node or "bastion",
        "stdout": stdout_result,
        "stderr": stderr_result
    }


# Updated GPU Health endpoint using the new SSH helper
@app.get("/api/health/gpu")
async def api_gpu_health_updated(user_id: str, target_node: Optional[str] = None):
    """Get GPU health status with improved SSH logic."""
    print(f"[GPU_HEALTH] Request: user_id={user_id}, target_node={target_node}")
    
    conn = connections.get(user_id)
    if not conn:
        raise HTTPException(status_code=404, detail="no session for user_id")
    
    client = conn.get("ssh_client")
    if not isinstance(client, paramiko.SSHClient):
        raise HTTPException(status_code=400, detail="SSH not connected")
    
    try:
        # Get hop configuration
        hop_config = conn.get("ssh_hop_config", {})
        
        print(f"[GPU_HEALTH] Getting GPU info from {target_node or 'bastion'}")
        
        # Execute nvidia-smi command
        nvidia_cmd = "nvidia-smi --query-gpu=index,name,temperature.gpu,utilization.gpu,memory.used,memory.total,power.draw --format=csv,noheader,nounits"
        
        result = await execute_command_with_hop(
            client=client,
            command=nvidia_cmd,
            target_node=target_node,
            hop_config=hop_config,
            timeout=15
        )
        
        if not result["success"]:
            print(f"[GPU_HEALTH] nvidia-smi failed: {result.get('error', 'Unknown error')}")
            return {
                "error": result.get("error", "Failed to execute nvidia-smi"),
                "details": result,
                "gpus": [],
                "target_node": target_node or "bastion"
            }
        
        # Parse nvidia-smi output
        gpus = []
        stdout = result["stdout"]
        
        if not stdout.strip():
            return {
                "error": "nvidia-smi returned empty output",
                "details": result,
                "gpus": [],
                "target_node": target_node or "bastion"
            }
        
        for line in stdout.strip().split('\n'):
            if not line.strip():
                continue
                
            try:
                parts = [p.strip() for p in line.split(',')]
                if len(parts) >= 7:
                    gpu_info = {
                        "index": int(parts[0]),
                        "name": parts[1],
                        "temperature": int(parts[2]) if parts[2].isdigit() else 0,
                        "utilization": int(parts[3]) if parts[3].isdigit() else 0,
                        "memory_used": int(parts[4]) if parts[4].isdigit() else 0,
                        "memory_total": int(parts[5]) if parts[5].isdigit() else 0,
                        "power_draw": float(parts[6]) if parts[6].replace('.', '').isdigit() else 0.0
                    }
                    gpus.append(gpu_info)
            except (ValueError, IndexError) as e:
                print(f"[GPU_HEALTH] Failed to parse GPU line '{line}': {e}")
                continue
        
        return {
            "gpus": gpus,
            "execution_details": result,
            "target_node": target_node or "bastion"
        }
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return {
            "error": str(e),
            "gpus": [],
            "target_node": target_node or "bastion"
        }


# Update the existing job view output endpoint to use the new helper
async def api_jobs_view_output_updated(
    user_id: str, 
    pid: int, 
    target_node: Optional[str] = None,
    lines: int = Query(default=100, description="Number of lines to show from end of file"),
    stream: str = Query(default="stdout", description="stdout or stderr")
):
    """View stdout or stderr of a running process by PID using improved SSH logic."""
    print(f"[JOBS VIEW OUTPUT] Request: user_id={user_id}, pid={pid}, target_node={target_node}, lines={lines}, stream={stream}")
    
    conn = connections.get(user_id)
    if not conn:
        print(f"[JOBS VIEW OUTPUT] Error: No connection found for user_id={user_id}")
        raise HTTPException(status_code=404, detail="no session for user_id")
    
    client = conn.get("ssh_client")
    if not isinstance(client, paramiko.SSHClient):
        print(f"[JOBS VIEW OUTPUT] Error: SSH not connected for user_id={user_id}")
        raise HTTPException(status_code=400, detail="ssh not connected")
    
    try:
        # Get hop configuration
        hop_config = conn.get("ssh_hop_config", {})
        
        # First, get the file descriptor path for the specified stream
        fd_num = "1" if stream == "stdout" else "2"
        get_fd_cmd = f'readlink /proc/{pid}/fd/{fd_num} 2>/dev/null'
        
        result = await execute_command_with_hop(
            client=client,
            command=get_fd_cmd,
            target_node=target_node,
            hop_config=hop_config,
            timeout=10
        )
        
        if not result["success"] or not result["stdout"].strip():
            return {
                "success": False,
                "error": f"Could not find {stream} file for PID {pid}",
                "details": result.get("error", "No file descriptor found"),
                "pid": pid,
                "stream": stream
            }
        
        file_path = result["stdout"].strip()
        
        # Check if it's a regular file (not terminal, pipe, socket)
        if any(pattern in file_path for pattern in ["/dev/", "socket:", "pipe:", "[", "]"]):
            return {
                "success": False,
                "error": f"PID {pid} {stream} is not redirected to a file",
                "details": f"{stream} points to: {file_path}",
                "pid": pid,
                "stream": stream
            }
        
        # Now read the file content (tail -n lines)
        read_cmd = f'tail -n {lines} "{file_path}" 2>/dev/null'
        
        read_result = await execute_command_with_hop(
            client=client,
            command=read_cmd,
            target_node=target_node,
            hop_config=hop_config,
            timeout=15
        )
        
        if not read_result["success"]:
            return {
                "success": False,
                "error": f"Could not read {stream} file",
                "details": read_result.get("error", "Read command failed"),
                "file_path": file_path,
                "pid": pid,
                "stream": stream
            }
        
        # Get file size for additional info
        stat_cmd = f'stat -c "%s" "{file_path}" 2>/dev/null'
        stat_result = await execute_command_with_hop(
            client=client,
            command=stat_cmd,
            target_node=target_node,
            hop_config=hop_config,
            timeout=10
        )
        
        file_size = 0
        if stat_result["success"] and stat_result["stdout"].strip().isdigit():
            file_size = int(stat_result["stdout"].strip())
        
        return {
            "success": True,
            "pid": pid,
            "stream": stream,
            "file_path": file_path,
            "file_size_bytes": file_size,
            "lines_requested": lines,
            "content": read_result["stdout"],
            "content_length": len(read_result["stdout"]),
            "target_node": target_node or "bastion",
            "execution_details": {
                "fd_lookup": result,
                "file_read": read_result,
                "file_stat": stat_result
            }
        }
        
    except Exception as e:
        print(f"[JOBS VIEW OUTPUT] Exception: {str(e)}")
        return {
            "success": False,
            "error": f"Failed to view {stream} for PID {pid}",
            "details": str(e),
            "pid": pid,
            "stream": stream,
            "target_node": target_node or "bastion"
        }


async def api_jobs_discover_processes_updated(
    user_id: str, 
    target_node: Optional[str] = None
):
    """Discover all processes with file-redirected stdout/stderr using improved SSH logic."""
    print(f"[JOBS DISCOVER] Request: user_id={user_id}, target_node={target_node}")
    
    conn = connections.get(user_id)
    if not conn:
        print(f"[JOBS DISCOVER] Error: No connection found for user_id={user_id}")
        raise HTTPException(status_code=404, detail="no session for user_id")
    
    client = conn.get("ssh_client")
    if not isinstance(client, paramiko.SSHClient):
        print(f"[JOBS DISCOVER] Error: SSH not connected for user_id={user_id}")
        raise HTTPException(status_code=400, detail="ssh not connected")
    
    # Use the exact command you provided to discover processes
    discover_cmd = '''
for d in /proc/[0-9]*/fd; do
  pid=${d%/fd}; pid=${pid#/proc/}
  out=$(readlink "$d/1" 2>/dev/null)
  err=$(readlink "$d/2" 2>/dev/null)
  # Skip terminals, pipes, sockets, etc.
  if [[ "$out$err" =~ /dev/|socket:|pipe:|\\[.*\\] ]]; then continue; fi
  # If either fd1 or fd2 points to a regular file, print it
  if [ -n "$out" ] || [ -n "$err" ]; then
    ps -p "$pid" -o pid,ppid,tty,stat,stime,cmd --no-headers 2>/dev/null
    printf "STDOUT_FD1:%s\\n" "${out:-NONE}"
    printf "STDERR_FD2:%s\\n" "${err:-NONE}"
    echo "---END_PROCESS---"
  fi
done
'''
    
    try:
        # Get hop configuration
        hop_config = conn.get("ssh_hop_config", {})
        
        result = await execute_command_with_hop(
            client=client,
            command=discover_cmd,
            target_node=target_node,
            hop_config=hop_config,
            timeout=30
        )
        
        if not result["success"]:
            return {
                "success": False,
                "error": "Failed to discover processes",
                "details": result,
                "target_node": target_node or "bastion"
            }
        
        # Parse the output
        processes = []
        current_process = {}
        
        for line in result["stdout"].split('\n'):
            line = line.strip()
            if not line:
                continue
            
            if line == "---END_PROCESS---":
                if current_process:
                    processes.append(current_process)
                    current_process = {}
            elif line.startswith("STDOUT_FD1:"):
                current_process["stdout_file"] = line[11:] if line[11:] != "NONE" else None
            elif line.startswith("STDERR_FD2:"):
                current_process["stderr_file"] = line[11:] if line[11:] != "NONE" else None
            else:
                # This should be the ps output line
                parts = line.split(None, 5)  # Split into max 6 parts
                if len(parts) >= 6:
                    current_process.update({
                        "pid": int(parts[0]),
                        "ppid": int(parts[1]),
                        "tty": parts[2],
                        "stat": parts[3], 
                        "stime": parts[4],
                        "cmd": parts[5]
                    })
        
        # Add the last process if exists
        if current_process:
            processes.append(current_process)
        
        return {
            "success": True,
            "processes_found": len(processes),
            "processes": processes,
            "target_node": target_node or "bastion",
            "execution_details": result
        }
        
    except Exception as e:
        print(f"[JOBS DISCOVER] Exception: {str(e)}")
        return {
            "success": False,
            "error": "Failed to discover processes",
            "details": str(e),
            "target_node": target_node or "bastion"
        }


# Updated endpoint routes using improved SSH logic
@app.get("/api/health/gpu-v2")
async def api_gpu_health_v2(user_id: str, target_node: Optional[str] = None):
    """Get GPU health status with improved SSH logic (v2)."""
    return await api_gpu_health_updated(user_id, target_node)

@app.get("/api/jobs/view-output-v2")
async def api_jobs_view_output_v2(
    user_id: str, 
    pid: int, 
    target_node: Optional[str] = None,
    lines: int = Query(default=100, description="Number of lines to show from end of file"),
    stream: str = Query(default="stdout", description="stdout or stderr")
):
    """View stdout or stderr of a running process by PID (v2 with improved SSH)."""
    return await api_jobs_view_output_updated(user_id, pid, target_node, lines, stream)

@app.get("/api/jobs/discover-processes-v2")
async def api_jobs_discover_processes_v2(user_id: str, target_node: Optional[str] = None):
    """Discover all processes with file-redirected stdout/stderr (v2 with improved SSH)."""
    return await api_jobs_discover_processes_updated(user_id, target_node)

@app.get("/api/jobs/quick-view-v2")
async def api_jobs_quick_view_v2(
    user_id: str,
    pid: int,
    target_node: Optional[str] = None,
    lines: int = Query(default=50, description="Number of lines to show")
):
    """Quick view of both stdout and stderr for a process (v2 with improved SSH)."""
    print(f"[JOBS QUICK VIEW V2] Request: user_id={user_id}, pid={pid}, target_node={target_node}, lines={lines}")
    
    # Get both stdout and stderr using the updated functions
    stdout_result = await api_jobs_view_output_updated(user_id, pid, target_node, lines, "stdout")
    stderr_result = await api_jobs_view_output_updated(user_id, pid, target_node, lines, "stderr")
    
    return {
        "pid": pid,
        "target_node": target_node or "bastion",
        "stdout": stdout_result,
        "stderr": stderr_result
    }

