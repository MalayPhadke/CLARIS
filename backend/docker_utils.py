"""Docker helper utilities used by the backend.

Provides container lifecycle, exec-in-container and helper to start openconnect inside
the container. These are thin wrappers around the docker CLI to keep the MVP simple.

VPN DISABLED (2026-02-10): OpenConnect VPN functionality has been disabled since the
backend is now deployed on the same network as HPC clusters. The run_openconnect_in_container
function is kept but disabled for potential future use.
"""
from __future__ import annotations

import shlex
import shutil
import subprocess
import time
import uuid
from typing import Tuple
import logging

logger = logging.getLogger("vigilink.backend.docker_utils")


def _safe_name(s: str) -> str:
    return "vigilink_" + "".join([c if c.isalnum() or c in "-_" else "_" for c in s])[:64]


def docker_available() -> bool:
    return shutil.which("docker") is not None


def find_user_container(user_id: str) -> str | None:
    """Find existing container for user.
    
    Args:
        user_id: Unique user identifier
    
    Returns:
        Container ID if found and running, None otherwise
    """
    if not docker_available():
        return None
    
    # List all containers (running and stopped) with label matching user
    proc = subprocess.run(
        ["docker", "ps", "-a", "--filter", f"label=vigilink.user_id={user_id}", "--format", "{{.ID}}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    if proc.returncode == 0 and proc.stdout.strip():
        container_id = proc.stdout.strip().split('\n')[0]  # Get first match
        # Check if it's running
        if container_is_running(container_id):
            logger.info("Found existing running container %s for user %s", container_id[:12], user_id)
            return container_id
        else:
            # Container exists but not running - try to start it
            logger.info("Found stopped container %s for user %s, attempting to restart", container_id[:12], user_id)
            restart_proc = subprocess.run(
                ["docker", "start", container_id],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            if restart_proc.returncode == 0:
                logger.info("Restarted container %s for user %s", container_id[:12], user_id)
                return container_id
            else:
                logger.warning("Failed to restart container %s: %s", container_id[:12], restart_proc.stderr)
                # Remove broken container
                subprocess.run(["docker", "rm", "-f", container_id], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    return None


def create_container_for_user(user_id: str, image: str = "vigilink-backend:latest") -> str:
    """Create and start a detached container for the user, or reuse existing one.
    Uses the default CMD from the Dockerfile which starts ssh_manager daemon.
    
    Args:
        user_id: Unique user identifier
        image: Docker image to use (default: vigilink-backend:latest with preinstalled tools)
    
    Returns:
        Container ID string
    
    Raises:
        RuntimeError: If docker is unavailable or container creation fails
    """
    if not docker_available():
        raise RuntimeError("Docker CLI not found. Ensure Docker is installed and in PATH.")
    
    # Check for existing container first
    existing_id = find_user_container(user_id)
    if existing_id:
        return existing_id
    
    # Create new container
    name = _safe_name(user_id + "_" + str(uuid.uuid4())[:8])
    cmd = [
        "docker",
        "run",
        "-d",
        "--name",
        name,
        "--label",
        f"vigilink.user_id={user_id}",
        "--cap-add=NET_ADMIN",
        "--device=/dev/net/tun",
        "--privileged",
        image,
        # No command override - use Dockerfile CMD which starts ssh_manager daemon
    ]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if proc.returncode != 0:
        error_msg = proc.stderr.strip()
        logger.error("Failed to create container for user %s: %s", user_id, error_msg)
        if "image" in error_msg.lower() and "not found" in error_msg.lower():
            raise RuntimeError(f"Docker image '{image}' not found. Build it with: docker build -t {image} backend/")
        raise RuntimeError(f"Container creation failed: {error_msg}")
    container_id = proc.stdout.strip()
    if not container_id:
        raise RuntimeError("Docker returned empty container ID")
    logger.info("Created container %s for user %s with ssh_manager daemon", container_id[:12], user_id)
    return container_id


def remove_container(container_id: str) -> None:
    if not docker_available():
        return
    subprocess.run(["docker", "rm", "-f", container_id], stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def container_is_running(container_id: str) -> bool:
    if not docker_available():
        return False
    proc = subprocess.run(["docker", "ps", "-q", "-f", f"id={container_id}"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return bool(proc.stdout.strip())


def exec_in_container(container_id: str, command: str, timeout: int = 30) -> Tuple[str, str, int]:
    """Execute a command inside a running container.
    
    Args:
        container_id: Container ID
        command: Shell command to execute
        timeout: Command timeout in seconds
    
    Returns:
        Tuple of (stdout, stderr, exit_code)
    """
    cmd = ["docker", "exec", container_id, "sh", "-lc", command]
    try:
        # Add a small buffer to subprocess timeout to allow graceful handling
        cp = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout + 2)
        out = cp.stdout.decode("utf-8", errors="replace") if isinstance(cp.stdout, (bytes, bytearray)) else (cp.stdout or "")
        err = cp.stderr.decode("utf-8", errors="replace") if isinstance(cp.stderr, (bytes, bytearray)) else (cp.stderr or "")
        return out, err, cp.returncode
    except subprocess.TimeoutExpired:
        logger.warning("Command timed out after %ds in container %s", timeout, container_id[:12])
        # Try to kill any hanging processes
        try:
            subprocess.run(["docker", "exec", container_id, "pkill", "-9", "-f", "nc"], 
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=2)
        except:
            pass
        return "", f"Command execution exceeded {timeout}s timeout", 124
    except Exception as e:
        logger.error("Failed to exec in container %s: %s", container_id[:12], e)
        return "", f"Exec failed: {str(e)}", 1


def run_openconnect_in_container(container_id: str, vpn_url: str, username: str | None, password: str | None, protocol: str = "anyconnect") -> bool:
    """Start openconnect VPN inside the container.
    
    VPN DISABLED (2026-02-10): This function is disabled since the backend is now
    on the same network as HPC clusters. Returns True immediately without starting VPN.
    
    To re-enable VPN:
    1. Uncomment the VPN logic below
    2. Uncomment the import in app.py
    3. Update login endpoint to call this function
    
    Args:
        container_id: Container ID
        vpn_url: VPN server URL
        username: VPN username (optional)
        password: VPN password (optional)
        protocol: VPN protocol (default: anyconnect)
    
    Returns:
        True (VPN disabled - always returns success)
    
    Raises:
        RuntimeError: If openconnect fails to start (when enabled)
    """
    # VPN DISABLED - Return success immediately without starting VPN
    logger.info("VPN DISABLED: Skipping openconnect for container %s (local network access)", container_id[:12])
    return True
    
    # ============================================================================
    # VPN DISABLED - The following code is commented out for local network access
    # Uncomment to re-enable VPN functionality
    # ============================================================================
    # if not vpn_url:
    #     raise RuntimeError("VPN URL is required")
    # 
    # import base64
    # 
    # user_part = f"--user {shlex.quote(username)}" if username else ""
    # # Use base64 to avoid all shell escaping issues with password
    # b64_password = base64.b64encode((password or '').encode('utf-8')).decode('ascii')
    # # Simple approach: echo password and pipe to openconnect, run in background
    # cmd_str = f"nohup bash -c 'echo {b64_password} | base64 -d | openconnect {shlex.quote(vpn_url)} {user_part} --protocol {shlex.quote(protocol)} --passwd-on-stdin' >/tmp/openconnect.log 2>&1 &"
    # out, err, rc = exec_in_container(container_id, cmd_str, timeout=60)
    # if rc != 0:
    #     logger.error("Failed to launch openconnect in container %s: %s", container_id[:12], err)
    #     raise RuntimeError(f"OpenConnect launch failed: {err or 'unknown error'}")
    #
    # # Wait for openconnect process to appear (up to 10 seconds)
    # for i in range(10):
    #     out2, err2, rc2 = exec_in_container(container_id, "pgrep -f openconnect || true", timeout=5)
    #     if out2.strip():
    #         logger.info("OpenConnect started successfully in container %s (PID: %s)", container_id[:12], out2.strip())
    #         return True
    #     time.sleep(1)
    # 
    # # Fetch logs for debugging
    # log_out, _, _ = exec_in_container(container_id, "cat /tmp/openconnect.log 2>/dev/null || echo 'No log'", timeout=5)
    # logger.error("OpenConnect did not start within timeout. Log: %s", log_out[:500])
    # raise RuntimeError(f"OpenConnect process did not start. Check credentials and server. Log: {log_out[:200]}")
    # ============================================================================
    # END VPN DISABLED SECTION
    # ============================================================================
