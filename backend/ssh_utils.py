"""SSH helper utilities (paramiko wrapper and mock client)."""
from __future__ import annotations

import io
import logging
from typing import Optional

logger = logging.getLogger("vigilink.backend.ssh_utils")

try:
    import paramiko  # type: ignore
    HAS_PARAMIKO = True
except Exception:
    paramiko = None  # type: ignore
    HAS_PARAMIKO = False


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
) -> "paramiko.SSHClient":
    """Build and connect a paramiko SSH client.
    
    Args:
        ssh_ip: SSH server hostname or IP
        ssh_user: SSH username
        password: SSH password (optional)
        timeout: Connection timeout in seconds
        port: SSH port (default 22)
        allow_agent: Allow SSH agent authentication
        look_for_keys: Look for SSH keys in ~/.ssh
        pkey_path: Path to private key file
        pkey_data: Private key data as string
        pkey_type: Private key type (ed25519, ecdsa, rsa)
    
    Returns:
        Connected paramiko.SSHClient
    
    Raises:
        RuntimeError: If paramiko is not available or connection fails
    """
    if not HAS_PARAMIKO or paramiko is None:
        raise RuntimeError("paramiko not available")

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
            banner_timeout=timeout,  # Prevent hanging on SSH banner
        )
        # Set default timeout on the transport to prevent operations from hanging
        transport = client.get_transport()
        if transport:
            transport.set_keepalive(30)  # Send keepalive every 30s
            # Set socket timeout to prevent indefinite blocking
            sock = transport.sock
            if sock:
                sock.settimeout(timeout)
    except Exception:
        try:
            client.close()
        except Exception:
            pass
        raise
    return client
