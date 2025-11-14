#!/usr/bin/env python3
"""
SSH Manager - Runs inside VPN container to manage persistent Paramiko SSH connections.
Accepts JSON commands via stdin, returns JSON results via stdout.
This script maintains persistent SSHClient instances and uses channel-based execution.
"""

import sys
import json
import paramiko
import traceback
from typing import Dict, Any

# Global storage for SSH clients keyed by session_id
ssh_clients: Dict[str, Dict[str, Any]] = {}


def connect_ssh(session_id: str, hostname: str, username: str, password: str, port: int = 22, timeout: int = 10) -> Dict[str, Any]:
    """Create a new persistent SSH connection."""
    try:
        if session_id in ssh_clients:
            return {"success": False, "error": f"Session {session_id} already exists"}
        
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        client.connect(
            hostname=hostname,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            allow_agent=False,
            look_for_keys=False
        )
        
        # Store client and metadata
        ssh_clients[session_id] = {
            "client": client,
            "hostname": hostname,
            "username": username,
            "port": port
        }
        
        return {
            "success": True,
            "session_id": session_id,
            "hostname": hostname,
            "username": username,
            "port": port
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "traceback": traceback.format_exc()
        }


def disconnect_ssh(session_id: str) -> Dict[str, Any]:
    """Close a persistent SSH connection."""
    try:
        if session_id not in ssh_clients:
            return {"success": False, "error": f"Session {session_id} not found"}
        
        client_info = ssh_clients[session_id]
        client = client_info["client"]
        client.close()
        
        del ssh_clients[session_id]
        
        return {
            "success": True,
            "session_id": session_id,
            "message": "SSH connection closed"
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "traceback": traceback.format_exc()
        }


def execute_command(session_id: str, command: str, timeout: int = 30) -> Dict[str, Any]:
    """Execute command on existing SSH connection using channel-based execution."""
    try:
        if session_id not in ssh_clients:
            return {"success": False, "error": f"Session {session_id} not found"}
        
        client_info = ssh_clients[session_id]
        client = client_info["client"]
        
        # Channel-based execution - opens new channel on existing connection
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        
        exit_code = stdout.channel.recv_exit_status()
        output = stdout.read().decode('utf-8', errors='replace')
        error = stderr.read().decode('utf-8', errors='replace')
        
        return {
            "success": True,
            "exit_code": exit_code,
            "stdout": output,
            "stderr": error
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "traceback": traceback.format_exc()
        }


def list_sessions() -> Dict[str, Any]:
    """List all active SSH sessions."""
    sessions = []
    for session_id, info in ssh_clients.items():
        sessions.append({
            "session_id": session_id,
            "hostname": info["hostname"],
            "username": info["username"],
            "port": info["port"]
        })
    return {
        "success": True,
        "sessions": sessions
    }


def main():
    """Main loop - TCP socket server listening on port 9999."""
    import socket
    
    host = '0.0.0.0'
    port = 9999
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(5)
    
    print(f"SSH Manager listening on {host}:{port}", file=sys.stderr, flush=True)
    
    while True:
        try:
            client_socket, addr = server_socket.accept()
            print(f"Connection from {addr}", file=sys.stderr, flush=True)
            
            # Read request
            data = client_socket.recv(16384).decode('utf-8')
            if not data:
                client_socket.close()
                continue
            
            request = json.loads(data)
            command = request.get("command")
            
            if command == "connect":
                result = connect_ssh(
                    session_id=request["session_id"],
                    hostname=request["hostname"],
                    username=request["username"],
                    password=request["password"],
                    port=request.get("port", 22),
                    timeout=request.get("timeout", 10)
                )
            elif command == "disconnect":
                result = disconnect_ssh(session_id=request["session_id"])
            elif command == "execute":
                result = execute_command(
                    session_id=request["session_id"],
                    command=request["cmd"],
                    timeout=request.get("timeout", 30)
                )
            elif command == "list":
                result = list_sessions()
            elif command == "exit":
                # Close all connections before exiting
                for session_id in list(ssh_clients.keys()):
                    disconnect_ssh(session_id)
                result = {"success": True, "message": "Exiting"}
                client_socket.sendall((json.dumps(result) + '\n').encode('utf-8'))
                client_socket.close()
                break
            else:
                result = {"success": False, "error": f"Unknown command: {command}"}
            
            # Send response
            response = json.dumps(result) + '\n'
            client_socket.sendall(response.encode('utf-8'))
            client_socket.close()
            
        except json.JSONDecodeError as e:
            error_result = {"success": False, "error": f"Invalid JSON: {str(e)}"}
            try:
                client_socket.sendall((json.dumps(error_result) + '\n').encode('utf-8'))
            except:
                pass
            client_socket.close()
        except Exception as e:
            error_result = {
                "success": False,
                "error": str(e),
                "traceback": traceback.format_exc()
            }
            print(f"Error: {e}", file=sys.stderr, flush=True)
            try:
                client_socket.sendall((json.dumps(error_result) + '\n').encode('utf-8'))
            except:
                pass
            try:
                client_socket.close()
            except:
                pass


if __name__ == "__main__":
    main()
