#!/usr/bin/env python3
"""
SSH Manager - Runs inside VPN container to manage persistent Paramiko SSH connections.
Accepts JSON commands via stdin, returns JSON results via stdout.
This script maintains persistent SSHClient instances and uses channel-based execution.
Supports interactive PTY shells for real-time terminal sessions.
"""

import sys
import json
import paramiko
import traceback
import select
from typing import Dict, Any

# Global storage for SSH clients and interactive channels keyed by session_id
ssh_clients: Dict[str, Dict[str, Any]] = {}
shell_channels: Dict[str, paramiko.Channel] = {}


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


def check_status(session_id: str) -> Dict[str, Any]:
    """Check if a specific SSH session is still connected."""
    try:
        if session_id not in ssh_clients:
            return {
                "success": True,
                "connected": False,
                "error": f"Session {session_id} not found"
            }
        
        client_info = ssh_clients[session_id]
        client = client_info["client"]
        
        # Check if transport is active
        transport = client.get_transport()
        is_connected = transport is not None and transport.is_active()
        
        return {
            "success": True,
            "connected": is_connected,
            "session_id": session_id,
            "hostname": client_info["hostname"],
            "username": client_info["username"]
        }
    except Exception as e:
        return {
            "success": False,
            "connected": False,
            "error": str(e),
            "traceback": traceback.format_exc()
        }


def start_shell(session_id: str, rows: int = 24, cols: int = 80) -> Dict[str, Any]:
    """Start an interactive PTY shell session."""
    try:
        if session_id not in ssh_clients:
            return {"success": False, "error": f"Session {session_id} not found"}
        
        if session_id in shell_channels:
            return {"success": False, "error": f"Shell already active for session {session_id}"}
        
        client_info = ssh_clients[session_id]
        client = client_info["client"]
        
        # Request a PTY and invoke shell
        channel = client.invoke_shell(term='xterm-256color', width=cols, height=rows)
        channel.setblocking(0)  # Non-blocking mode for reading
        
        shell_channels[session_id] = channel
        
        return {
            "success": True,
            "session_id": session_id,
            "message": "Interactive shell started"
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "traceback": traceback.format_exc()
        }


def shell_input(session_id: str, data: str) -> Dict[str, Any]:
    """Send input to the interactive shell and return any immediate output."""
    try:
        if session_id not in shell_channels:
            return {"success": False, "error": f"No active shell for session {session_id}"}
        
        channel = shell_channels[session_id]
        
        # Send input to shell
        channel.send(data)
        
        # Read any immediate output (non-blocking with short timeout)
        output = ""
        if channel.recv_ready():
            # Read available data (up to 64KB)
            output = channel.recv(65536).decode('utf-8', errors='replace')
        
        return {
            "success": True,
            "output": output
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "traceback": traceback.format_exc()
        }


def shell_read(session_id: str) -> Dict[str, Any]:
    """Read any pending output from the shell (non-blocking)."""
    try:
        if session_id not in shell_channels:
            return {"success": False, "error": f"No active shell for session {session_id}"}
        
        channel = shell_channels[session_id]
        output = ""
        
        # Check if data is available
        if channel.recv_ready():
            output = channel.recv(65536).decode('utf-8', errors='replace')
        
        return {
            "success": True,
            "output": output
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "traceback": traceback.format_exc()
        }


def shell_resize(session_id: str, rows: int, cols: int) -> Dict[str, Any]:
    """Resize the PTY terminal."""
    try:
        if session_id not in shell_channels:
            return {"success": False, "error": f"No active shell for session {session_id}"}
        
        channel = shell_channels[session_id]
        channel.resize_pty(width=cols, height=rows)
        
        return {
            "success": True,
            "rows": rows,
            "cols": cols
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "traceback": traceback.format_exc()
        }


def stop_shell(session_id: str) -> Dict[str, Any]:
    """Stop the interactive shell session."""
    try:
        if session_id not in shell_channels:
            return {"success": True, "message": "No active shell to stop"}
        
        channel = shell_channels[session_id]
        channel.close()
        del shell_channels[session_id]
        
        return {
            "success": True,
            "session_id": session_id,
            "message": "Shell stopped"
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



import threading
import socketserver

# Global lock for thread safety
state_lock = threading.Lock()

class ThreadedTCPRequestHandler(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            # Read request
            data = self.request.recv(16384).decode('utf-8')
            if not data:
                return
            
            request = json.loads(data)
            command = request.get("command")
            
            result = {"success": False, "error": "Unknown command"}
            
            if command == "connect":
                # 1. Check if session exists (Lock)
                with state_lock:
                    if request["session_id"] in ssh_clients:
                        result = {"success": False, "error": f"Session {request['session_id']} already exists"}
                        self._send_response(result)
                        return

                # 2. Connect (No Lock - Slow Network I/O)
                # We create a temporary client instance
                try:
                    client = paramiko.SSHClient()
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    client.connect(
                        hostname=request["hostname"],
                        port=request.get("port", 22),
                        username=request["username"],
                        password=request["password"],
                        timeout=request.get("timeout", 10),
                        allow_agent=False,
                        look_for_keys=False
                    )
                    
                    # 3. Store session (Lock)
                    with state_lock:
                        # Check again to prevent race condition
                        if request["session_id"] in ssh_clients:
                            client.close()
                            result = {"success": False, "error": f"Session {request['session_id']} already exists (race)"}
                        else:
                            ssh_clients[request["session_id"]] = {
                                "client": client,
                                "hostname": request["hostname"],
                                "username": request["username"],
                                "port": request.get("port", 22)
                            }
                            result = {
                                "success": True,
                                "session_id": request["session_id"],
                                "hostname": request["hostname"],
                                "username": request["username"],
                                "port": request.get("port", 22)
                            }
                except Exception as e:
                    result = {"success": False, "error": str(e), "traceback": traceback.format_exc()}

            elif command == "disconnect":
                # 1. Remove from dict (Lock)
                client_to_close = None
                with state_lock:
                    if request["session_id"] in ssh_clients:
                        client_to_close = ssh_clients.pop(request["session_id"])
                        # Also remove associated shell if any
                        if request["session_id"] in shell_channels:
                            shell_channels.pop(request["session_id"])
                
                # 2. Close connection (No Lock)
                if client_to_close:
                    try:
                        client_to_close["client"].close()
                        result = {"success": True, "session_id": request["session_id"], "message": "SSH connection closed"}
                    except Exception as e:
                        result = {"success": False, "error": str(e)}
                else:
                    result = {"success": False, "error": f"Session {request['session_id']} not found"}

            elif command == "execute":
                # 1. Get client (Lock)
                client_info = None
                with state_lock:
                    if request["session_id"] in ssh_clients:
                        client_info = ssh_clients[request["session_id"]]
                
                # 2. Execute (No Lock)
                if client_info:
                    # Re-implement execute_command logic here to avoid global lock issues with helper function
                    # Or just call the helper function but ensure it doesn't use global dicts if we pass the client
                    # For safety, let's use the helper but we need to modify helper to take client object or just inline it.
                    # To minimize code changes, we'll just inline the logic or rely on the helper using the global dict 
                    # BUT the helper accesses the global dict. So we should probably modify the helper or inline.
                    # Let's inline for safety and clarity.
                    try:
                        client = client_info["client"]
                        stdin, stdout, stderr = client.exec_command(request["cmd"], timeout=request.get("timeout", 30))
                        exit_code = stdout.channel.recv_exit_status()
                        output = stdout.read().decode('utf-8', errors='replace')
                        error = stderr.read().decode('utf-8', errors='replace')
                        result = {"success": True, "exit_code": exit_code, "stdout": output, "stderr": error}
                    except Exception as e:
                        result = {"success": False, "error": str(e), "traceback": traceback.format_exc()}
                else:
                    result = {"success": False, "error": f"Session {request['session_id']} not found"}

            elif command == "status":
                # 1. Get client (Lock)
                client_info = None
                with state_lock:
                    if request["session_id"] in ssh_clients:
                        client_info = ssh_clients[request["session_id"]]
                
                # 2. Check status (No Lock)
                if client_info:
                    try:
                        transport = client_info["client"].get_transport()
                        is_connected = transport is not None and transport.is_active()
                        result = {
                            "success": True, 
                            "connected": is_connected, 
                            "session_id": request["session_id"],
                            "hostname": client_info["hostname"],
                            "username": client_info["username"]
                        }
                    except Exception as e:
                        result = {"success": False, "connected": False, "error": str(e)}
                else:
                    result = {"success": True, "connected": False, "error": f"Session {request['session_id']} not found"}

            elif command == "shell_start":
                # 1. Get client (Lock)
                client_info = None
                with state_lock:
                    if request["session_id"] in ssh_clients:
                        client_info = ssh_clients[request["session_id"]]
                        if request["session_id"] in shell_channels:
                            result = {"success": False, "error": f"Shell already active for session {request['session_id']}"}
                            client_info = None # Skip next step
                
                # 2. Start shell (No Lock)
                if client_info:
                    try:
                        channel = client_info["client"].invoke_shell(
                            term='xterm-256color', 
                            width=request.get("cols", 80), 
                            height=request.get("rows", 24)
                        )
                        channel.setblocking(0)
                        
                        # 3. Store channel (Lock)
                        with state_lock:
                            shell_channels[request["session_id"]] = channel
                        
                        result = {"success": True, "session_id": request["session_id"], "message": "Interactive shell started"}
                    except Exception as e:
                        result = {"success": False, "error": str(e)}

            elif command == "shell_input":
                # 1. Get channel (Lock)
                channel = None
                with state_lock:
                    if request["session_id"] in shell_channels:
                        channel = shell_channels[request["session_id"]]
                
                # 2. Send input (No Lock)
                if channel:
                    try:
                        channel.send(request.get("data", ""))
                        output = ""
                        if channel.recv_ready():
                            output = channel.recv(65536).decode('utf-8', errors='replace')
                        result = {"success": True, "output": output}
                    except Exception as e:
                        result = {"success": False, "error": str(e)}
                else:
                    result = {"success": False, "error": f"No active shell for session {request['session_id']}"}

            elif command == "shell_read":
                # 1. Get channel (Lock)
                channel = None
                with state_lock:
                    if request["session_id"] in shell_channels:
                        channel = shell_channels[request["session_id"]]
                
                # 2. Read (No Lock)
                if channel:
                    try:
                        output = ""
                        if channel.recv_ready():
                            output = channel.recv(65536).decode('utf-8', errors='replace')
                        result = {"success": True, "output": output}
                    except Exception as e:
                        result = {"success": False, "error": str(e)}
                else:
                    result = {"success": False, "error": f"No active shell for session {request['session_id']}"}

            elif command == "shell_resize":
                # 1. Get channel (Lock)
                channel = None
                with state_lock:
                    if request["session_id"] in shell_channels:
                        channel = shell_channels[request["session_id"]]
                
                # 2. Resize (No Lock)
                if channel:
                    try:
                        channel.resize_pty(width=request.get("cols", 80), height=request.get("rows", 24))
                        result = {"success": True, "rows": request.get("rows", 24), "cols": request.get("cols", 80)}
                    except Exception as e:
                        result = {"success": False, "error": str(e)}
                else:
                    result = {"success": False, "error": f"No active shell for session {request['session_id']}"}

            elif command == "shell_stop":
                # 1. Remove channel (Lock)
                channel_to_close = None
                with state_lock:
                    if request["session_id"] in shell_channels:
                        channel_to_close = shell_channels.pop(request["session_id"])
                
                # 2. Close (No Lock)
                if channel_to_close:
                    try:
                        channel_to_close.close()
                        result = {"success": True, "session_id": request["session_id"], "message": "Shell stopped"}
                    except Exception as e:
                        result = {"success": False, "error": str(e)}
                else:
                    result = {"success": True, "message": "No active shell to stop"}

            elif command == "list":
                with state_lock:
                    result = list_sessions()

            elif command == "exit":
                with state_lock:
                    for session_id in list(ssh_clients.keys()):
                        try:
                            ssh_clients[session_id]["client"].close()
                        except:
                            pass
                    ssh_clients.clear()
                    shell_channels.clear()
                result = {"success": True, "message": "Exiting"}
                self._send_response(result)
                return

            else:
                result = {"success": False, "error": f"Unknown command: {command}"}
            
            self._send_response(result)
            
        except json.JSONDecodeError as e:
            self._send_response({"success": False, "error": f"Invalid JSON: {str(e)}"})
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr, flush=True)
            self._send_response({"success": False, "error": str(e), "traceback": traceback.format_exc()})

    def _send_response(self, result):
        try:
            response = json.dumps(result) + '\n'
            self.wfile.write(response.encode('utf-8'))
        except:
            pass

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

def main():
    """Main loop - TCP socket server listening on port 9999."""
    host = '0.0.0.0'
    port = 9999
    
    print(f"SSH Manager listening on {host}:{port} (Multi-threaded & Fine-grained Locking)", file=sys.stderr, flush=True)
    
    server = ThreadedTCPServer((host, port), ThreadedTCPRequestHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

if __name__ == "__main__":
    main()
