"""Tool definitions and implementations for the agent."""
import logging
import shlex
from typing import Any, Dict, List
from docker_utils import exec_in_container

logger = logging.getLogger("vigilink.tools")


# Tool definitions in JSON Schema format for LLM
TOOL_DEFINITIONS = [
    {
        "name": "read_file",
        "description": "Read the contents of a file from the remote SSH server or container",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Absolute or relative path to the file to read"
                }
            },
            "required": ["path"]
        }
    },
    {
        "name": "write_file",
        "description": "Write content to a file on the remote SSH server or container. Creates the file if it doesn't exist.",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Absolute or relative path to the file to write"
                },
                "content": {
                    "type": "string",
                    "description": "Content to write to the file"
                }
            },
            "required": ["path", "content"]
        }
    },
    {
        "name": "run_command",
        "description": "Execute a shell command on the remote SSH server or container",
        "parameters": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "Shell command to execute"
                }
            },
            "required": ["command"]
        }
    },
    {
        "name": "edit_file",
        "description": "Replace a specific section of code in a file. Use this for precise edits like changing variable names, updating indentation, or modifying small blocks without rewriting the entire file.",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Absolute or relative path to the file"
                },
                "target": {
                    "type": "string",
                    "description": "The exact code block to replace. Must match the file content exactly, including whitespace and indentation."
                },
                "replacement": {
                    "type": "string",
                    "description": "The new code block to insert in place of the target."
                }
            },
            "required": ["path", "target", "replacement"]
        }
    },
    {
        "name": "list_files",
        "description": "List files and directories in a specified path",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to list files from (defaults to current directory)"
                }
            },
            "required": []
        }
    },
    {
        "name": "find_files",
        "description": "Search for files matching a pattern recursively",
        "parameters": {
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Glob pattern or filename to search for"
                },
                "path": {
                    "type": "string",
                    "description": "Starting path for search (defaults to home directory)"
                }
            },
            "required": ["pattern"]
        }
    }
]


class ToolExecutor:
    """Executes tools for the agent using ssh_manager."""
    
    def __init__(self, container_id: str, session_id: str, send_to_ssh_manager_func):
        """Initialize tool executor.
        
        Args:
            container_id: Docker container ID for VPN/SSH access
            session_id: SSH session ID
            send_to_ssh_manager_func: Function to send commands to ssh_manager
        """
        self.container_id = container_id
        self.session_id = session_id
        self.send_to_ssh_manager = send_to_ssh_manager_func
    
    def execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a tool and return the result.
        
        Args:
            tool_name: Name of the tool to execute
            arguments: Tool arguments
            
        Returns:
            Dict with 'success' (bool) and 'result' (str) or 'error' (str)
        """
        try:
            if tool_name == "read_file":
                return self._read_file(arguments["path"])
            elif tool_name == "write_file":
                return self._write_file(arguments["path"], arguments["content"])
            elif tool_name == "edit_file":
                return self._edit_file(arguments["path"], arguments["target"], arguments["replacement"])
            elif tool_name == "run_command":
                return self._run_command(arguments["command"])
            elif tool_name == "list_files":
                return self._list_files(arguments.get("path", "."))
            elif tool_name == "find_files":
                return self._find_files(arguments["pattern"], arguments.get("path", "~"))
            else:
                return {"success": False, "error": f"Unknown tool: {tool_name}"}
        except Exception as e:
            logger.error(f"Tool execution error ({tool_name}): {e}")
            return {"success": False, "error": str(e)}
    
    def _read_file(self, path: str) -> Dict[str, Any]:
        """Read file contents."""
        try:
            # Use cat to read file (more reliable than dd for full reads)
            read_cmd = f"cat {shlex.quote(path)} 2>/dev/null"
            
            result = self.send_to_ssh_manager(self.container_id, {
                "command": "execute",
                "session_id": self.session_id,
                "cmd": read_cmd,
                "timeout": 10
            }, 12)
            
            if not result.get("success"):
                return {"success": False, "error": result.get("error", "Failed to read file")}
            
            if result.get("exit_code", 0) != 0:
                return {"success": False, "error": f"File not found or not readable: {path}"}
            
            content = result.get("stdout", "")
            return {"success": True, "result": content}
            
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _edit_file(self, path: str, target: str, replacement: str) -> Dict[str, Any]:
        """Replace target text with replacement text in file."""
        try:
            # 1. Read the file first
            read_result = self._read_file(path)
            if not read_result["success"]:
                return read_result
            
            content = read_result["result"]
            
            # 2. Check if target exists
            if target not in content:
                # Try to be helpful if it's a whitespace issue
                if target.strip() in content:
                    return {"success": False, "error": "Target text found but whitespace didn't match exactly. Please check indentation."}
                return {"success": False, "error": "Target text not found in file. Please read the file again to ensure you have the exact content."}
            
            # 3. Perform replacement
            # Only replace the first occurrence to be safe, or maybe all? 
            # Usually agents intend to replace a specific block. 
            # If there are duplicates, it might be ambiguous. 
            # Let's count occurrences.
            count = content.count(target)
            if count > 1:
                return {"success": False, "error": f"Target text found {count} times. Please provide more context in the target string to make it unique."}
            
            new_content = content.replace(target, replacement)
            
            # 4. Write back
            return self._write_file(path, new_content)
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _write_file(self, path: str, content: str) -> Dict[str, Any]:
        """Write content to file."""
        try:
            # Escape content for shell - use base64 to avoid escaping issues
            import base64
            content_b64 = base64.b64encode(content.encode('utf-8')).decode('ascii')
            
            # Decode base64 and write to file
            write_cmd = f"echo {content_b64} | base64 -d > {shlex.quote(path)}"
            
            result = self.send_to_ssh_manager(self.container_id, {
                "command": "execute",
                "session_id": self.session_id,
                "cmd": write_cmd,
                "timeout": 10
            }, 12)
            
            if not result.get("success"):
                return {"success": False, "error": result.get("error", "Failed to write file")}
            
            if result.get("exit_code", 0) != 0:
                stderr = result.get("stderr", "")
                return {"success": False, "error": f"Failed to write file: {stderr}"}
            
            return {"success": True, "result": f"Successfully wrote to {path}"}
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _run_command(self, command: str) -> Dict[str, Any]:
        """Execute shell command."""
        try:
            result = self.send_to_ssh_manager(self.container_id, {
                "command": "execute",
                "session_id": self.session_id,
                "cmd": command,
                "timeout": 30
            }, 35)
            
            if not result.get("success"):
                return {"success": False, "error": result.get("error", "Command execution failed")}
            
            stdout = result.get("stdout", "")
            stderr = result.get("stderr", "")
            exit_code = result.get("exit_code", 0)
            
            output = f"Exit code: {exit_code}\n"
            if stdout:
                output += f"Output:\n{stdout}\n"
            if stderr:
                output += f"Errors:\n{stderr}\n"
            
            return {"success": True, "result": output.strip()}
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _list_files(self, path: str) -> Dict[str, Any]:
        """List files in directory."""
        try:
            list_cmd = f"ls -lAh --time-style='+%Y-%m-%d %H:%M' {shlex.quote(path)} 2>/dev/null || ls -lA {shlex.quote(path)}"
            
            result = self.send_to_ssh_manager(self.container_id, {
                "command": "execute",
                "session_id": self.session_id,
                "cmd": list_cmd,
                "timeout": 10
            }, 12)
            
            if not result.get("success"):
                return {"success": False, "error": result.get("error", "Failed to list files")}
            
            if result.get("exit_code", 0) != 0:
                return {"success": False, "error": f"Directory not found: {path}"}
            
            output = result.get("stdout", "")
            return {"success": True, "result": output}
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _find_files(self, pattern: str, path: str) -> Dict[str, Any]:
        """Find files matching pattern."""
        try:
            # Use find with -name for glob patterns
            find_cmd = f"find {shlex.quote(path)} -name {shlex.quote(pattern)} 2>/dev/null | head -50"
            
            result = self.send_to_ssh_manager(self.container_id, {
                "command": "execute",
                "session_id": self.session_id,
                "cmd": find_cmd,
                "timeout": 20
            }, 25)
            
            if not result.get("success"):
                return {"success": False, "error": result.get("error", "Search failed")}
            
            output = result.get("stdout", "").strip()
            if not output:
                return {"success": True, "result": "No files found matching pattern"}
            
            return {"success": True, "result": output}
            
        except Exception as e:
            return {"success": False, "error": str(e)}
