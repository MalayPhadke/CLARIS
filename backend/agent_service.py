"""Agent session management and persistence."""
import asyncio
import json
import logging
import os
import time
from typing import Any, Dict, List, Optional
from pathlib import Path

from llm import LLMClient
from tools import TOOL_DEFINITIONS, ToolExecutor

logger = logging.getLogger("vigilink.agent")

# Persistence file
AGENT_SESSIONS_FILE = "agent_sessions.json"


class AgentSession:
    """Manages a single agent conversation session."""
    
    def __init__(
        self, 
        session_id: str, 
        user_id: str, 
        container_id: str, 
        ssh_session_id: str,
        send_to_ssh_manager_func
    ):
        """Initialize agent session.
        
        Args:
            session_id: Unique session identifier
            user_id: User ID from authentication
            container_id: Docker container ID
            ssh_session_id: SSH session ID for remote access
            send_to_ssh_manager_func: Function to communicate with ssh_manager
        """
        self.session_id = session_id
        self.user_id = user_id
        self.container_id = container_id
        self.ssh_session_id = ssh_session_id
        self.send_to_ssh_manager = send_to_ssh_manager_func
        
        # Conversation state
        self.messages: List[Dict[str, str]] = []
        self.context_files: List[str] = []  # Files in context (for @ mentions)
        
        # Agent components
        self.llm = LLMClient()
        self.tool_executor = ToolExecutor(container_id, ssh_session_id, send_to_ssh_manager_func)
        
        # Background task state
        self.is_processing = False
        self.last_activity = time.time()
        
        # Add system prompt
        self.messages.append({
            "role": "system",
            "content": self._get_system_prompt()
        })
    
    def _get_system_prompt(self) -> str:
        """Generate system prompt for the agent."""
        return """You are a helpful AI assistant for a remote cluster/server environment. 
You have access to tools to read/write files, execute commands, list directories, and search for files.

When the user asks you to do something:
1. Use the appropriate tools to accomplish the task
2. Explain what you're doing in a clear, concise way
3. Show command outputs or file contents when relevant

Context files (added via @ mentions) are files the user wants you to focus on. 
When context files are present, prioritize them in your responses.

Be proactive and helpful. If you need more information, ask the user."""
    
    async def process_message(self, user_message: str) -> Dict[str, Any]:
        """Process a user message and return agent response.
        
        Args:
            user_message: Message from user
            
        Returns:
            Dict with 'content' (response text) and 'metadata' (optional)
        """
        self.is_processing = True
        self.last_activity = time.time()
        
        try:
            # Add user message to history
            self.messages.append({
                "role": "user",
                "content": user_message
            })
            
            # Add context files info if present
            if self.context_files:
                context_info = f"\n\n[Context files: {', '.join(self.context_files)}]"
                self.messages[-1]["content"] += context_info
            
            # Agent loop: LLM -> Tool Calls -> LLM (until done)
            max_iterations = 10
            iteration = 0
            
            while iteration < max_iterations:
                iteration += 1
                
                # Call LLM with tools
                response = self.llm.chat(
                    messages=self.messages,
                    tools=TOOL_DEFINITIONS,
                    temperature=0.7
                )
                
                # Check for tool calls
                tool_calls = response.get("tool_calls", [])
                
                if not tool_calls:
                    # No more tool calls, agent is done
                    assistant_message = response.get("content", "")
                    self.messages.append({
                        "role": "assistant",
                        "content": assistant_message
                    })
                    
                    return {
                        "content": assistant_message,
                        "metadata": {
                            "iterations": iteration,
                            "context_files": self.context_files
                        }
                    }
                
                # Execute tool calls
                tool_results = []
                for tool_call in tool_calls:
                    tool_name = tool_call["name"]
                    tool_args = tool_call["arguments"]
                    
                    logger.info(f"[agent] Executing tool: {tool_name} with args: {tool_args}")
                    
                    # Execute tool
                    result = self.tool_executor.execute_tool(tool_name, tool_args)
                    tool_results.append({
                        "tool": tool_name,
                        "result": result
                    })
                
                # Add tool results to conversation
                # Format: "Tool: <name>\nResult: <result>"
                tool_summary = "\n\n".join([
                    f"Tool: {tr['tool']}\n" + 
                    (f"Result: {tr['result']['result']}" if tr['result']['success'] 
                     else f"Error: {tr['result']['error']}")
                    for tr in tool_results
                ])
                
                self.messages.append({
                    "role": "assistant",
                    "content": f"[Tool executions]\n{tool_summary}"
                })
            
            # Max iterations reached
            error_msg = "Maximum iterations reached. Please try breaking down your request."
            self.messages.append({
                "role": "assistant",
                "content": error_msg
            })
            
            return {
                "content": error_msg,
                "metadata": {
                    "error": "max_iterations",
                    "iterations": iteration
                }
            }
            
        except Exception as e:
            logger.error(f"Agent processing error: {e}", exc_info=True)
            error_msg = f"An error occurred: {str(e)}"
            self.messages.append({
                "role": "assistant",
                "content": error_msg
            })
            return {
                "content": error_msg,
                "metadata": {"error": str(e)}
            }
        finally:
            self.is_processing = False
            self.last_activity = time.time()
    
    def add_context_file(self, file_path: str):
        """Add a file to the context."""
        if file_path not in self.context_files:
            self.context_files.append(file_path)
    
    def remove_context_file(self, file_path: str):
        """Remove a file from the context."""
        if file_path in self.context_files:
            self.context_files.remove(file_path)
    
    def get_history(self) -> List[Dict[str, str]]:
        """Get conversation history (excluding system message)."""
        return [msg for msg in self.messages if msg["role"] != "system"]
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize session to dict for persistence."""
        return {
            "session_id": self.session_id,
            "user_id": self.user_id,
            "container_id": self.container_id,
            "ssh_session_id": self.ssh_session_id,
            "messages": self.messages,
            "context_files": self.context_files,
            "last_activity": self.last_activity
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any], send_to_ssh_manager_func):
        """Restore session from dict."""
        session = cls(
            session_id=data["session_id"],
            user_id=data["user_id"],
            container_id=data["container_id"],
            ssh_session_id=data["ssh_session_id"],
            send_to_ssh_manager_func=send_to_ssh_manager_func
        )
        session.messages = data.get("messages", [])
        session.context_files = data.get("context_files", [])
        session.last_activity = data.get("last_activity", time.time())
        return session


class AgentManager:
    """Manages all agent sessions with persistence."""
    
    def __init__(self, send_to_ssh_manager_func):
        """Initialize agent manager.
        
        Args:
            send_to_ssh_manager_func: Function to communicate with ssh_manager
        """
        self.send_to_ssh_manager = send_to_ssh_manager_func
        self.sessions: Dict[str, AgentSession] = {}
        self._load_sessions()
    
    def get_or_create_session(
        self, 
        user_id: str, 
        container_id: str, 
        ssh_session_id: str
    ) -> AgentSession:
        """Get existing session or create new one.
        
        Args:
            user_id: User ID
            container_id: Docker container ID
            ssh_session_id: SSH session ID
            
        Returns:
            AgentSession instance
        """
        # Session key is user_id + ssh_session_id
        session_key = f"{user_id}:{ssh_session_id}"
        
        if session_key not in self.sessions:
            session = AgentSession(
                session_id=session_key,
                user_id=user_id,
                container_id=container_id,
                ssh_session_id=ssh_session_id,
                send_to_ssh_manager_func=self.send_to_ssh_manager
            )
            self.sessions[session_key] = session
            self._save_sessions()
        
        return self.sessions[session_key]
    
    def get_session(self, session_key: str) -> Optional[AgentSession]:
        """Get session by key."""
        return self.sessions.get(session_key)
    
    def _save_sessions(self):
        """Persist sessions to disk."""
        try:
            data = {
                key: session.to_dict()
                for key, session in self.sessions.items()
            }
            
            with open(AGENT_SESSIONS_FILE, 'w') as f:
                json.dump(data, f, indent=2)
            
            logger.info(f"Saved {len(self.sessions)} agent sessions")
        except Exception as e:
            logger.error(f"Failed to save agent sessions: {e}")
    
    def _load_sessions(self):
        """Load sessions from disk."""
        try:
            if not os.path.exists(AGENT_SESSIONS_FILE):
                logger.info("No saved agent sessions found")
                return
            
            with open(AGENT_SESSIONS_FILE, 'r') as f:
                data = json.load(f)
            
            for key, session_data in data.items():
                session = AgentSession.from_dict(session_data, self.send_to_ssh_manager)
                self.sessions[key] = session
            
            logger.info(f"Loaded {len(self.sessions)} agent sessions")
        except Exception as e:
            logger.error(f"Failed to load agent sessions: {e}")
    
    def cleanup_old_sessions(self, max_age_hours: int = 24):
        """Remove sessions older than max_age_hours."""
        now = time.time()
        max_age_seconds = max_age_hours * 3600
        
        old_keys = [
            key for key, session in self.sessions.items()
            if now - session.last_activity > max_age_seconds
        ]
        
        for key in old_keys:
            del self.sessions[key]
            logger.info(f"Cleaned up old session: {key}")
        
        if old_keys:
            self._save_sessions()
