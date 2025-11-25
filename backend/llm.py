"""LLM wrapper for Google Gemini API with function calling support."""
import os
import logging
import time
from typing import Any, Dict, List, Optional
import google.generativeai as genai
from dotenv import load_dotenv

logger = logging.getLogger("vigilink.llm")

# Load environment variables
load_dotenv()

# Configure Gemini API
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)
    logger.info("Gemini API configured successfully")
else:
    logger.warning("⚠️  GEMINI_API_KEY not set. Agent will not function.")


class LLMClient:
    """Wrapper for Gemini API with function calling support."""
    
    def __init__(self, model_name: str = "gemini-2.5-pro"):
        """Initialize LLM client with specified model."""
        self.model_name = model_name
    
    def chat(
        self, 
        messages: List[Dict[str, str]], 
        tools: Optional[List[Dict[str, Any]]] = None,
        temperature: float = 0.7
    ) -> Dict[str, Any]:
        """Send chat request to Gemini API.
        
        Args:
            messages: List of message dicts with 'role' and 'content'
            tools: Optional list of tool definitions for function calling
            temperature: Temperature for response generation
            
        Returns:
            Dict with 'content' (str) and optional 'tool_calls' (list)
        """
        if not GEMINI_API_KEY:
            raise RuntimeError("Gemini API not configured. Set GEMINI_API_KEY environment variable.")
        
        try:
            # Extract system prompt
            system_instruction = None
            chat_messages = []
            
            for msg in messages:
                if msg["role"] == "system":
                    system_instruction = msg["content"]
                else:
                    role = "user" if msg["role"] == "user" else "model"
                    chat_messages.append({
                        "role": role,
                        "parts": [msg["content"]]
                    })
            
            # Initialize model with system instruction
            model = genai.GenerativeModel(
                self.model_name,
                system_instruction=system_instruction
            )
            
            # Configure generation
            generation_config = genai.types.GenerationConfig(
                temperature=temperature
            )
            
            # Convert tools if provided
            gemini_tools = None
            if tools:
                gemini_tools = self._convert_tools_to_gemini(tools)
            
            # Generate content
            # We pass the full history as contents
            response = model.generate_content(
                chat_messages,
                generation_config=generation_config,
                tools=gemini_tools
            )
            
            # Parse response
            result = {
                "content": "",
                "tool_calls": []
            }
            
            # Check for function calls
            if hasattr(response, 'candidates') and response.candidates:
                candidate = response.candidates[0]
                if hasattr(candidate, 'content') and candidate.content.parts:
                    for part in candidate.content.parts:
                        if hasattr(part, 'text') and part.text:
                            result["content"] += part.text
                        elif hasattr(part, 'function_call') and part.function_call:
                            # Extract function call
                            fc = part.function_call
                            result["tool_calls"].append({
                                "name": fc.name,
                                "arguments": dict(fc.args)
                            })
            
            # Fallback to text attribute if content is empty but text exists
            if not result["content"] and not result["tool_calls"] and hasattr(response, 'text'):
                try:
                    result["content"] = response.text
                except Exception:
                    pass # response.text might fail if blocked
            
            return result
            
        except Exception as e:
            logger.error(f"Gemini API error: {e}")
            raise
    
    def _convert_tools_to_gemini(self, tools: List[Dict[str, Any]]) -> List[Any]:
        """Convert tool definitions to Gemini format.
        
        Args:
            tools: List of tool dicts with 'name', 'description', 'parameters'
            
        Returns:
            List of Gemini tool definitions
        """
        gemini_tools = []
        
        for tool in tools:
            gemini_tools.append(
                genai.protos.Tool(
                    function_declarations=[
                        genai.protos.FunctionDeclaration(
                            name=tool["name"],
                            description=tool["description"],
                            parameters=genai.protos.Schema(
                                type=genai.protos.Type.OBJECT,
                                properties={
                                    k: genai.protos.Schema(
                                        type=self._get_schema_type(v.get("type", "string")),
                                        description=v.get("description", "")
                                    )
                                    for k, v in tool["parameters"].get("properties", {}).items()
                                },
                                required=tool["parameters"].get("required", [])
                            )
                        )
                    ]
                )
            )
        
        return gemini_tools
    
    def _get_schema_type(self, type_str: str) -> Any:
        """Convert JSON schema type to Gemini schema type."""
        type_map = {
            "string": genai.protos.Type.STRING,
            "number": genai.protos.Type.NUMBER,
            "integer": genai.protos.Type.INTEGER,
            "boolean": genai.protos.Type.BOOLEAN,
            "array": genai.protos.Type.ARRAY,
            "object": genai.protos.Type.OBJECT
        }
        return type_map.get(type_str.lower(), genai.protos.Type.STRING)
