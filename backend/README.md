# Vigilink Backend - Mobile-First Cluster Access MVP

A FastAPI-based backend providing per-user VPN connections and **multiple SSH sessions per user** through isolated Docker containers. Designed for mobile-first access to remote clusters with file browsing, terminal commands, and GPU monitoring.

## Architecture Overview

```
backend/
├── app.py              # FastAPI application (orchestrator & endpoints)
├── schemas.py          # Pydantic request/response models
├── docker_utils.py     # Docker container lifecycle & VPN helpers
├── ssh_utils.py        # Paramiko SSH client wrapper
├── persistence.py      # Connection state persistence
├── middleware.py       # Request ID middleware
├── Dockerfile          # Prebuilt container image with VPN/SSH/sshpass tools
└── requirements.txt    # Python dependencies
```

### Key Design Decisions

- **Per-user Docker containers**: Each VPN session creates an isolated Debian container with NET_ADMIN capabilities
- **Multiple SSH sessions per user**: Support up to 5 concurrent SSH connections per user via `session_id`
- **Channel-based command execution**: Reuses existing SSH connections, opens new channels per command (lowest latency)
- **No reconnection overhead**: One TCP+SSH handshake per session, cheap channels per command
- **Container lifecycle**: Containers created on `/vpn/connect`, removed on `/vpn/disconnect`
- **Prebuilt image**: Tools (openconnect, openssh-client, sshpass, iproute2) baked into `vigilink-backend:latest`
- **In-memory sessions**: SSH clients stored in memory with session metadata

## Prerequisites

- **Docker**: Docker daemon must be running and accessible via CLI
- **Python 3.8+**: For FastAPI backend
- **Paramiko** (optional): For SSH functionality (`pip install paramiko`)

## Setup & Installation

### 1. Build the Docker Image

The backend uses a prebuilt Docker image with all VPN/SSH tools installed. Build it once:

**PowerShell:**
```powershell
# From the backend/ directory
docker build -t vigilink-backend:latest .
```

**Git Bash:**
```bash
# From the backend/ directory
docker build -t vigilink-backend:latest .
```

### 2. Install Python Dependencies

**PowerShell:**
```powershell
# Create virtual environment (optional but recommended)
python -m venv venv
venv\Scripts\Activate.ps1

# Install dependencies
pip install fastapi uvicorn paramiko
# Or: pip install -r requirements.txt
```

**Git Bash:**
```bash
# Create virtual environment (optional but recommended)
python -m venv venv
source venv/Scripts/activate  # Windows Git Bash
# or: source venv/bin/activate  # Linux/Mac

# Install dependencies
pip install fastapi uvicorn paramiko
# Or: pip install -r requirements.txt
```

### 3. Start the Server

**PowerShell:**
```powershell
# From the repository root (parent of backend/)
uvicorn backend.app:app --host 0.0.0.0 --port 8000 --reload
```

**Git Bash:**
```bash
# From the repository root (parent of backend/)
uvicorn backend.app:app --host 0.0.0.0 --port 8000 --reload
```

Server will start at `http://localhost:8000`

## API Reference

Base URL: `http://localhost:8000`

### Health Check

**GET** `/healthz`

Check if the backend is running.

**PowerShell:**
```powershell
curl http://localhost:8000/healthz
```

**Git Bash:**
```bash
curl http://localhost:8000/healthz
```

**Response:**
```json
{"status": "ok"}
```

---

### VPN Management

#### Connect to VPN

**POST** `/vpn/connect`

Creates a Docker container for the user and optionally starts openconnect VPN inside it.

**Request Body:**
```json
{
  "user_id": "alice",
  "vpn_url": "vpn.example.com",
  "username": "alice",
  "password": "secret123",
  "real": true
}
```

**Parameters:**
- `user_id` (required): Unique user identifier
- `vpn_url` (required if `real=true`): VPN server URL
- `username` (optional): VPN username
- `password` (optional): VPN password
- `real` (default: false): If true, starts actual openconnect VPN connection

**PowerShell:**
```powershell
curl -X POST http://localhost:8000/vpn/connect `
  -H "Content-Type: application/json" `
  -d '{\"user_id\":\"debarpanb\",\"vpn_url\":\"vpn.iisc.ac.in\",\"username\":\"debarpanb@iisc.ac.in\",\"password\":\"supsay@1998\",\"real\":true}'
```

**Git Bash:**
```bash
curl -X POST http://localhost:8000/vpn/connect \
  -H "Content-Type: application/json" \
  -d '{"user_id":"debarpanb","vpn_url":"vpn.iisc.ac.in","username":"debarpanb@iisc.ac.in","password":"supsay@1998","real":true}'
```

**Response:**
```json
{
  "status": "started",
  "user_id": "alice",
  "container_id": "abc123def456"
}
```

**Errors:**
- `400`: Missing required fields or invalid parameters
- `429`: Too many connection attempts (rate limited)
- `500`: Docker unavailable, container creation failed, or VPN connection failed

#### Get VPN Status

**GET** `/vpn/status?user_id=alice`

Check if a user's VPN container is running.

**PowerShell:**
```powershell
curl "http://localhost:8000/vpn/status?user_id=alice"
```

**Git Bash:**
```bash
curl "http://localhost:8000/vpn/status?user_id=alice"
```

**Response:**
```json
{
  "connected": true,
  "container_id": "abc123def456"
}
```

**Errors:**
- `404`: No VPN session found for user

#### Disconnect VPN

**POST** `/vpn/disconnect?user_id=alice`

Stops and removes the user's Docker container.

**PowerShell:**
```powershell
curl -X POST "http://localhost:8000/vpn/disconnect?user_id=alice"
```

**Git Bash:**
```bash
curl -X POST "http://localhost:8000/vpn/disconnect?user_id=alice"
```

**Response:**
```json
{
  "status": "stopped"
}
```

**Errors:**
- `404`: No VPN session found for user

---

### SSH Management

#### Connect via SSH

**POST** `/ssh/connect?session_id=default`

Establishes a paramiko SSH connection to a remote host. Supports **multiple sessions per user** via `session_id` (up to 5 concurrent sessions). Each session maintains a persistent SSH connection that reuses channels for commands (lowest latency).

**Query Parameters:**
- `session_id` (optional, default: `"default"`): Unique identifier for this SSH session. Use different IDs to maintain multiple concurrent connections (e.g., `clusterA`, `clusterB`, `bastion`).

**Request Body:**
```json
{
  "user_id": "alice",
  "hostname": "cluster.example.com",
  "username": "alice",
  "password": "password123",
  "port": 22
}
```

**Parameters:**
- `user_id` (required): Unique user identifier
- `hostname` (required): SSH server hostname or IP
- `username` (required): SSH username
- `password` (required): SSH password
- `port` (default: 22): SSH port

**PowerShell:**
```powershell
# Default session
curl -X POST "http://localhost:8000/ssh/connect?session_id=default" `
  -H "Content-Type: application/json" `
  -d '{\"user_id\":\"alice\",\"hostname\":\"cluster.example.com\",\"username\":\"alice\",\"password\":\"password123\"}'

# Multiple sessions example
curl -X POST "http://localhost:8000/ssh/connect?session_id=clusterA" `
  -H "Content-Type: application/json" `
  -d '{\"user_id\":\"alice\",\"hostname\":\"10.64.1.1\",\"username\":\"alice\",\"password\":\"pass1\"}'

curl -X POST "http://localhost:8000/ssh/connect?session_id=clusterB" `
  -H "Content-Type: application/json" `
  -d '{\"user_id\":\"alice\",\"hostname\":\"10.64.2.1\",\"username\":\"alice\",\"password\":\"pass2\"}'
```

**Git Bash:**
```bash
# Default session
curl -X POST "http://localhost:8000/ssh/connect?session_id=default" \
  -H "Content-Type: application/json" \
  -d '{"user_id":"alice","hostname":"cluster.example.com","username":"alice","password":"password123"}'

# Multiple sessions example
curl -X POST "http://localhost:8000/ssh/connect?session_id=clusterA" \
  -H "Content-Type: application/json" \
  -d '{"user_id":"alice","hostname":"10.64.1.1","username":"alice","password":"pass1"}'

curl -X POST "http://localhost:8000/ssh/connect?session_id=clusterB" \
  -H "Content-Type: application/json" \
  -d '{"user_id":"alice","hostname":"10.64.2.1","username":"alice","password":"pass2"}'
```

**Response:**
```json
{
  "connected": true,
  "user_id": "alice",
  "session_id": "default",
  "hostname": "cluster.example.com",
  "port": 22
}
```

**Errors:**
- `400`: Missing required fields
- `502`: Paramiko not installed or SSH connection failed

#### Get SSH Status

**GET** `/ssh/status?user_id=alice`

Check status of all SSH sessions for a user.

**PowerShell:**
```powershell
curl "http://localhost:8000/ssh/status?user_id=alice"
```

**Git Bash:**
```bash
curl "http://localhost:8000/ssh/status?user_id=alice"
```

**Response:**
```json
{
  "connected": true,
  "user_id": "alice",
  "count": 2,
  "sessions": [
    {
      "session_id": "clusterA",
      "hostname": "10.64.1.1",
      "username": "alice",
      "port": 22,
      "active": true,
      "connected_at": 1700000000.0
    },
    {
      "session_id": "clusterB",
      "hostname": "10.64.2.1",
      "username": "alice",
      "port": 22,
      "active": true,
      "connected_at": 1700000010.0
    }
  ]
}
```

**Errors:**
- None (returns empty sessions list if no connections)

#### Disconnect SSH

**POST** `/ssh/disconnect?user_id=alice&session_id=default`

Closes a specific SSH session.

**Query Parameters:**
- `user_id` (required): User identifier
- `session_id` (optional, default: `"default"`): Session identifier to disconnect

**PowerShell:**
```powershell
# Disconnect specific session
curl -X POST "http://localhost:8000/ssh/disconnect?user_id=alice&session_id=clusterA"

# Disconnect default session
curl -X POST "http://localhost:8000/ssh/disconnect?user_id=alice"
```

**Git Bash:**
```bash
# Disconnect specific session
curl -X POST "http://localhost:8000/ssh/disconnect?user_id=alice&session_id=clusterA"

# Disconnect default session
curl -X POST "http://localhost:8000/ssh/disconnect?user_id=alice"
```

**Response:**
```json
{
  "disconnected": true,
  "user_id": "alice",
  "session_id": "clusterA"
}
```

**Errors:**
- `404`: No SSH sessions for user or session_id not found

---

### Terminal Commands

#### Run Terminal Command

**POST** `/api/terminal/bastion/run`

Executes a shell command. Prefers running inside the user's VPN container if available, falls back to SSH connection, or runs locally as last resort.

**Request Body:**
```json
{
  "user_id": "alice",
  "command": "hostname",
  "timeout": 30
}
```

**Parameters:**
- `user_id` (required): Unique user identifier
- `command` (required): Shell command to execute
- `timeout` (default: 30): Command timeout in seconds

**Example:**
```powershell
curl -X POST http://localhost:8000/api/terminal/bastion/run `
  -H "Content-Type: application/json" `
  -d '{\"user_id\":\"alice\",\"command\":\"hostname\",\"timeout\":10}'
```

**Response:**
```json
{
  "stdout": "my-container-hostname\n",
  "stderr": "",
  "exit_code": 0,
  "container_id": "abc123def456"
}
```

**Errors:**
- `400`: Missing required fields
- `404`: No active session (VPN or SSH) for user

---

### File System Operations

#### List Directory

**GET** `/api/fs/list?user_id=alice&path=/home/alice`

Lists files in a directory. Uses `ls` inside container if VPN connected, or SFTP if SSH connected.

**Parameters:**
- `user_id` (required): Unique user identifier
- `path` (optional, default: `.`): Directory path to list

**Example:**
```powershell
curl "http://localhost:8000/api/fs/list?user_id=alice&path=/home/alice"
```

**Response:**
```json
{
  "path": "/home/alice",
  "entries": [
    {"name": ".", "size": 4096, "mode": "drwxr-xr-x"},
    {"name": "..", "size": 4096, "mode": "drwxr-xr-x"},
    {"name": "file.txt", "size": 1024, "mode": "-rw-r--r--"}
  ]
}
```

**Errors:**
- `400`: No SSH connection available
- `404`: No active session for user
- `500`: Failed to list directory

#### Read File

**GET** `/api/fs/read?user_id=alice&path=/home/alice/file.txt&offset=0&length=1024`

Reads a file or file slice. Uses `dd` inside container if VPN connected, or SFTP if SSH connected.

**Parameters:**
- `user_id` (required): Unique user identifier
- `path` (required): File path to read
- `offset` (optional, default: 0): Byte offset to start reading
- `length` (optional, default: 65536): Number of bytes to read

**Example:**
```powershell
curl "http://localhost:8000/api/fs/read?user_id=alice&path=/home/alice/file.txt&offset=0&length=100"
```

**Response:**
```json
{
  "path": "/home/alice/file.txt",
  "offset": 0,
  "data": "Hello, world!\nThis is the file content..."
}
```

**Errors:**
- `400`: Missing path parameter or no SSH connection
- `404`: No active session for user

---

## Testing the Endpoints

### Complete Workflow Example

```powershell
# 1. Check server health
curl http://localhost:8000/healthz

# 2. Connect to VPN (creates container, starts openconnect)
curl -X POST http://localhost:8000/vpn/connect `
  -H "Content-Type: application/json" `
  -d '{\"user_id\":\"testuser\",\"vpn_url\":\"vpn.example.com\",\"username\":\"testuser\",\"password\":\"pass123\",\"real\":true}'

# 3. Check VPN status
curl "http://localhost:8000/vpn/status?user_id=testuser"

# 4. Run a command inside the container
curl -X POST http://localhost:8000/api/terminal/bastion/run `
  -H "Content-Type: application/json" `
  -d '{\"user_id\":\"testuser\",\"command\":\"ip addr show\",\"timeout\":10}'

# 5. List files in container
curl "http://localhost:8000/api/fs/list?user_id=testuser&path=/etc"

# 6. Read a file
curl "http://localhost:8000/api/fs/read?user_id=testuser&path=/etc/hostname"

# 7. Disconnect VPN (removes container)
curl -X POST "http://localhost:8000/vpn/disconnect?user_id=testuser"
```

### SSH-Only Workflow (no VPN)

```powershell
# 1. Connect via SSH
curl -X POST http://localhost:8000/ssh/connect `
  -H "Content-Type: application/json" `
  -d '{\"user_id\":\"sshuser\",\"hostname\":\"remote.example.com\",\"username\":\"sshuser\",\"password\":\"sshpass\"}'

# 2. Run command via SSH
curl -X POST http://localhost:8000/api/terminal/bastion/run `
  -H "Content-Type: application/json" `
  -d '{\"user_id\":\"sshuser\",\"command\":\"uptime\"}'

# 3. Browse files via SFTP
curl "http://localhost:8000/api/fs/list?user_id=sshuser&path=/var/log"

# 4. Disconnect SSH
curl -X POST "http://localhost:8000/ssh/disconnect?user_id=sshuser"
```

---

## Error Handling

All endpoints return standard HTTP status codes with JSON error details:

- **200**: Success
- **400**: Bad request (missing or invalid parameters)
- **404**: Resource not found (no session for user)
- **429**: Rate limited (too many VPN connection attempts)
- **500**: Internal server error (Docker, VPN, or SSH failure)
- **502**: Bad gateway (SSH connection failed)

**Example Error Response:**
```json
{
  "detail": "Container creation failed: Docker image 'vigilink-backend:latest' not found. Build it with: docker build -t vigilink-backend:latest backend/"
}
```

---

## Configuration

### Environment Variables

Currently all configuration is hardcoded. Future versions may support:

- `DOCKER_IMAGE`: Container image name (default: `vigilink-backend:latest`)
- `VPN_COOLDOWN_SECONDS`: Rate limit for VPN connects (default: 10)
- `CONTAINER_TIMEOUT`: Max container lifetime

### Persistence

Connection metadata is persisted to `.vigilink_conns.json` in the backend directory. This file is loaded on startup and saved on shutdown. Contains:

- `container_id`: Active container ID per user
- `container_started_at`: Container creation timestamp
- `ssh_hop_config`: SSH connection metadata (if applicable)

**Note**: SSH client objects and live connections are NOT persisted (only metadata).

---

## Security Considerations

### ⚠️ Important Security Notes

1. **Privileged Containers**: Containers run with `--privileged`, `--cap-add=NET_ADMIN`, and `/dev/net/tun` access to support VPN. This is a security trade-off for the MVP.

2. **CORS**: Currently allows all origins (`allow_origins=["*"]`). Restrict this in production.

3. **Authentication**: No user authentication implemented. The `user_id` is trusted. Add auth middleware in production.

4. **Password Storage**: Passwords are not persisted, but are passed in plaintext via API. Use HTTPS in production.

5. **Rate Limiting**: Basic per-user VPN connect cooldown (10s). Consider more robust rate limiting.

### Recommendations for Production

- Use a reverse proxy (nginx, Traefik) with HTTPS
- Implement proper authentication (JWT, OAuth2)
- Restrict container capabilities (avoid `--privileged` if possible)
- Use secrets management for VPN/SSH credentials
- Implement request validation and sanitization
- Add audit logging for all connections
- Set resource limits on containers (CPU, memory)

---

## Troubleshooting

### "Docker image not found"

**Error:** `Container creation failed: Docker image 'vigilink-backend:latest' not found`

**Solution:** Build the Docker image:
```powershell
cd backend
docker build -t vigilink-backend:latest .
```

### "Docker is not available"

**Error:** `Docker is not available. Ensure Docker daemon is running.`

**Solution:** 
- Start Docker Desktop (Windows/Mac)
- Or start Docker daemon: `sudo systemctl start docker` (Linux)
- Verify: `docker ps`

### "OpenConnect did not start"

**Error:** `OpenConnect process failed to start. Check VPN credentials and server URL.`

**Possible Causes:**
- Invalid VPN URL, username, or password
- VPN server is unreachable
- Network issues inside container

**Debugging:**
```powershell
# Check container logs
docker logs <container_id>

# Exec into container
docker exec -it <container_id> sh

# View openconnect logs
cat /tmp/openconnect.log
```

### "Paramiko not installed"

**Error:** `Paramiko library not installed. Install with: pip install paramiko`

**Solution:**
```powershell
pip install paramiko
```

### Container cleanup

If containers are not removed properly:

```powershell
# List all vigilink containers
docker ps -a | grep vigilink

# Remove all vigilink containers
docker rm -f $(docker ps -aq -f name=vigilink)
```

---

## Development

### Running Tests

(Tests not yet implemented)

```powershell
pytest backend/tests/
```

### Code Structure

- **app.py**: FastAPI app initialization, CORS, middleware registration, and all endpoint definitions
- **schemas.py**: Pydantic models for request validation
- **docker_utils.py**: Docker CLI wrappers for container lifecycle and openconnect startup
- **ssh_utils.py**: Paramiko client builder with key/password support
- **persistence.py**: JSON-based connection state persistence
- **middleware.py**: Request ID middleware for logging/tracing

### Adding New Endpoints

1. Define request/response schemas in `schemas.py`
2. Implement business logic in appropriate utility module
3. Add endpoint handler in `app.py` with proper error handling
4. Update this README with API documentation

---

## License

(Add your license here)

## Contributors

(Add contributors here)
