# CLARIS - Cluster Access Remote Interface System

> **Status Checkpoint: 2026-02-10**  
> **VPN Functionality: DISABLED** (Backend deployed on local network with HPC clusters)  
> **Deployment: Tailscale Funnel** (Frontend at `/`, Backend API at `/api`)

---

## Overview

CLARIS is a mobile-first web application for accessing HPC clusters. It provides:
- **Web-based terminal access** to multiple HPC clusters
- **Persistent SSH sessions** managed inside Docker containers
- **File browsing** (local container and remote SSH)
- **GPU monitoring** for clusters with NVIDIA GPUs
- **AI Agent** for cluster operations assistance

## Architecture

```
┌─────────────────┐     ┌──────────────────────────────────────────────────────┐
│   Frontend      │     │                    Backend                          │
│   (React/Vite)  │────▶│   FastAPI + Docker Container per User               │
│   Port: 5173    │     │   Port: 8000                                        │
└─────────────────┘     └──────────────────────────────────────────────────────┘
                                           │
                                           ▼
                        ┌──────────────────────────────────────────────────────┐
                        │              Docker Container                         │
                        │  ┌─────────────────────────────────────────────────┐ │
                        │  │  ssh_manager.py (TCP socket on port 9999)       │ │
                        │  │  - Manages persistent Paramiko SSH connections  │ │
                        │  │  - Handles SSH session lifecycle                │ │
                        │  └─────────────────────────────────────────────────┘ │
                        │                        │                              │
                        │                        ▼                              │
                        │              HPC Clusters (SSH)                       │
                        │              - Cluster 1 (simple)                     │
                        │              - Cluster 2 (slurm)                      │
                        │              - Cluster 3 (bastion)                    │
                        └──────────────────────────────────────────────────────┘
```

## Current Status

### ✅ Working Features

| Feature | Status | Notes |
|---------|--------|-------|
| **Authentication** | ✅ Working | JWT-based, 30-day token lifetime |
| **Login** | ✅ Working | Username/password only (VPN URL removed from UI) |
| **Container Management** | ✅ Working | Per-user Docker containers with ssh_manager daemon |
| **SSH Connections** | ✅ Working | Direct SSH to clusters (no VPN tunnel) |
| **WebSocket Terminal** | ✅ Working | Real-time interactive terminal |
| **File Browser** | ✅ Working | Local container + remote SSH filesystem |
| **GPU Monitoring** | ✅ Working | nvidia-smi integration |
| **AI Agent** | ✅ Working | LLM-based assistant for cluster ops |
| **Session Persistence** | ✅ Working | Container reuse on reconnection |

### ⏸️ Disabled Features (VPN)

| Feature | Status | Notes |
|---------|--------|-------|
| **OpenConnect VPN** | ⏸️ Disabled | Backend now on local network |
| **VPN Server URL field** | ⏸️ Removed | Login simplified to username/password |
| **VPN Status endpoint** | ⏸️ Stub | Returns container status instead |

## Directory Structure

```
CLARIS/
├── backend/                 # FastAPI backend
│   ├── app.py              # Main application, API endpoints
│   ├── docker_utils.py     # Docker container management
│   ├── ssh_manager.py      # SSH connection daemon (runs in container)
│   ├── ssh_utils.py        # SSH helper functions
│   ├── agent_service.py    # AI Agent implementation
│   ├── llm.py              # LLM integration
│   ├── schemas.py          # Pydantic models
│   ├── persistence.py      # Session persistence
│   └── Dockerfile          # Container image definition
│
├── cluster-dash/           # React frontend
│   ├── src/
│   │   ├── pages/
│   │   │   ├── Login.tsx       # Login page (simplified)
│   │   │   ├── Clusters.tsx    # Cluster list
│   │   │   └── ClusterDetail.tsx # Cluster detail view
│   │   ├── components/
│   │   │   └── cluster/        # Cluster-specific components
│   │   └── lib/
│   │       ├── api.ts          # API client
│   │       ├── connection.tsx  # Connection context
│   │       └── auth.ts         # Auth helpers
│   └── package.json
│
├── build-image.sh          # Docker image build script
├── cleanup.sh              # Cleanup script for dev
└── STATUS_README.md        # This file
```

## API Endpoints

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/login` | Login with username/password, get JWT token |
| GET | `/auth/verify` | Verify JWT token |
| POST | `/auth/logout` | Logout (preserves container) |

### VPN (Disabled - Stubs)
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/vpn/connect` | *Disabled* - Creates container only |
| GET | `/vpn/status` | Returns container status |
| POST | `/vpn/disconnect` | Removes container |

### SSH
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/ssh/connect` | Create SSH session |
| GET | `/ssh/status` | Get SSH session status |
| POST | `/ssh/disconnect` | Close SSH session |
| POST | `/ssh/reconnect` | Reconnect existing session |

### Terminal & Commands
| Method | Endpoint | Description |
|--------|----------|-------------|
| WebSocket | `/terminal/ws` | Interactive terminal |
| POST | `/api/terminal/bastion/run` | Execute command |

### File System
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/remote/fs/list` | List remote directory |
| GET | `/api/remote/fs/read` | Read remote file |
| GET | `/api/container/fs/list` | List container directory |

### GPU & Agent
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/gpu/info` | Get GPU information |
| POST | `/agent/message` | Send message to AI agent |

## How to Run

### Prerequisites
- Docker installed and running
- Python 3.11+ with virtual environment
- Node.js/Bun for frontend
- Tailscale installed (for remote access)

### Backend
```bash
cd backend

# Build Docker image (required for container-based SSH)
cd .. && ./build-image.sh && cd backend

# Activate virtual environment
source ./venv/bin/activate  # or create one first

   # Install dependencies (includes websockets support)
   pip install -r requirements.txt

# Start server
uvicorn app:app --host 0.0.0.0 --port 8000 --reload
```

### Frontend
```bash
cd cluster-dash

# Install dependencies
bun install  # or npm install

# Start dev server (port 8001 for Tailscale)
bun dev  # or npm run dev
```

### Tailscale Funnel Deployment

For remote access via Tailscale Funnel:

```bash
# Serve frontend at root path (/)
tailscale serve https:443 / http://localhost:8001

# Serve backend API at /api path
tailscale serve https:443 /api http://localhost:8000

# Enable public funnel access
tailscale funnel 443 on
```

This setup:
- Frontend accessible at `https://<your-tailscale-hostname>/`
- Backend API at `https://<your-tailscale-hostname>/api`
- WebSocket terminal at `wss://<your-tailscale-hostname>/api/ws/terminal/...`

### Environment Variables (Optional)

Create `.env` in backend/:
```bash
JWT_SECRET_KEY=your-secret-key-here
ENCRYPTION_MASTER_KEY=your-encryption-key-here
GEMINI_API_KEY=your-gemini-key-here  # For AI Agent
```

For frontend, create `.env.local` in cluster-dash/:
```bash
# Only needed for non-Tailscale local development
VITE_API_URL=http://localhost:8000
```

## VPN Re-enablement

To re-enable VPN functionality:

### Backend (`backend/app.py`)
1. Uncomment the import:
   ```python
   from docker_utils import run_openconnect_in_container
   ```
2. In `/auth/login` endpoint, uncomment VPN connection logic
3. In `/vpn/connect` endpoint, uncomment openconnect calls

### Backend (`backend/docker_utils.py`)
1. In `run_openconnect_in_container()`, remove the early return and uncomment the VPN logic

### Backend (`backend/schemas.py`)
1. Make `vpn_url` required again in `VPNConnectRequest`

### Frontend (`cluster-dash/src/pages/Login.tsx`)
1. Add back VPN Server URL input field
2. Update form submission to include VPN URL

## Cluster Types Supported

| Type | Description | SSH Behavior |
|------|-------------|--------------|
| `simple` | Direct SSH access | Connect directly to host |
| `slurm` | SLURM-based cluster | Connect to login node, use squeue/sbatch |
| `bastion` | Jump host setup | SSH to bastion, then to compute nodes |

## Security

- JWT tokens with 30-day expiration
- Encrypted password storage (Fernet)
- Rate limiting (5 attempts per 5 minutes per IP)
- Security audit logging
- Per-user isolated containers

## Known Issues / TODOs

- [ ] Token refresh mechanism not implemented
- [ ] User sessions not persisted to disk on shutdown
- [ ] No multi-factor authentication
- [ ] Container cleanup on inactivity not automated

---

*Last updated: 2026-02-10*
