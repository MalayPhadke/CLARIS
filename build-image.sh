#!/usr/bin/env bash
set -euo pipefail

# Build script for vigilink-backend Docker image (bash)

CYAN='\033[0;36m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
RED='\033[0;31m'
RESET='\033[0m'

echo -e "${CYAN}Building vigilink-backend Docker image...${RESET}"

imageName="vigilink-backend:latest"
dockerfilePath="backend/Dockerfile"

# Check if Docker is available
if ! command -v docker >/dev/null 2>&1; then
  echo -e "${RED}Error: Docker is not installed or not in PATH${RESET}" >&2
  exit 1
fi

# Check if Dockerfile exists
if [[ ! -f "$dockerfilePath" ]]; then
  echo -e "${RED}Error: Dockerfile not found at $dockerfilePath${RESET}" >&2
  exit 1
fi

# Build the image
echo -e "${YELLOW}Building image: $imageName${RESET}"
if docker build -t "$imageName" -f "$dockerfilePath" backend/; then
  echo -e "\n${GREEN}Success! Image built: $imageName${RESET}"
  echo -e "${CYAN}Verify with: docker images | grep vigilink-backend${RESET}"
else
  echo -e "\n${RED}Error: Docker build failed${RESET}" >&2
  exit 1
fi
