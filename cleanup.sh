#!/usr/bin/env bash
set -euo pipefail

# Cleanup script for Vigilink backend (bash)

CYAN='\033[0;36m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
RED='\033[0;31m'
GRAY='\033[0;37m'
RESET='\033[0m'

echo -e "\n${CYAN}=== Vigilink Backend Cleanup ===${RESET}"

echo -e "\n${YELLOW}[1/4] Stopping uvicorn/python processes...${RESET}"

# Find python/uvicorn processes related to this project
pids=$(ps -eo pid,comm,args | grep -E 'python|uvicorn' | grep -E 'CLARIS|backend|uvicorn' | grep -v grep | awk '{print $1}' || true)
if [[ -n "$pids" ]]; then
  for pid in $pids; do
    echo -e "  Killing process $pid"
    if kill -9 "$pid" >/dev/null 2>&1; then
      echo -e "    Killed $pid"
    else
      echo -e "    Could not kill $pid"
    fi
  done
  echo -e "${GREEN}  Stopped processes${RESET}"
else
  echo -e "${GREEN}  No uvicorn/python processes found${RESET}"
fi

sleep 2

echo -e "\n${YELLOW}[2/4] Removing vigilink Docker containers...${RESET}"
containers=$(docker ps -aq --filter "name=vigilink" 2>/dev/null || true)
if [[ -n "$containers" ]]; then
  count=$(echo "$containers" | sed '/^$/d' | wc -l | tr -d ' ')
  echo -e "  Found $count container(s)"
  if docker rm -f $containers 2>/dev/null; then
    echo -e "${GREEN}  Removed all vigilink containers${RESET}"
  else
    echo -e "${YELLOW}  Warning: Some containers may not have been removed${RESET}"
  fi
else
  echo -e "${GREEN}  No vigilink containers found${RESET}"
fi

echo -e "\n${YELLOW}[3/4] Cleaning connection state...${RESET}"
stateFile="backend/.vigilink_conns.json"
if [[ -f "$stateFile" ]]; then
  if rm -f "$stateFile"; then
    echo -e "${GREEN}  Removed $stateFile${RESET}"
  else
    echo -e "${YELLOW}  Warning: Could not remove state file${RESET}"
  fi
else
  echo -e "${GREEN}  No state file found${RESET}"
fi

echo -e "\n${YELLOW}[4/4] Checking port 8000...${RESET}"
sleep 1
port8000=""
if command -v ss >/dev/null 2>&1; then
  port8000=$(ss -ltnp 2>/dev/null | grep ":8000" || true)
elif command -v lsof >/dev/null 2>&1; then
  port8000=$(lsof -iTCP:8000 -sTCP:LISTEN -Pn 2>/dev/null || true)
fi

if [[ -n "$port8000" ]]; then
  echo -e "${YELLOW}  Warning: Port 8000 is still in use:${RESET}"
  echo -e "  ${GRAY}$port8000${RESET}"
  echo -e "  You may need to manually kill these processes or wait a few seconds"
else
  echo -e "${GREEN}  Port 8000 is free${RESET}"
fi

echo -e "\n${CYAN}=== Cleanup Complete ===${RESET}"
echo -e "\nYou can now start the server with:"
echo -e "  cd backend"
echo -e "  uvicorn app:app --host 0.0.0.0 --port 8000 --reload"
echo ""
