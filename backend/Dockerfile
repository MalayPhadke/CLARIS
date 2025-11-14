# Vigilink Backend Container Image
# Python slim with preinstalled VPN, SSH tools, and Paramiko
FROM python:3.11-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive

# Install openconnect, openssh-client, socat, netcat, and network utilities
RUN apt-get update -y && \
    apt-get install -y --no-install-recommends \
        openconnect \
        openssh-client \
        socat \
        netcat-openbsd \
        iproute2 \
        iputils-ping \
        procps \
        ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install Python dependencies for SSH management
RUN pip install --no-cache-dir paramiko==3.4.0

# Copy SSH manager script
COPY ssh_manager.py /usr/local/bin/ssh_manager.py
RUN chmod +x /usr/local/bin/ssh_manager.py

# Start ssh_manager.py daemon listening on port 9999 and keep container running
CMD ["sh", "-c", "python3 /usr/local/bin/ssh_manager.py & while true; do sleep 3600; done"]
