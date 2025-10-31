# ============================================================================
# SSH Server - Intentionally Misconfigured
# ============================================================================
# Base: Ubuntu with OpenSSH
# Intentional Vulnerabilities: Weak creds, sudo misconfig, exposed keys
# ============================================================================

FROM ubuntu:22.04

# Prevent interactive prompts during installation
ENV DEBIAN_FRONTEND=noninteractive

# Install SSH server and common tools
RUN apt-get update && apt-get install -y \
    openssh-server \
    sudo \
    vim \
    nano \
    curl \
    wget \
    netcat \
    net-tools \
    iputils-ping \
    nmap \
    tcpdump \
    python3 \
    python3-pip \
    git \
    && rm -rf /var/lib/apt/lists/*

# Create necessary directories
RUN mkdir /var/run/sshd

# Configure SSH for vulnerabilities
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/' /etc/ssh/sshd_config && \
    echo "AllowUsers root admin doctor nurse" >> /etc/ssh/sshd_config

# Set weak root password (intentional vulnerability)
RUN echo 'root:password123' | chpasswd

# Create vulnerable users
RUN useradd -m -s /bin/bash -G sudo admin && \
    echo 'admin:admin2024' | chpasswd && \
    useradd -m -s /bin/bash doctor && \
    echo 'doctor:Doctor2024!' | chpasswd && \
    useradd -m -s /bin/bash nurse && \
    echo 'nurse:Nurse123' | chpasswd

# Create sudo misconfiguration (intentional vulnerability)
RUN echo "admin ALL=(ALL) NOPASSWD: /usr/bin/vim, /usr/bin/find, /usr/bin/python3" >> /etc/sudoers && \
    echo "doctor ALL=(ALL) NOPASSWD: /bin/cat /var/log/*" >> /etc/sudoers

# Create sensitive files with weak permissions (intentional vulnerability)
RUN mkdir -p /opt/config && \
    echo "DB_HOST=ehr-database" > /opt/config/app.conf && \
    echo "DB_USER=ehrapp" >> /opt/config/app.conf && \
    echo "DB_PASS=Welcome123!" >> /opt/config/app.conf && \
    echo "API_KEY=${STRIPE_API_KEY:-example_api_key}" >> /opt/config/app.conf && \
    chmod 644 /opt/config/app.conf

# Create .ssh directory with exposed private key (intentional vulnerability)
RUN mkdir -p /root/.ssh && \
    ssh-keygen -t rsa -b 2048 -f /root/.ssh/id_rsa -N "" && \
    chmod 644 /root/.ssh/id_rsa && \
    cp /root/.ssh/id_rsa.pub /root/.ssh/authorized_keys

# Create backup directory with sensitive data
RUN mkdir -p /opt/backups && \
    echo '{"username":"admin","password":"admin123","role":"superadmin"}' > /opt/backups/creds.json && \
    chmod 644 /opt/backups/creds.json

# Create a vulnerable script with SUID bit (for privilege escalation)
RUN echo '#!/bin/bash' > /usr/local/bin/backup.sh && \
    echo 'echo "Running backup as: $(whoami)"' >> /usr/local/bin/backup.sh && \
    echo 'tar -czf /tmp/backup.tar.gz /opt/config/* 2>/dev/null' >> /usr/local/bin/backup.sh && \
    echo 'chmod 777 /tmp/backup.tar.gz' >> /usr/local/bin/backup.sh && \
    chmod 755 /usr/local/bin/backup.sh

# Create history files with sensitive commands (information disclosure)
RUN echo "mysql -u root -padmin123 healthcare_db" >> /root/.bash_history && \
    echo "cat /opt/config/app.conf" >> /root/.bash_history && \
    echo "ssh admin@file-server" >> /root/.bash_history && \
    echo "ftp fileadmin@file-server" >> /root/.bash_history && \
    chmod 644 /root/.bash_history

# Expose SSH port
EXPOSE 22

# Health check
HEALTHCHECK --interval=30s --timeout=3s \
    CMD netstat -tln | grep 22 || exit 1

# Start SSH service
CMD ["/usr/sbin/sshd", "-D"]

