# ============================================================================
# Workstation - Simulated Windows Workstation
# ============================================================================
# Base: Ubuntu with VNC, Samba, and desktop environment
# Intentional Vulnerabilities: SMB misconfig, cached creds, weak permissions
# ============================================================================

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install desktop environment (lightweight) and tools
RUN apt-get update && apt-get install -y \
    xfce4 \
    xfce4-terminal \
    tightvncserver \
    samba \
    smbclient \
    cifs-utils \
    net-tools \
    curl \
    wget \
    vim \
    nano \
    && rm -rf /var/lib/apt/lists/*

# Create user
RUN useradd -m -s /bin/bash doctor && \
    echo 'doctor:Doctor2024!' | chpasswd && \
    mkdir -p /home/doctor/Documents && \
    mkdir -p /home/doctor/Desktop && \
    mkdir -p /home/doctor/Shared

# Configure VNC (weak password)
RUN mkdir -p /root/.vnc && \
    echo 'vnc123' | vncpasswd -f > /root/.vnc/passwd && \
    chmod 600 /root/.vnc/passwd

# Configure Samba with vulnerabilities
RUN echo '[global]' > /etc/samba/smb.conf && \
    echo '   workgroup = MEDCARE' >> /etc/samba/smb.conf && \
    echo '   server string = Doctor Workstation' >> /etc/samba/smb.conf && \
    echo '   security = user' >> /etc/samba/smb.conf && \
    echo '   map to guest = Bad Password' >> /etc/samba/smb.conf && \
    echo '   dns proxy = no' >> /etc/samba/smb.conf && \
    echo '' >> /etc/samba/smb.conf && \
    echo '[Shared]' >> /etc/samba/smb.conf && \
    echo '   path = /home/doctor/Shared' >> /etc/samba/smb.conf && \
    echo '   browseable = yes' >> /etc/samba/smb.conf && \
    echo '   writable = yes' >> /etc/samba/smb.conf && \
    echo '   guest ok = yes' >> /etc/samba/smb.conf && \
    echo '   read only = no' >> /etc/samba/smb.conf && \
    echo '   create mask = 0777' >> /etc/samba/smb.conf && \
    echo '   directory mask = 0777' >> /etc/samba/smb.conf && \
    echo '' >> /etc/samba/smb.conf && \
    echo '[Documents]' >> /etc/samba/smb.conf && \
    echo '   path = /home/doctor/Documents' >> /etc/samba/smb.conf && \
    echo '   browseable = yes' >> /etc/samba/smb.conf && \
    echo '   writable = yes' >> /etc/samba/smb.conf && \
    echo '   valid users = doctor' >> /etc/samba/smb.conf && \
    echo '   create mask = 0755' >> /etc/samba/smb.conf

# Add Samba user
RUN (echo 'Doctor2024!'; echo 'Doctor2024!') | smbpasswd -a -s doctor

# Create sensitive files with cached credentials (intentional vulnerability)
RUN echo '[Database Connection]' > /home/doctor/Documents/connection.ini && \
    echo 'server=ehr-database' >> /home/doctor/Documents/connection.ini && \
    echo 'username=ehrapp' >> /home/doctor/Documents/connection.ini && \
    echo 'password=Welcome123!' >> /home/doctor/Documents/connection.ini && \
    echo '' >> /home/doctor/Documents/connection.ini && \
    echo '[FTP Server]' >> /home/doctor/Documents/connection.ini && \
    echo 'host=file-server' >> /home/doctor/Documents/connection.ini && \
    echo 'username=fileadmin' >> /home/doctor/Documents/connection.ini && \
    echo 'password=Files2024!' >> /home/doctor/Documents/connection.ini

# Create browser history file with credentials
RUN mkdir -p /home/doctor/.mozilla/firefox && \
    echo 'http://ehr-portal/login?user=doctor1&pass=doctor123' > /home/doctor/.mozilla/firefox/history.txt

# Create SSH config with saved credentials
RUN mkdir -p /home/doctor/.ssh && \
    echo 'Host admin-server' > /home/doctor/.ssh/config && \
    echo '    HostName ssh-server' >> /home/doctor/.ssh/config && \
    echo '    User admin' >> /home/doctor/.ssh/config && \
    echo '    IdentityFile ~/.ssh/id_rsa' >> /home/doctor/.ssh/config

# Set weak permissions
RUN chmod -R 755 /home/doctor && \
    chmod 644 /home/doctor/Documents/connection.ini && \
    chmod 644 /home/doctor/.ssh/config

# Create startup script
RUN echo '#!/bin/bash' > /start.sh && \
    echo 'export USER=root' >> /start.sh && \
    echo 'export HOME=/root' >> /start.sh && \
    echo 'smbd --foreground --no-process-group &' >> /start.sh && \
    echo 'nmbd --foreground --no-process-group &' >> /start.sh && \
    echo 'mkdir -p /var/log/samba' >> /start.sh && \
    echo 'touch /var/log/samba/log.smbd' >> /start.sh && \
    echo 'vncserver :0 -geometry 1024x768 -depth 24 -rfbport 5900 &' >> /start.sh && \
    echo 'sleep 5' >> /start.sh && \
    echo 'tail -f /var/log/samba/log.smbd /dev/null' >> /start.sh && \
    chmod +x /start.sh

EXPOSE 445 139 5900

HEALTHCHECK --interval=30s --timeout=3s \
    CMD netstat -tln | grep 445 || exit 1

CMD ["/start.sh"]

