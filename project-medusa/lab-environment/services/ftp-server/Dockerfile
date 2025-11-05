# ============================================================================
# FTP Server - Vulnerable File Server
# ============================================================================
# Base: Ubuntu with vsftpd
# Intentional Vulnerabilities: Anonymous FTP, weak creds, sensitive files
# ============================================================================

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install vsftpd and utilities
RUN apt-get update && apt-get install -y \
    vsftpd \
    ftp \
    && rm -rf /var/lib/apt/lists/*

# Create FTP user with weak password
RUN useradd -m -s /bin/bash ftpuser && \
    echo 'ftpuser:ftp123' | chpasswd && \
    useradd -m -s /bin/bash fileadmin && \
    echo 'fileadmin:Files2024!' | chpasswd

# Create directory structure
RUN mkdir -p /home/ftpuser/medical_records && \
    mkdir -p /home/ftpuser/backups && \
    mkdir -p /home/ftpuser/uploads && \
    mkdir -p /home/fileadmin/confidential

# Create vulnerable vsftpd configuration
RUN echo "listen=YES" > /etc/vsftpd.conf && \
    echo "listen_ipv6=NO" >> /etc/vsftpd.conf && \
    echo "anonymous_enable=YES" >> /etc/vsftpd.conf && \
    echo "local_enable=YES" >> /etc/vsftpd.conf && \
    echo "write_enable=YES" >> /etc/vsftpd.conf && \
    echo "local_umask=022" >> /etc/vsftpd.conf && \
    echo "anon_upload_enable=YES" >> /etc/vsftpd.conf && \
    echo "anon_mkdir_write_enable=YES" >> /etc/vsftpd.conf && \
    echo "dirmessage_enable=YES" >> /etc/vsftpd.conf && \
    echo "xferlog_enable=YES" >> /etc/vsftpd.conf && \
    echo "connect_from_port_20=YES" >> /etc/vsftpd.conf && \
    echo "xferlog_file=/var/log/vsftpd/vsftpd.log" >> /etc/vsftpd.conf && \
    echo "xferlog_std_format=YES" >> /etc/vsftpd.conf && \
    echo "listen_port=21" >> /etc/vsftpd.conf && \
    echo "pam_service_name=vsftpd" >> /etc/vsftpd.conf && \
    echo "userlist_enable=NO" >> /etc/vsftpd.conf && \
    echo "tcp_wrappers=NO" >> /etc/vsftpd.conf && \
    echo "pasv_enable=YES" >> /etc/vsftpd.conf && \
    echo "pasv_min_port=21000" >> /etc/vsftpd.conf && \
    echo "pasv_max_port=21010" >> /etc/vsftpd.conf && \
    echo "allow_writeable_chroot=YES" >> /etc/vsftpd.conf && \
    echo "seccomp_sandbox=NO" >> /etc/vsftpd.conf

# Create log directory
RUN mkdir -p /var/log/vsftpd

# Set permissions (intentionally weak)
RUN chown -R ftpuser:ftpuser /home/ftpuser && \
    chmod -R 755 /home/ftpuser && \
    chown -R fileadmin:fileadmin /home/fileadmin && \
    chmod -R 755 /home/fileadmin

# Create sample sensitive files
RUN echo "Patient ID,Name,SSN,Diagnosis" > /home/ftpuser/medical_records/patients.csv && \
    echo "P001,John Doe,123-45-6789,Diabetes Type 2" >> /home/ftpuser/medical_records/patients.csv && \
    echo "P002,Jane Smith,987-65-4321,Hypertension" >> /home/ftpuser/medical_records/patients.csv && \
    echo "Database backup credentials:" > /home/ftpuser/backups/README.txt && \
    echo "Host: ehr-database" >> /home/ftpuser/backups/README.txt && \
    echo "User: root" >> /home/ftpuser/backups/README.txt && \
    echo "Pass: admin123" >> /home/ftpuser/backups/README.txt

# Create a fake database dump
RUN echo "-- MedCare Database Backup" > /home/ftpuser/backups/db_backup_2024.sql && \
    echo "-- Generated: 2024-01-15" >> /home/ftpuser/backups/db_backup_2024.sql && \
    echo "-- SENSITIVE DATA - DO NOT DISTRIBUTE" >> /home/ftpuser/backups/db_backup_2024.sql

EXPOSE 21 21000-21010

# Health check - verify vsftpd is running
HEALTHCHECK --interval=30s --timeout=3s \
    CMD ps aux | grep vsftpd | grep -v grep || exit 1

CMD ["/usr/sbin/vsftpd", "/etc/vsftpd.conf"]

