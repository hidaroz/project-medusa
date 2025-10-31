# ============================================================================
# Log Collector - Centralized Logging System
# ============================================================================
# Base: Alpine with syslog and simple web viewer
# Purpose: Collect and display logs from all services
# ============================================================================

FROM alpine:3.18

# Install syslog-ng and necessary tools
RUN apk add --no-cache \
    syslog-ng \
    lighttpd \
    bash \
    curl \
    python3 \
    py3-pip

# Create log directories
RUN mkdir -p /var/log/collected/webapp && \
    mkdir -p /var/log/collected/database && \
    mkdir -p /var/log/collected/ssh && \
    mkdir -p /var/log/collected/ftp && \
    mkdir -p /var/log/collected/api && \
    mkdir -p /var/log/analysis

# Configure syslog-ng
RUN echo 'source s_network { udp(port(514)); tcp(port(514)); };' > /etc/syslog-ng/syslog-ng.conf && \
    echo 'destination d_all { file("/var/log/collected/all.log"); };' >> /etc/syslog-ng/syslog-ng.conf && \
    echo 'log { source(s_network); destination(d_all); };' >> /etc/syslog-ng/syslog-ng.conf

# Create simple web interface for log viewing
RUN mkdir -p /var/www/localhost/htdocs

COPY ./web /var/www/localhost/htdocs/

# Configure lighttpd
RUN sed -i 's/#   mod_cgi/    mod_cgi/' /etc/lighttpd/lighttpd.conf

# Set permissions
RUN chmod -R 755 /var/www/localhost/htdocs && \
    chmod 777 /var/log/collected

# Create startup script
RUN echo '#!/bin/bash' > /start.sh && \
    echo 'syslog-ng' >> /start.sh && \
    echo 'lighttpd -D -f /etc/lighttpd/lighttpd.conf' >> /start.sh && \
    chmod +x /start.sh

EXPOSE 514/udp 514/tcp 80

HEALTHCHECK --interval=30s --timeout=3s \
    CMD curl -f http://localhost/ || exit 1

CMD ["/start.sh"]

