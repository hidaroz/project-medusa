# ============================================================================
# EHR Web Application - Vulnerable Healthcare Portal
# ============================================================================
# Base: Apache with PHP for classic web vulnerabilities
# Intentional Vulnerabilities: SQLi, XSS, IDOR, Weak Auth
# ============================================================================

FROM php:8.1-apache

# Install required PHP extensions
RUN docker-php-ext-install mysqli pdo pdo_mysql

# Enable Apache modules
RUN a2enmod rewrite headers

# Install additional tools for realism
RUN apt-get update && apt-get install -y \
    vim \
    curl \
    netcat-traditional \
    && rm -rf /var/lib/apt/lists/*

# Create upload directory with weak permissions (intentional)
RUN mkdir -p /var/www/html/uploads && \
    chmod 777 /var/www/html/uploads

# Copy application files
COPY ./src/ /var/www/html/

# Set weak permissions (intentional vulnerability)
RUN chown -R www-data:www-data /var/www/html && \
    find /var/www/html -type f -exec chmod 644 {} \; && \
    find /var/www/html -type d -exec chmod 755 {} \;

# Configure PHP for vulnerability exposure
RUN echo "display_errors = On" >> /usr/local/etc/php/php.ini && \
    echo "error_reporting = E_ALL" >> /usr/local/etc/php/php.ini && \
    echo "allow_url_include = On" >> /usr/local/etc/php/php.ini && \
    echo "file_uploads = On" >> /usr/local/etc/php/php.ini && \
    echo "upload_max_filesize = 100M" >> /usr/local/etc/php/php.ini

# Enable verbose Apache logging
RUN echo "LogLevel info" >> /etc/apache2/apache2.conf

EXPOSE 80

# Health check
HEALTHCHECK --interval=30s --timeout=3s \
    CMD curl -f http://localhost/ || exit 1

CMD ["apache2-foreground"]

