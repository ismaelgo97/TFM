# DVWA on Ubuntu 22.04 — target environment for TFM security testing

FROM ubuntu:22.04

LABEL maintainer="Ismael Alonso Gómez Calero"

ENV DEBIAN_FRONTEND=noninteractive

# System packages
RUN apt-get update && apt-get install -y --no-install-recommends \
        apache2 \
        php \
        php-mysqli \
        php-gd \
        php-mbstring \
        php-xml \
        php-zip \
        php-curl \
        mariadb-client \
        curl \
    && rm -rf /var/lib/apt/lists/*

# allow_url_include required by DVWA file inclusion module
RUN sed -i 's/^allow_url_include = .*/allow_url_include = On/' /etc/php/*/apache2/php.ini

RUN a2enmod rewrite

# DVWA served at /DVWA — run: git clone --depth=1 https://github.com/digininja/DVWA docker/dvwa
COPY dvwa/ /var/www/html/DVWA/
# DB credentials injected via environment variables
COPY config/dvwa.config.inc.php /var/www/html/DVWA/config/config.inc.php

COPY config/apache-dvwa.conf /etc/apache2/sites-available/dvwa.conf
RUN a2ensite dvwa && a2dissite 000-default

RUN chown -R www-data:www-data /var/www/html/DVWA \
    && chmod -R 755 /var/www/html/DVWA \
    && chmod 777 /var/www/html/DVWA/hackable/uploads \
    && chmod 777 /var/www/html/DVWA/config

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80

ENTRYPOINT ["/entrypoint.sh"]
