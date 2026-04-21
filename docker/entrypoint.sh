#!/bin/bash
set -e

DB_HOST="${DVWA_DB_HOST:-db}"
DB_USER="${DVWA_DB_USER:-dvwa}"
DB_PASS="${DVWA_DB_PASSWORD:-dvwa_pass}"

# Expose env vars to Apache so PHP getenv() picks them up
cat >> /etc/apache2/envvars <<EOF
export DVWA_DB_HOST="${DB_HOST}"
export DVWA_DB_NAME="${DVWA_DB_NAME:-dvwa}"
export DVWA_DB_USER="${DB_USER}"
export DVWA_DB_PASSWORD="${DB_PASS}"
EOF

echo "[*] Waiting for MariaDB at ${DB_HOST}..."
until mysqladmin ping -h "${DB_HOST}" -u "${DB_USER}" -p"${DB_PASS}" --silent 2>/dev/null; do
    sleep 2
done
echo "[+] Database ready."

echo "[*] Starting Apache..."
source /etc/apache2/envvars
apache2 -D BACKGROUND

echo "[*] Waiting for Apache to be ready..."
until curl -s -o /dev/null http://localhost/DVWA/setup.php; do
    sleep 1
done

echo "[*] Running DVWA database setup..."
curl -s -o /dev/null --data "create_db=Create+%2F+Reset+Database" http://localhost/DVWA/setup.php
echo "[+] DVWA ready at http://localhost/DVWA (admin / password)"

tail -f /var/log/apache2/access.log /var/log/apache2/error.log
