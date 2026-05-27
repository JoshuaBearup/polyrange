#!/bin/sh
# Initialise + start MariaDB with TCP enabled (alpine defaults to socket-only,
# port 0), wait + provision over the unix socket, then exec the Node runtime
# (connects via TCP 127.0.0.1:3306 with MYSQL_URL).
set -e
SOCK=/run/mysqld/mysqld.sock
mkdir -p /run/mysqld /var/lib/mysql
chown -R mysql:mysql /run/mysqld /var/lib/mysql
if [ ! -d /var/lib/mysql/mysql ]; then
  echo "[start] initialising mariadb data dir..."
  mariadb-install-db --user=mysql --datadir=/var/lib/mysql --auth-root-authentication-method=normal >/dev/null 2>&1
fi
echo "[start] starting mariadb (TCP 127.0.0.1:3306)..."
mariadbd --user=mysql --datadir=/var/lib/mysql --skip-networking=0 --bind-address=127.0.0.1 --port=3306 --socket="$SOCK" &
echo "[start] waiting for mariadb socket..."
until mariadb-admin --socket="$SOCK" ping >/dev/null 2>&1; do sleep 0.4; done
echo "[start] provisioning app db..."
mariadb --socket="$SOCK" -u root <<SQL
CREATE DATABASE IF NOT EXISTS app;
ALTER USER 'root'@'localhost' IDENTIFIED BY 'polyrange';
CREATE USER IF NOT EXISTS 'root'@'127.0.0.1' IDENTIFIED BY 'polyrange';
GRANT ALL PRIVILEGES ON *.* TO 'root'@'127.0.0.1';
FLUSH PRIVILEGES;
SQL
echo "[start] mariadb ready"
exec node /app/runtime/server.mjs
