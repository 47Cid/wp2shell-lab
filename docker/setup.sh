#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

PORT="${WP_PORT:-8888}"

if [[ "${1:-}" == "down" ]]; then
    docker compose down -v --remove-orphans
    exit 0
fi

mkdir -p rce
chmod 777 rce
rm -f rce/*.php

echo "[*] starting WordPress 6.9.4 + MySQL 8.0 lab"
docker compose up -d

echo "[*] waiting for WordPress to be ready..."
for _ in $(seq 1 90); do
    curl -sf "http://localhost:${PORT}/wp-admin/install.php" >/dev/null 2>&1 && break
    sleep 1
done

echo "[*] running WordPress install"
curl -sS "http://localhost:${PORT}/wp-admin/install.php?step=2" \
    --data-urlencode 'weblog_title=wp2shell-lab' \
    --data-urlencode 'user_name=admin' \
    --data-urlencode 'admin_password=admin' \
    --data-urlencode 'admin_password2=admin' \
    --data-urlencode 'pw_weak=on' \
    --data-urlencode 'admin_email=lab@example.com' \
    --data-urlencode 'blog_public=0' >/dev/null || true

echo "[+] lab ready at http://localhost:${PORT}"
echo "    admin / admin"
