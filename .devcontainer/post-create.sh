#!/usr/bin/env bash
# .devcontainer/post-create.sh
# Runs once inside the app container after VS Code first creates the devcontainer.
# Mirrors the steps from docker/docker-first-run.sh adapted for the devcontainer layout.

set -euo pipefail

NRDB=/var/www/html/nrdb
DEVCONTAINER_PARAMS="${NRDB}/.devcontainer/parameters.yml"
PARAMS_DEST="${NRDB}/app/config/parameters.yml"

echo "──────────────────────────────────────────────"
echo "  NetrunnerDB devcontainer post-create setup"
echo "──────────────────────────────────────────────"

# ── 1. parameters.yml ──────────────────────────────────────────────────────────
echo "→ Installing parameters.yml ..."
if [ -f "${DEVCONTAINER_PARAMS}" ]; then
    cp "${DEVCONTAINER_PARAMS}" "${PARAMS_DEST}"
    echo "  Copied .devcontainer/parameters.yml → app/config/parameters.yml"
else
    # Fall back to the docker/ template so the container still starts.
    cp "${NRDB}/docker/dev-parameters.yml" "${PARAMS_DEST}"
    echo "  WARNING: .devcontainer/parameters.yml not found; used docker/dev-parameters.yml as fallback."
    echo "  Edit app/config/parameters.yml (ignored by git) with your local values."
fi

# Fix the database host to match the devcontainer compose service name
sed -i "s/database_host: nrdb-dev-db/database_host: db/" "${PARAMS_DEST}"

# ── 2. Composer install ────────────────────────────────────────────────────────
echo "→ Running composer install ..."
cd "${NRDB}"
SYMFONY_ENV=dev composer install --no-interaction --prefer-dist

# ── 3. mod_rewrite is already enabled in the Dockerfile (a2enmod rewrite) ─────
# Do NOT restart Apache here — in a container apache2-foreground is PID 1 and
# a restart sends SIGTERM, killing the container mid-script.
echo "→ mod_rewrite already enabled at build time, skipping restart."

# ── 4. Doctrine schema ────────────────────────────────────────────────────────
echo "→ Waiting for MySQL to be ready ..."
until php bin/console doctrine:query:sql "SELECT 1" &>/dev/null; do
    echo "   ... still waiting for DB"
    sleep 2
done

echo "→ Running doctrine:schema:update --force ..."
php bin/console doctrine:schema:update --force

# ── 5. Import card data (from the sibling netrunner-cards-json repo) ──────────
CARDS_DIR="/var/www/html/netrunner-cards-json"
if [ -d "${CARDS_DIR}" ]; then
    echo "→ Importing card data from ${CARDS_DIR} ..."
    php bin/console app:import:std -f "${CARDS_DIR}"
else
    echo "  Skipping card import – netrunner-cards-json not found at ${CARDS_DIR}."
    echo "  Make sure the netrunner-cards-json repo is cloned as a sibling directory:"
    echo "    ../netrunner-cards-json   (next to netrunnerdb on your host)"
    echo "  Then rebuild the container or run manually:"
    echo "    php bin/console app:import:std -f ${CARDS_DIR}"
fi

# ── 6. Fix permissions ────────────────────────────────────────────────────────
echo "→ Fixing permissions on var/ ..."
chown -R www-data:www-data "${NRDB}/var" || true

echo ""
echo "✅ Setup complete!"
echo "   Open http://localhost:8080/app_dev.php in your browser."

# ── 7. Import Postgres Data ──────────────────────────────────────────────────────────────────────────────────────────────────────
echo "→ Waiting for PostgreSQL to be ready ..."
until PGPASSWORD=postgres pg_isready -h postgres -U postgres -d postgres &>/dev/null; do
    echo "   ... still waiting for Postgres"
    sleep 2
done
echo "→ Ensuring nrdb_api_development database exists ..."
PGPASSWORD=postgres psql -U postgres -h postgres -tc "SELECT 1 FROM pg_database WHERE datname = 'nrdb_api_development'" | grep -q 1 || \
PGPASSWORD=postgres psql -U postgres -h postgres -c "CREATE DATABASE nrdb_api_development;"
echo "→ Importing Postgres backup data ..."
if [ -f "${NRDB}/nrdb-api-development.backup.gz" ]; then
    gunzip -c "${NRDB}/nrdb-api-development.backup.gz" > "${NRDB}/nrdb-api-development.backup"
    PGPASSWORD=postgres psql -U postgres -d nrdb_api_development -h postgres -f "${NRDB}/nrdb-api-development.backup"
    rm ${NRDB}/nrdb-api-development.backup
fi