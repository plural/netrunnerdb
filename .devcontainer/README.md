# NetrunnerDB — VS Code Dev Container

A ready-to-use Dev Container for [NetrunnerDB](https://netrunnerdb.com) that
mirrors the existing `docker/` setup but wrapped up for use in VS Code.

## Stack

| Component | Version |
|-----------|---------|
| PHP       | 7.4 (Apache) |
| MySQL     | 8 |
| Composer  | 2.2.x LTS (PHP 7.x compatible) |
| Symfony   | 3.4.x |

## Prerequisites

1. [VS Code](https://code.visualstudio.com/)
2. [Dev Containers extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers)
3. [Docker Desktop](https://www.docker.com/products/docker-desktop/) (or Docker Engine + Compose v2)

## First-time setup

```bash
# 1. Open the repo in VS Code, then use the command palette:
#    "Dev Containers: Reopen in Container"
#
# The post-create script will automatically:
#   - install parameters.yml
#   - run composer install
#   - run doctrine:schema:update --force
#   - import card data from cards/ if it exists
```

### Card data (optional)

Clone the card data repository **as a sibling** next to `netrunnerdb`:

```
nsg/
├── netrunnerdb/          ← this repo
└── netrunner-cards-json/ ← clone here
```

```bash
# from the parent directory (e.g. ~/src/nsg/)
git clone https://github.com/NetrunnerDB/netrunner-cards-json
```

The devcontainer mounts it automatically at `/var/www/html/netrunner-cards-json`
and the post-create script runs the import. If you add it after the first run:

```bash
php bin/console app:import:std -f /var/www/html/netrunner-cards-json
```

## Browsing the app

Once the container starts, VS Code will forward port **8080**.
Open: <http://localhost:8080/app_dev.php>

## Connecting to MySQL from your host machine

Port **3306** is forwarded. Use any MySQL client with:

| Setting  | Value     |
|----------|-----------|
| Host     | 127.0.0.1 |
| Port     | 3306      |
| Database | nrdb-dev  |
| User     | nrdb-dev  |
| Password | passwd    |

## Useful commands (inside the container)

```bash
# Rebuild the DB schema after entity changes
php bin/console doctrine:schema:update --force

# Re-import all card data
php bin/console app:import:std -f cards

# Create + promote an admin user
php bin/console fos:user:activate <username>
php bin/console fos:user:promote --super <username>

# Clear the Symfony cache
php bin/console cache:clear
```

## Customising parameters.yml

Edit `.devcontainer/parameters.yml` before opening the container (or edit
`app/config/parameters.yml` inside the container after first run). The file is
excluded from git tracking.

The config defaults to the prod v3 API server and prod image hosting.
