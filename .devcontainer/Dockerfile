FROM php:7.4-apache

# ── System packages ────────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y \
    git \
    curl \
    unzip \
    libzip-dev \
    zlib1g-dev \
    libicu-dev \
    && rm -rf /var/lib/apt/lists/*

# ── PHP extensions ─────────────────────────────────────────────────────────────
# Match the production Dockerfile exactly for the baseline set.
RUN docker-php-ext-install zip pdo_mysql

# intl is required by Symfony 3.4 (needs libicu-dev installed above).
# Split into a separate layer so failures are easy to identify.
RUN docker-php-ext-configure intl && docker-php-ext-install intl

# mbstring is statically compiled into php:7.4-apache — always active, nothing to do.
# opcache is enabled below via php.ini.

# ── php.ini tweaks ─────────────────────────────────────────────────────────────
RUN { \
    echo 'mbstring.internal_encoding = UTF-8'; \
    echo 'display_errors = On'; \
    echo 'error_reporting = E_ALL'; \
    echo 'date.timezone = UTC'; \
    echo 'opcache.enable = 1'; \
} > /usr/local/etc/php/conf.d/nrdb.ini

# ── Apache config ──────────────────────────────────────────────────────────────
# Switch to port 8080 (matches docker/docker-compose.yml)
RUN sed -i "s/Listen 80/Listen 8080/" /etc/apache2/ports.conf

# Enable mod_rewrite (required by Symfony's front controller)
RUN a2enmod rewrite

# Copy the virtual-host config from the existing docker/ directory
COPY docker/000-default.conf /etc/apache2/sites-available/000-default.conf

# ── Composer 2.2 (LTS – supports PHP 7.x) ─────────────────────────────────────
RUN curl -sS https://getcomposer.org/installer \
    | php -- --install-dir=/usr/local/bin --filename=composer --version=2.2.23

# ── Permissions ────────────────────────────────────────────────────────────────
RUN chown -R www-data:www-data /var/www

WORKDIR /var/www/html/nrdb

EXPOSE 8080

CMD ["apache2-foreground"]
