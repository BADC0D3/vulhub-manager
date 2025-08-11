FROM php:8.0-apache

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    libpng-dev \
    libonig-dev \
    libxml2-dev \
    zip \
    unzip

# Clear cache
RUN apt-get clean && rm -rf /var/lib/apt/lists/*

# Install PHP extensions
RUN docker-php-ext-install pdo_mysql mbstring exif pcntl bcmath gd

# Install Composer
COPY --from=composer:latest /usr/bin/composer /usr/bin/composer

# Set working directory
WORKDIR /var/www/html

# Create a vulnerable Laravel app
RUN composer create-project --prefer-dist laravel/laravel:^8.0 . --no-interaction

# Make it vulnerable - disable CSRF protection
RUN sed -i "s/'verify_csrf_token'/'\/\/verify_csrf_token'/g" app/Http/Kernel.php

# Set permissions
RUN chown -R www-data:www-data /var/www/html \
    && chmod -R 755 /var/www/html/storage

# Configure Apache
RUN a2enmod rewrite
COPY --from=composer:latest /usr/bin/composer /usr/bin/composer
RUN echo '<VirtualHost *:80>\n\
    DocumentRoot /var/www/html/public\n\
    <Directory /var/www/html/public>\n\
        AllowOverride All\n\
        Order allow,deny\n\
        Allow from all\n\
    </Directory>\n\
</VirtualHost>' > /etc/apache2/sites-available/000-default.conf

EXPOSE 80

CMD ["apache2-foreground"] 