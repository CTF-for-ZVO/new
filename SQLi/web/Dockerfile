FROM php:8.1-apache

# Встановлення розширення mysqli для роботи з MariaDB
RUN docker-php-ext-install mysqli

# Встановлення потрібних прав
RUN chown -R www-data:www-data /var/www/html
