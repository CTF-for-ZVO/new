FROM php:8.1-apache

# Встановлення розширення mysqli для роботи з MariaDB
RUN docker-php-ext-install mysqli

# Встановлення потрібних прав
RUN chown -R www-data:www-data /var/www/html


RUN mkdir -p /var/log/apache_logs && \
    chown -R www-data:www-data /var/log/apache_logs

COPY 001-custom-log.conf /etc/apache2/sites-available/000-default.conf

RUN a2dissite 000-default.conf && \
    a2ensite 000-default.conf
