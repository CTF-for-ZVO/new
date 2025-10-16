FROM php:7.2-apache

RUN rm -f /var/log/apache2/access.log /var/log/apache2/error.log
RUN echo "* * * * * rm /var/log/apache2/access.log /var/log/apache2/error.log" >> /etc/crontab
COPY src/ /var/www/html/
