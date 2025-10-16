FROM php:8.3-apache

RUN rm -f /var/log/apache2/access.log /var/log/apache2/error.log
RUN apt-get update && \
    apt-get install -y logrotate cron &&
COPY apache_logrotate.conf /etc/logrotate.d/apache2
RUN echo "* * * * * /usr/sbin/logrotate /etc/logrotate.conf" > /etc/crontab

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

COPY src/ /var/www/html/
CMD ["apache2-foreground"]
