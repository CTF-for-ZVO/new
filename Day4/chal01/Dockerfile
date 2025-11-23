FROM php:7.3-apache

ARG flag="s3curityByP@ss"
RUN mv "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini"
RUN sed -i 's/^;\{0,1\}memory_limit = .*/memory_limit = 32M/' "$PHP_INI_DIR/php.ini"
RUN apt update && apt install iputils-ping -y

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
  CMD curl --fail http://localhost/?cmd=uptime || exit 1

COPY src/ /var/www/html/
RUN chmod a-w -R /var/www/
RUN sed -i 's/flag_placeholder/'$flag'/' /var/www/html/.env
