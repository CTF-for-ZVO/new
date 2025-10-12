

fork bomb
`while+true%3b+do+sh+-c+"while+true%3b+do+sh+-c+'while+true%3b+do+sh+-c+%3a+%3b+done'+%26+done"+%26+done`

`docker run --name test16 -dit --restart always --cpus 0.2 --memory 256m --pids-limit 100 -p 10101:80  rce1`

```
FROM php:7.2-apache

RUN mv "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini"
RUN sed -i 's/^;\{0,1\}memory_limit = .*/memory_limit = 32M/' "$PHP_INI_DIR/php.ini"

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
  CMD curl --fail http://localhost/?cmd=uptime || exit 1

COPY src/ /var/www/html/
RUN chmod a-w -R /var/www/
```
