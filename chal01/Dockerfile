FROM php:7.2-apache

ARG UID=101
ARG GID=101

RUN set -x \
    && groupadd --system --gid $GID ctf || true \
    && useradd --system --gid ctf --no-create-home --home /nonexistent --comment "ctf user" --shell /bin/false --uid $UID ctf || true

COPY src/ /var/www/html/
RUN chmod a-w -R /var/www/

USER 101
CMD ["/usr/sbin/apache2ctl", "-D", "FOREGROUND"]
