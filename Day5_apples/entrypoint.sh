#!/bin/bash
set -e

# Запускаємо Cron у фоновому режимі
# Це дозволяє планувальнику (який запустить logrotate) працювати
echo "Starting cron daemon..."
/etc/init.d/cron start

# Виконуємо основну команду, передану через CMD (тобто 'apache2-foreground')
echo "Starting Apache..."
exec "$@"
