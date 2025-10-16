### керування flag
`ARG flag={some_secret_text}`

`sed -i 's/ШАБЛОН_ПОШУКУ/'$flag'/g' НАЗВА_ФАЙЛУ`

### RCE
ping.php
```
<?php
if (isset($_GET['ip'])) {
    print_r(shell_exec('ping -c 1 '.$_GET['ip']));
} else {
    echo "Something went wrong";
}
?>
```
Dockerfile
```
FROM php:7.2-apache

RUN apt update && apt install iputils-ping -y 
COPY src/ /var/www/html/
```

#### write protection
```
FROM php:7.2-apache

RUN apt update && apt install iputils-ping -y 
COPY src/ /var/www/html/
RUN chmod a-w -R /var/www/
```


#### fork bomb
`while+true%3b+do+sh+-c+"while+true%3b+do+sh+-c+'while+true%3b+do+sh+-c+%3a+%3b+done'+%26+done"+%26+done`

`while true; do sh -c "while true; do sh -c 'while true; do sh -c : ; done' & done" & done`

`docker run --name rce1 -dit --restart always --cpus 0.2 --memory 256m --pids-limit 100 -p 10101:80  rce1`<br>

Dockerfile
```

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
```


### RCE security bypass
ping_v2.php
```
<?php
if (isset($_GET['ip'])) {
    if (preg_match('/[\|&\$ ]/', $_GET['ip'])) {
        die("Error: Invalid host or IP address.");
    }
    print_r(shell_exec('ping -c 1 '.$_GET['ip']));
} else {
    echo "Something went wrong";
}
?>
```



### LFI
Dockerfile
```
FROM php:7.3-apache

COPY src/ /var/www/html/
RUN chmod a-w -R /var/www/
```
### Apples
[https://github.com/CTF-for-ZVO/new/tree/main/Day5_apples](https://github.com/CTF-for-ZVO/new/tree/main/Day5_apples/src)

### LFI to RCE
Dockerfile
```
FROM php:7.3-apache

RUN rm -f /var/log/apache2/access.log /var/log/apache2/error.log

COPY src/ /var/www/html/
RUN chmod a-w -R /var/www/
```
