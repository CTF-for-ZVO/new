### Розгортання CTFd
1. Встановіть Docker або використовуйте дроплет з Digital Ocean зі встановленим Docker
1. Встановіть Docker Compose `apt install docker-compose`
1. Клонуйте репозиторій CTFd за допомогою `git clone https://github.com/CTFd/CTFd.git`
1. Відредагуйте файл docker-compose.yml з репозиторію, щоб вказати змінну середовища SECRET_KEY для сервісу CTFd.
 `head -c 64 /dev/urandom > .ctfd_secret_key` within the CTFd repo to generate a .ctfd_secret_key file.
1. Запускаємо `docker-compose up -d`


### Firewall ufw
1. `ufw status verbose`
2. `ufw status numbered`
3. `ufw delete 3`
4. `ufw allow 443`

### CTFd docker-compose.yml
```
services:
  ctfd:
    build: .
    user: root
    restart: always
    ports:
      - "127.0.0.1:8000:8000"
    environment:
      - UPLOAD_FOLDER=/var/uploads
      - DATABASE_URL=mysql+pymysql://ctfd:ctfd@db/ctfd
      - REDIS_URL=redis://cache:6379
      - WORKERS=1
      - LOG_FOLDER=/var/log/CTFd
      - ACCESS_LOG=-
      - ERROR_LOG=-
      - REVERSE_PROXY=true
    volumes:
      - .data/CTFd/logs:/var/log/CTFd
      - .data/CTFd/uploads:/var/uploads
      - .:/opt/CTFd:ro
    depends_on:
      - db
    networks:
        default:
        internal:

#  nginx:
#    image: nginx:stable
#    restart: always
#    volumes:
#      - ./conf/nginx/http.conf:/etc/nginx/nginx.conf
#    ports:
#      - 80:80
#    depends_on:
#      - ctfd

  db:
    image: mariadb:10.11
    restart: always
    environment:
      - MARIADB_ROOT_PASSWORD=ctfd
      - MARIADB_USER=ctfd
      - MARIADB_PASSWORD=ctfd
      - MARIADB_DATABASE=ctfd
      - MARIADB_AUTO_UPGRADE=1
    volumes:
      - .data/mysql:/var/lib/mysql
    networks:
        internal:
    # This command is required to set important mariadb defaults
    command: [mysqld, --character-set-server=utf8mb4, --collation-server=utf8mb4_unicode_ci, --wait_timeout=28800, --log-warnings=0]

  cache:
    image: redis:4
    restart: always
    volumes:
    - .data/redis:/data
    networks:
        internal:

networks:
    default:
    internal:
        internal: true
```

`docker-compose down`
`docker-compose up`


### ctop
```
docker run --rm -ti \
  --name=ctop \
  --volume /var/run/docker.sock:/var/run/docker.sock:ro \
  quay.io/vektorlab/ctop:latest
```

### Nginx
На Linux (Ubuntu/Debian):
`apt update`
`apt install nginx`
Після встановлення переконайтесь, що Nginx запущений:
`sercice start nginx`
`service enable nginx`

### /etc/nginx/sites-enabled/ctf.conf
```
# Map: Відповідність host → порт
    map $host $target_port {
        default          8000; # за замовчуванням порт
        chal1.ctf-in-every-house.site  10001;
        chal2.ctf-in-every-house.site  10002;
        chal3.ctf-in-every-house.site  10003;
        # Додавайте свої сабдомени тут
    }


    server {
        listen 443 ssl;
        server_name dashboard.ctf-in-every-house.site;
        ssl_certificate     /etc/letsencrypt/live/ctf-in-every-house.site/fullchain.pem;  # Шлях до сертифікату від letsencrypt
        ssl_certificate_key /etc/letsencrypt/live/ctf-in-every-house.site/privkey.pem;    # Шлях до приватного ключа від letsencrypt

    location /events {

      proxy_pass http://127.0.0.1:8000;
      proxy_set_header Connection '';
      proxy_http_version 1.1;
      chunked_transfer_encoding off;
      proxy_buffering off;
      proxy_cache off;
      proxy_redirect off;
      proxy_set_header Host $host;
      proxy_set_header X-Real-IP $remote_addr;
      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
      proxy_set_header X-Forwarded-Host $server_name;
    }

    # Proxy connections to the application servers
    location / {

      proxy_pass http://127.0.0.1:8000;
      proxy_redirect off;
      proxy_set_header Host $host;
      proxy_set_header X-Real-IP $remote_addr;
      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
      proxy_set_header X-Forwarded-Host $server_name;
    }

    }


    server {
        listen 443 ssl;
        server_name .ctf-in-every-house.site;
        ssl_certificate     /etc/letsencrypt/live/ctf-in-every-house.site/fullchain.pem; # Шлях до сертифікату від letsencrypt
        ssl_certificate_key /etc/letsencrypt/live/ctf-in-every-house.site/privkey.pem;   # Шлях до приватного ключа від letsencrypt

        location / {
            proxy_pass http://127.0.0.1:$target_port;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }
    }
```

#### якщо потрібно згенерувати самопідписаний сертифікат
1. В конфігурації nginx вказуємо таких шлях до ключа та сертифікату (в двох місцях)
```
ssl_certificate     /etc/ssl/private/nginx-selfsigned.key;     
ssl_certificate_key /etc/ssl/certs/nginx-selfsigned.crt;
```
2. Генеруємо самопідписаний сертифікат
`openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/nginx-selfsigned.key -out /etc/ssl/certs/nginx-selfsigned.crt`

3. Перевірте конфігурацію на наявність синтаксичних помилок:
`nginx -t`

4. Якщо помилок немає, перезапустіть Nginx, щоб застосувати зміни:
   `service nginx restart`


### DNS
1. Тут я купував домен
`https://www.namecheap.com/`
2. В налаштуваннях домену обираємо `custom DNS`
```
ns1.digitalocean.com
ns2.digitalocean.com
ns3.digitalocean.com
```
3. Генеруємо сертифікати
   `certbot certonly --manual --preferred-challenges dns -d "*.ctf-in-every-house.site" -d "ctf-in-every-house.site"`

### Github
1. Генеруємо ssh ключ
   `ssh-keygen -t ed25519 -C "email+ctf@gmail.com"`
2. Клонування репозиторію
   `git clone git@github.com:CTF-for-ZVO/ctf-in-every-house.git`
