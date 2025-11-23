## chal1
#### chal1/Dockerfile
```
FROM nginx:stable-alpine
COPY src/ /usr/share/nginx/html
EXPOSE 80
```
#### chal1/src/admintools/flag.txt
```
flag{my_first_spidering_flag}
```

#### install dirb
`apt install dirb`

#### test 
`dirb https://chal1.ctf-in-every-house.site`

## chal2
#### chal2/Dockerfile
```
FROM nginx:stable-alpine
RUN apk update && \
    apk add --no-cache git bash && \
    rm -rf /var/cache/apk/*

COPY src/ /usr/share/nginx/html
COPY ./setup.sh /tmp/setup.sh

RUN chmod u+x /tmp/setup.sh
RUN sh /tmp/setup.sh
EXPOSE 80
```

#### chal2/setup.sh
```
#!/bin/bash

# Переходимо в кореневу папку
cd /usr/share/nginx/html

# 1. Ініціалізація Git та налаштування користувача (потрібно для комітів)
git init

# Встановлюємо фіктивні дані користувача, щоб коміти були можливі
git config user.email "dev@ctf-in-every-house.local"
git config user.name "CTF Developer"

# 2. Перший коміт (базова сторінка)
git add index.html
git commit -m "Initial commit: setting up the homepage"

# 3. Створення та коміт прапора (ВРАЗЛИВІСТЬ)
echo "The flag is FLAG{G1T_H1d3s_Th3_S3cr3t}" > secret_flag.txt
git add secret_flag.txt
git commit -m "Added secret flag file temporarily"

# 4. Видалення файлу з прапором та фінальний коміт
rm secret_flag.txt
git add secret_flag.txt # Додаємо видалення до staging area
git commit -m "Removed secret_flag file"
```

#### chal2/src/index.html
```
<!DOCTYPE html>
<html lang="uk">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Оновлення Коду та Git</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
            background-color: #f4f4f9; /* Світло-сірий фон */
            color: #333;
            text-align: center;
        }

        .container {
            width: 80%;
            max-width: 900px;
            margin: 50px auto;
            padding: 30px;
            background-color: #ffffff; /* Білий контейнер */
            border-radius: 8px;
            box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1);
        }

        h1 {
            color: #2c3e50; /* Темно-синій заголовок */
            margin-bottom: 20px;
            font-size: 2.2em;
        }

        p {
            font-size: 1.1em;
            line-height: 1.6;
            margin-bottom: 20px;
        }

        .highlight {
            color: #e74c3c; /* Червоний акцент */
            font-weight: bold;
        }

        .git-logo {
            font-size: 3em;
            color: #f34f29; /* Колір логотипу Git */
            margin: 15px 0;
            display: inline-block;
        }

        /* Стиль для списку переваг */
        ul {
            list-style: none;
            padding: 0;
            text-align: left;
            margin: 20px 0 30px 0;
            display: inline-block;
        }

        li {
            background: #ecf0f1; /* Дуже світлий фон для елементів списку */
            margin-bottom: 10px;
            padding: 10px 15px;
            border-left: 5px solid #3498db; /* Синя смужка */
            border-radius: 4px;
        }

        strong {
            color: #3498db;
        }
    </style>
</head>
<body>

    <div class="container">
        <div class="git-logo">
            <span role="img" aria-label="Git Icon">🔄</span>
        </div>
        <h1>Наші Розробники Використовують <span class="highlight">Git</span></h1>
        
        <p>Для забезпечення високої якості, злагодженої роботи та надійності оновлень коду, всі команди розробників нашої компанії використовують систему контролю версій <span class="highlight">**Git**</span>.</p>
        
        <p>Це стандарт індустрії, який дозволяє нам ефективно керувати розробкою, відстежувати зміни та впроваджувати нові функції без ризиків.</p>

        <h2>Ключові Переваги:</h2>
        <ul>
            <li>**Надійне Співавторство:** Кілька розробників можуть працювати над різними частинами коду одночасно без конфліктів.</li>
            <li>**Повна Історія:** Кожна зміна, внесена до проекту, фіксується і може бути відновлена у будь-який момент.</li>
            <li>**Швидке Розгортання:** Використання гілок (branches) дозволяє нам швидко тестувати та впроваджувати оновлення.</li>
            <li>**Безпека Коду:** Запобігає випадковій втраті або пошкодженню критичних частин програмного забезпечення.</li>
        </ul>

        <p>Ми прагнемо до професійного та організованого процесу розробки, і **Git** є основою цього підходу.</p>

    </div>

</body>
</html>
```

#### test 
`apt install pip`
`pip install git-dumper`
`git-dumper https://chal2.ctf-in-every-house.site/.git/ /tmp/chal2-test/`
`cd /tmp/chal2-test/`
`git log`
`git show de0431fb87a2f16a1af90d3916a19b9289092369`

## chal3
#### chal3/Dockerfile
```
FROM nginx:stable-alpine
COPY src/ /usr/share/nginx/html
EXPOSE 80
```
#### chal3/src/index.html
```
<!DOCTYPE html>
<html>
<head>
    <title>JS Obfuscation Challenge</title>
    <meta charset="UTF-8">
</head>
<body>
    <h1>Знайди прапор!</h1>
    <p>Тобі потрібно ввести правильний пароль, щоб отримати прапор.</p>
    
    <input type="text" id="passwordInput" placeholder="Введи пароль">
    <button onclick="checkPassword()">Перевірити</button>
    
    <script src="challenge.js"></script>
</body>
</html>
```
#### chal3/src/challenge.js obfuscated
```
const _0x4062f9=_0x148f;(function(_0x5ccae2,_0x504e60){const _0x366ed6=_0x148f,_0x17b08a=_0x5ccae2();while(!![]){try{const _0x1c78ef=-parseInt(_0x366ed6(0x12a))/(-0x21dd*-0x1+-0x26*-0x45+-0x160d*0x2)*(parseInt(_0x366ed6(0x13a))/(0x1be+0x4*-0x7f4+0x1e14))+-parseInt(_0x366ed6(0x11e))/(-0x136e*-0x1+-0x26c0+-0x7*-0x2c3)+-parseInt(_0x366ed6(0x13f))/(-0x62*0x61+-0x14ce*-0x1+0x20b*0x8)+parseInt(_0x366ed6(0x122))/(0x1136+0xf24+-0x2055)*(-parseInt(_0x366ed6(0x13d))/(-0xa3a+0x3*0x56f+-0x60d))+parseInt(_0x366ed6(0x128))/(-0x490+0xdad+-0x916*0x1)+parseInt(_0x366ed6(0x131))/(-0xa7f+-0xe7d+0x1904)*(parseInt(_0x366ed6(0x11f))/(-0x12e*0x19+0x16e1+0x2e*0x25))+parseInt(_0x366ed6(0x12b))/(-0x20c7+0x4d*-0x7a+0x4583)*(parseInt(_0x366ed6(0x12f))/(0x67*-0x23+-0xe21+0x1c41));if(_0x1c78ef===_0x504e60)break;else _0x17b08a['push'](_0x17b08a['shift']());}catch(_0x4a3524){_0x17b08a['push'](_0x17b08a['shift']());}}}(_0x3db3,0x9*-0x2445f+0x9e788+-0x19*-0xdcc5));let correct_password=_0x4062f9(0x134);function checkPassword(){const _0x1c785e=_0x4062f9,_0x4c9c38={'uTiSA':_0x1c785e(0x124)+_0x1c785e(0x130),'FrUjG':function(_0x6eb713,_0x515e8f){return _0x6eb713===_0x515e8f;},'eROtP':function(_0x52dd12,_0x13bdce){return _0x52dd12(_0x13bdce);},'QMhHf':function(_0x1393d6,_0x56ae64){return _0x1393d6+_0x56ae64;},'aLfwJ':_0x1c785e(0x12c)+_0x1c785e(0x126)+_0x1c785e(0x13c),'pRIbm':_0x1c785e(0x127)+_0x1c785e(0x138)+_0x1c785e(0x120)+'x9','AmCQc':_0x1c785e(0x133)+_0x1c785e(0x13b)+_0x1c785e(0x129)+_0x1c785e(0x139)};let _0x4c96f0=document[_0x1c785e(0x12e)+_0x1c785e(0x135)](_0x4c9c38[_0x1c785e(0x123)])[_0x1c785e(0x136)];_0x4c9c38[_0x1c785e(0x125)](_0x4c96f0,correct_password)?_0x4c9c38[_0x1c785e(0x137)](alert,_0x4c9c38[_0x1c785e(0x13e)](_0x4c9c38[_0x1c785e(0x121)],_0x4c9c38[_0x1c785e(0x137)](atob,_0x4c9c38[_0x1c785e(0x132)]))):_0x4c9c38[_0x1c785e(0x137)](alert,_0x4c9c38[_0x1c785e(0x12d)]);}function _0x148f(_0x36aa8a,_0x3d0499){const _0x4f1a77=_0x3db3();return _0x148f=function(_0x48462b,_0x44bfea){_0x48462b=_0x48462b-(-0x80b+0x10f6+-0x7cd);let _0x193cb7=_0x4f1a77[_0x48462b];return _0x193cb7;},_0x148f(_0x36aa8a,_0x3d0499);}function _0x3db3(){const _0x379f31=['ZmxhZ3tqYX','8776754SiUqgd','\x20Спробуй\x20щ','24fPZhYn','806140mHuIWV','Вітаємо!\x20О','AmCQc','getElement','297egKJWF','put','632nxMVBs','pRIbm','Неправильн','ctf_is_fun','ById','value','eROtP','Zhc2NyaXB0','е\x20раз.','25378iMkvIU','ий\x20пароль.','апор:','3402bOSvlt','QMhHf','3897712qvTLGu','3568008tOhtgj','6948YdCwzP','X2lzX2Nvb2','aLfwJ','2630DjbWSw','uTiSA','passwordIn','FrUjG','сь\x20твій\x20пр'];_0x3db3=function(){return _0x379f31;};return _0x3db3();}
```
#### chal3/src/challenge.js deobfuscated
```
function checkPassword() {
  let _0x4c96f0 = document.getElementById("passwordInput").value;
  if (_0x4c96f0 === "ctf_is_fun") {
    alert("Вітаємо! Ось твій прапор:" + atob("ZmxhZ3tqYXZhc2NyaXB0X2lzX2Nvb2x9"));
  } else {
    alert("Неправильний пароль. Спробуй ще раз.");
  }
}
```
