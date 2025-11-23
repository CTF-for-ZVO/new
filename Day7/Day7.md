## Encoding
https://cyberchef.io/#recipe=To_HTML_Entity(true,'Hex%20entities')URL_Encode(true)To_Binary('Space',8)&input=ZmxhZ3szbmMwZDFuR30

https://www.dcode.fr/en

## Encrypting
https://cyberchef.io/#recipe=ROT13(true,true,false,13)&input=ZmxhZ3szbmMwZDFuR30

#### AES ECB
```
FROM python:3.10-slim

ARG flag="flag{ecb_aes_s3cret}"

WORKDIR /app

COPY src/ .
RUN pip install --no-cache-dir -r requirements.txt

RUN echo "$flag" > flag.txt

EXPOSE 5000

CMD ["python", "app.py"]

```

```
from flask import Flask, jsonify, send_from_directory
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os
import secrets

# Random 16 Bytes key
KEY = secrets.token_bytes(16) 

current_dir = os.path.dirname(os.path.abspath(__file__))
with open(current_dir+'/flag.txt', 'r') as f: FLAG = f.read().strip()

app = Flask(__name__)

@app.route('/')
def serve_source():
    return send_from_directory(current_dir, 'app.py')


@app.route('/encrypt/<plaintext>/')
def encrypt(plaintext):
    try:
        plaintext_bytes = bytes.fromhex(plaintext)
    except ValueError:
        return jsonify({"error": "Invalid hex string for plaintext"}), 400

    data_to_pad = plaintext_bytes + FLAG.encode()
    
    padded = pad(data_to_pad, 16)
    
    # 3. Ініціалізація AES у режимі ECB
    cipher = AES.new(KEY, AES.MODE_ECB)
    
    try:
        encrypted = cipher.encrypt(padded)
    except ValueError as e:
        return jsonify({"error": str(e)}), 500

    return jsonify({"ciphertext": encrypted.hex()})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
```
#### AES CBC
```
FROM python:3.10-slim

ARG flag="flag{access_granted}"

WORKDIR /app

COPY src/ .
RUN pip install --no-cache-dir -r requirements.txt

RUN echo "$flag" > flag.txt

EXPOSE 5000

CMD ["python", "app.py"]
```

```
from Crypto.Cipher import AES
import os
from Crypto.Util.Padding import pad, unpad
from datetime import datetime, timedelta
from flask import Flask, jsonify, send_from_directory
import secrets

# Random 16 Bytes key
KEY = secrets.token_bytes(16) 

current_dir = os.path.dirname(os.path.abspath(__file__))
with open(current_dir+'/flag.txt', 'r') as f: FLAG = f.read().strip()

app = Flask(__name__)

@app.route('/')
def serve_source():
    return send_from_directory(current_dir, 'app.py')


@app.route('/check_admin/<cookie>/<iv>/')
def check_admin(cookie, iv):
    cookie = bytes.fromhex(cookie)
    iv = bytes.fromhex(iv)

    try:
        cipher = AES.new(KEY, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(cookie)
        unpadded = unpad(decrypted, 16)
    except ValueError as e:
        return {"error": str(e)}

    if b"admin=True" in unpadded.split(b";"):
        return {"flag": FLAG}
    else:
        return {"error": "Only admin can read the flag"}


@app.route('/get_cookie/')
def get_cookie():
    expires_at = (datetime.today() + timedelta(days=1)).strftime("%s")
    cookie = f"admin=False;expiry={expires_at}".encode()

    iv = os.urandom(16)
    padded = pad(cookie, 16)
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(padded)
    ciphertext = iv.hex() + encrypted.hex()

    return {"cookie": ciphertext}

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
```
