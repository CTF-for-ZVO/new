#!/usr/bin/env python3
import os, base64
from PIL import Image
import piexif
OUTPUT_DIR = "generated"
os.makedirs(OUTPUT_DIR, exist_ok=True)
FLAG = "FLAG{f1l3_r3c0v3ry_h3r0}"
FLAG_B64 = base64.b64encode(FLAG.encode()).decode()
print("[1/2] Creating JPEG with flag in EXIF...")
img = Image.new('RGB', (400, 200), color=(100, 150, 200))
# Hide FLAG in EXIF metadata (base64 encoded)
exif_dict = {"0th": {}, "Exif": {}, "GPS": {}, "1st": {}, "thumbnail": None}
exif_dict["Exif"][piexif.ExifIFD.UserComment] = FLAG_B64.encode('ascii')
exif_dict["0th"][piexif.ImageIFD.Make] = b"Recovery Camera"
exif_bytes = piexif.dump(exif_dict)
normal_jpg = os.path.join(OUTPUT_DIR, "normal.jpg")
img.save(normal_jpg, 'JPEG', exif=exif_bytes)
print("[2/2] Corrupting JPEG (removing header)...")
broken_jpg = os.path.join(OUTPUT_DIR, "broken.jpg")
with open(normal_jpg, 'rb') as f:
    data = f.read()
# Видалити перші 10 байт (JPEG header)
with open(broken_jpg, 'wb') as f:
    f.write(data[10:])
os.remove(normal_jpg)
print(f"[+] Corrupted JPEG created: {broken_jpg}")
print("[*] File is missing JPEG magic bytes!")
print("[*] Solve:")
print("    1. Fix header: printf '\\xFF\\xD8\\xFF\\xE0' | cat - broken.jpg > fixed.jpg")
print("    2. Extract EXIF: exiftool fixed.jpg | grep 'User Comment'")
print("    3. Decode base64: echo '<key>' | base64 -d")
print(f"[!] TIP: strings won't show readable FLAG!")
print(f"[!] FLAG is base64 encoded in EXIF metadata")
