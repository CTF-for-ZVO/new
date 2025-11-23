#!/usr/bin/env python3
"""
Task 5: Metadata Forensics - Generator
Генерує JPEG та PDF з закодованим прапором у метаданих
"""

import os
import sys
import base64

try:
    from PIL import Image
    from PIL.ExifTags import TAGS
    import piexif
except ImportError:
    print("[!] Pillow or piexif not installed!")
    print("[*] Installing: pip install Pillow piexif")
    sys.exit(1)

try:
    from PyPDF2 import PdfWriter, PdfReader
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import letter
except ImportError:
    print("[!] PyPDF2 or reportlab not installed!")
    print("[*] Installing: pip install PyPDF2 reportlab")
    sys.exit(1)

# Конфігурація

FLAG="flag{m3t4d4t4_t3lls_s3cr3ts}"

OUTPUT_DIR = "generated"
PHOTO_FILE = "photo.jpg"
PDF_FILE = "document.pdf"
FLAG_PART1 = FLAG[:10]
FLAG_PART2 = FLAG[10:]

# Encode обидві частини
FLAG_PART1_B64 = base64.b64encode(FLAG_PART1.encode()).decode()
# Для Part 2 використаємо hex encoding
FLAG_PART2_HEX = FLAG_PART2.encode().hex()

def create_photo_with_metadata():
    """Створює JPEG з base64 encoded metadata"""
    output_path = os.path.join(OUTPUT_DIR, PHOTO_FILE)

    print(f"[*] Generating photo: {output_path}")

    # Створити просте зображення
    img = Image.new('RGB', (800, 600), color=(100, 150, 200))

    # Додати текст (опціонально)
    from PIL import ImageDraw, ImageFont
    draw = ImageDraw.Draw(img)
    draw.text((300, 280), "Sample Photo", fill=(255, 255, 255))

    # Створити EXIF дані
    exif_dict = {
        "0th": {},
        "Exif": {},
        "GPS": {},
        "1st": {},
        "thumbnail": None
    }

    # Додати метадані з base64 encoded FLAG PART 1
    # UserComment (0x9286) - в Exif IFD
    # ВАЖЛИВО: закодовано в base64!
    exif_dict["Exif"][piexif.ExifIFD.UserComment] = FLAG_PART1_B64.encode('ascii')

    # Додати інші реалістичні дані
    exif_dict["0th"][piexif.ImageIFD.Make] = b"Canon"
    exif_dict["0th"][piexif.ImageIFD.Model] = b"EOS 5D Mark IV"
    exif_dict["0th"][piexif.ImageIFD.Software] = b"Adobe Photoshop 2023"
    exif_dict["0th"][piexif.ImageIFD.Artist] = b"John Doe"
    exif_dict["0th"][piexif.ImageIFD.Copyright] = b"Copyright 2024"
    
    # Додати GPS дані (benign - реальні координати Київа)
    exif_dict["GPS"][piexif.GPSIFD.GPSLatitudeRef] = b'N'
    exif_dict["GPS"][piexif.GPSIFD.GPSLatitude] = [(50, 1), (27, 1), (0, 1)]  # 50.45° N
    exif_dict["GPS"][piexif.GPSIFD.GPSLongitudeRef] = b'E'
    exif_dict["GPS"][piexif.GPSIFD.GPSLongitude] = [(30, 1), (31, 1), (0, 1)]  # 30.52° E

    # Конвертувати в байти
    exif_bytes = piexif.dump(exif_dict)

    # Зберегти з EXIF
    img.save(output_path, "JPEG", exif=exif_bytes, quality=95)

    print(f"[+] Photo created with encoded metadata!")
    print(f"[+] Original: {FLAG_PART1}")
    print(f"[+] Encoded (base64): {FLAG_PART1_B64}")
    print(f"[+] Hidden in EXIF UserComment")

    return output_path

def create_pdf_with_metadata():
    """Створює PDF з hex encoded metadata"""
    output_path = os.path.join(OUTPUT_DIR, PDF_FILE)

    print(f"[*] Generating PDF: {output_path}")

    # Створити простий PDF
    temp_pdf = os.path.join(OUTPUT_DIR, "temp.pdf")
    c = canvas.Canvas(temp_pdf, pagesize=letter)

    # Додати контент
    c.setFont("Helvetica", 24)
    c.drawString(100, 700, "Confidential Document")
    c.setFont("Helvetica", 12)
    c.drawString(100, 650, "This is a sample PDF document.")
    c.drawString(100, 630, "Nothing suspicious here...")
    c.drawString(100, 600, "Annual Financial Report 2024")

    c.save()

    # Відкрити PDF і додати метадані
    reader = PdfReader(temp_pdf)
    writer = PdfWriter()

    # Копіювати сторінки
    for page in reader.pages:
        writer.add_page(page)

    # Додати метадані з hex encoded FLAG PART 2
    # ВАЖЛИВО: закодовано в hex!
    writer.add_metadata({
        '/Author': FLAG_PART2_HEX,
        '/Title': 'Annual Report 2024',
        '/Subject': 'Financial Data',
        '/Creator': 'Microsoft Word',
        '/Producer': 'Adobe Acrobat Pro',
        '/Keywords': 'finance, report, annual, 2024'
    })

    # Записати фінальний PDF
    with open(output_path, 'wb') as f:
        writer.write(f)

    # Видалити temp
    os.remove(temp_pdf)

    print(f"[+] PDF created with encoded metadata!")
    print(f"[+] Original: {FLAG_PART2}")
    print(f"[+] Encoded (hex): {FLAG_PART2_HEX}")
    print(f"[+] Hidden in Author field")

    return output_path

def generate_files():
    """Генерує обидва файли"""
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print(f"[*] Output directory: {OUTPUT_DIR}")
    print(f"[*] Complete flag: {FLAG_PART1}{FLAG_PART2}")
    print()
    print("[*] Encoding strategy:")
    print(f"    Part 1: Base64 in JPEG EXIF")
    print(f"    Part 2: Hex in PDF metadata")
    print()

    # Генерувати фото
    photo = create_photo_with_metadata()
    print()

    # Генерувати PDF
    pdf = create_pdf_with_metadata()
    print()

    print(f"[+] Files generated successfully!")
    print(f"[+] Photo: {photo} ({os.path.getsize(photo)} bytes)")
    print(f"[+] PDF: {pdf} ({os.path.getsize(pdf)} bytes)")
    print()
    print("[*] Analysis approach:")
    print(f"    1. Extract EXIF: exiftool {PHOTO_FILE}")
    print(f"    2. Find UserComment: exiftool {PHOTO_FILE} | grep Comment")
    print(f"    3. Decode base64: echo '{FLAG_PART1_B64}' | base64 -d")
    print()
    print(f"    4. Extract PDF metadata: exiftool {PDF_FILE}")
    print(f"    5. Find Author: exiftool {PDF_FILE} | grep Author")
    print(f"    6. Decode hex: echo '{FLAG_PART2_HEX}' | xxd -r -p")
    print()
    print("[!] TIP: strings won't show readable FLAG!")
    print("[!] Both parts are encoded - need exiftool + decoding")
    print()
    print(f"[✓] Complete flag: {FLAG_PART1}{FLAG_PART2}")

def main():
    print("=" * 60)
    print("Task 5: Metadata Forensics - Advanced Generator")
    print("=" * 60)
    print()

    generate_files()

    print()
    print("[✓] Generation complete!")
    print()
    print("Challenge: Extract and decode FLAG from metadata")
    print("Difficulty: Both parts are encoded (base64 + hex)")

if __name__ == "__main__":
    main()
