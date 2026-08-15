# 🔍 Phase 1: Initial Recon (Always start here)

### 1. Identify file type

file image.png

### 2. Check metadata

exiftool image.png

👉 Look for:

- Hidden comments
- Suspicious software tags
- GPS / timestamps

---

# 🧵 Phase 2: Basic Data Extraction

### 1. Extract readable strings

strings image.png | less

👉 Look for:

- Flags (`flag{}`)
- URLs
- Base64 blobs

---

### 2. Check for appended data

binwalk image.png

If something is found:

binwalk -e image.png  
cd _image.png.extracted

---

# 🧪 Phase 3: Steganography Tools

## 🔐 1. Steghide (Most common in CTFs)

steghide info image.jpg

If it says data is embedded:

steghide extract -sf image.jpg

👉 If password protected:

stegcracker image.jpg wordlist.txt

---

## 🎨 2. Zsteg (for PNG/BMP)

zsteg image.png

More aggressive:

zsteg -a image.png

---

## 📦 3. Outguess (JPEG stego)

outguess -r image.jpg output.txt

---

# 🔬 Phase 4: File Carving

If hidden files exist:

foremost image.png

Output goes to:

./output/

---

# 🧠 Phase 5: Advanced Analysis

## 🔎 1. Check for hidden archives

binwalk -e image.png

Look for:

- ZIP
- TAR
- GZIP

---

## 🧾 2. Manual extraction (if offset known)

dd if=image.png of=hidden.zip bs=1 skip=OFFSET

---

## 🔐 3. Decode Base64 (if found)

echo "encoded_text" | base64 -d

---

# 🧩 Phase 6: Visual Steganography

Use tools like:

stegsolve

👉 Look for:

- Bit planes
- Color anomalies
- Hidden QR codes

---

# ⚙️ Phase 7: Check Compression Tricks

Sometimes files are:

- XOR encoded
- Rotated
- Encrypted

Try:

xxd image.png | less

---

# 🔁 Phase 8: Iterate (MOST IMPORTANT)

CTFs often layer techniques:

Example chain:

image → steghide → zip → password → base64 → flag

---

# 🚨 Real-World Strategy (IMPORTANT)
When you get a file:

1. `file`
2. `exiftool`
3. `strings`
4. `binwalk`
5. `zsteg` (if PNG)
6. `steghide`
7. `foremost`
8. manual extraction
# Imp shit

zbarimg image.png - scan qr code
