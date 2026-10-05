# CVE Scanner 🛡️

Tools untuk memindai kerentanan (CVE) pada suatu sistem, aplikasi, atau website
berdasarkan versi dan teknologi yang terdeteksi. Cocok untuk **security audit
di lab sendiri**, **belajar vulnerability management**, dan **riset defensive**.

---

## ⚠️ Disclaimer

Tools ini **hanya untuk digunakan pada**:
- Sistem, server, atau aplikasi **milik sendiri**
- Lab pribadi yang **kamu kontrol penuh**
- Target **bug bounty** yang secara eksplisit mengizinkan di scope-nya

**DILARANG** menggunakan tools ini pada aset orang lain tanpa izin tertulis.
Penggunaan tanpa izin melanggar **UU ITE Pasal 30 & 46** dan bisa dikenai
sanksi pidana hingga **8 tahun penjara**.

Segala risiko dan tanggung jawab penggunaan ada pada pengguna.

---

## ✨ Fitur

- 🔍 **Deteksi Teknologi** — Mengidentifikasi server, framework, CMS, dan versi
  yang digunakan target (via header, HTML, dan fingerprint).
- 📋 **CVE Lookup** — Mencari CVE yang relevan berdasarkan teknologi & versi
  yang terdeteksi (sumber: NVD, CVE.org, Exploit-DB).
- 📊 **Severity Rating** — Menampilkan tingkat kerentanan (CVSS Score:
  Critical, High, Medium, Low) untuk setiap CVE.
- 📝 **Detailed Report** — Output dalam format JSON, HTML, atau teks yang
  mudah dibaca.
- 🎯 **Filter Severity** — Hanya menampilkan CVE dengan severity tertentu
  (misal: `--severity high,critical`).
- 🔗 **Referensi Lengkap** — Link ke NVD, CVE.org, dan advisory resmi.
- 💾 **Cache Lokal** — Menyimpan hasil lookup untuk mengurangi request
  ke API publik.

---

## 🛠️ Instalasi

### Prasyarat
- Python 3.8+
- pip

### Langkah
```bash
# Clone repository
git clone https://github.com/USERNAME/cve-scanner.git
cd cve-scanner

# Buat virtual environment (opsional tapi disarankan)
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt
