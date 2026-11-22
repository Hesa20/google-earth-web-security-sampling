# Web Application Security Sampling: Google Earth

Dokumentasi proyek akhir **Google Cybersecurity Professional Certificate** yang memodelkan peran *Junior Cybersecurity Analyst* dalam melakukan *website security sampling* secara pasif, identifikasi aset, penilaian risiko, investigasi insiden berbasis simulasi log, serta penyusunan peta jalan mitigasi.

![Focus](https://img.shields.io/badge/Focus-Cybersecurity%20Assessment-blue)
![Tools](https://img.shields.io/badge/Tools-SQL%20%7C%20Python%20%7C%20Browser%20DevTools-informational)
![Methodology](https://img.shields.io/badge/Scope-Passive%20Sampling%20%26%20Lab%20Simulation-success)

---

## Disclaimer & Ruang Lingkup Etis

Proyek ini dilakukan murni untuk tujuan edukasi dan portofolio dengan mematuhi batasan keamanan dan etika:
- **No Real Attacks**: Tidak ada *penetration testing*, pemindaian kerentanan aktif (*active scanning*), eksploitasi sistem, maupun pengujian kredensial terhadap infrastruktur publik Google.
- **Passive Observation Only**: Pengumpulan data dilakukan hanya melalui observasi antarmuka terautentikasi milik sendiri dan dokumentasi publik resmi.
- **Simulated Lab Data**: Seluruh investigasi log dan deteksi anomali dijalankan menggunakan dataset simulasi lokal (`data/simulated_earth_logs.csv`) dengan alamat IP dokumentasi RFC 5737 dan akun fiktif.

---

## 1. Ringkasan Proyek & Postur Keamanan

- **Target Sampling**: Google Earth Web (platform geospasial berbasis web untuk eksplorasi citra 3D, *site analysis*, dan kolaborasi proyek pemetaan).
- **Kontrol Terobservasi**: Enkripsi transport HTTPS/TLS, autentikasi terpusat Google Single Sign-On (SSO), pembatasan kuota penyimpanan awan (*Standard Plan* 1 GB), dan pembatasan ekspor pada katalog *Data Layers*.
- **Slide Presentasi Lengkap**: Lihat [Google_Earth_Security_Sampling_Deck.pdf](docs/Google_Earth_Security_Sampling_Deck.pdf).

---

## 2. Pemetaan Permukaan Web & Klasifikasi Aset

| Kategori Surface | Komponen Terobservasi | Aset Internal Terkait | Klasifikasi Data | Pemilik Aset |
| :--- | :--- | :--- | :--- | :--- |
| **Public** | Overview, Plans, Versions | CDN, Tiles & 3D Imagery Server | Public | Tim Infrastruktur |
| **Web App** | Map Projects, Local KML Editor | Cloud Storage, KML Parser, Auth SSO | Restricted | Tim Engineering |
| **Data** | Data Layers, Storage 1 GB | Geospasial DB, File KML Pengguna | Confidential | Pemilik Proyek |
| **Email** | Share Project, Filter People | Layanan Notifikasi & IAM Akses | Internal | Admin Workspace |

---

## 3. Penilaian Risiko & Pemetaan Kepatuhan

| Risiko Utama | Threat & Vulnerability | Impact | Likelihood | Prioritas |
| :--- | :--- | :--- | :--- | :--- |
| **Kebocoran Proyek Peta** | Tautan proyek dibagikan publik oleh pengguna | Tinggi | Tinggi | **Kritis** |
| **Injeksi File KML Lokal** | Parsing XML/KML berbahaya di Local KML Editor | Tinggi | Sedang | **Tinggi** |
| **Penyalahgunaan Akun** | Sesi SSO dibajak pada perangkat bersama | Tinggi | Sedang | **Tinggi** |
| **Eksfiltrasi Data Layer** | Scraping visual pada katalog Data Layers | Sedang | Rendah | **Sedang** |

**Pemetaan Kepatuhan Regulasi**:
- **ISO/IEC 27001**: Kontrol Akses (A.9) terkait verifikasi hak akses berbagi proyek (*People* & *Owner*).
- **NIST CSF**: Fungsi *Protect* & *Detect* untuk pemantauan telemetri dan anomali sesi.
- **UU PDP Indonesia / GDPR**: Perlindungan data pribadi dan informasi lokasi pada proyek pengguna.

---

## 4. Investigasi Insiden & Bukti Teknis

### Skenario & Lini Masa Insiden (Simulasi Lab)
Simulasi mendeteksi lonjakan aktivitas ekspor file KML dan perubahan izin berbagi di luar jam kerja:
1. **02:14 WIB (`LOGIN_SUCCESS`)**: Login dari IP baru (`203.0.113.45`) pada akun `analyst_demo@workspace.local`.
2. **02:18 WIB (`CHANGE_SHARE_PERMISSION`)**: Perubahan izin akses proyek ke tautan terbuka.
3. **02:21 WIB (`EXPORT_KML`)**: Ekspor beruntun file KML proyek dalam rentang waktu singkat.
4. **02:30 WIB (Triage)**: Terkonfirmasi sebagai indikasi *account takeover* pada level akun pengguna, bukan kompromi server inti.

### Bukti 1: Observasi Pasif Antarmuka & Telemetri Jaringan
Observasi fitur *Export KML* dan permintaan telemetri jaringan (`log?format=json&hasfast=true`, `collect?...`) melalui *Browser DevTools*:

![Observasi Google Earth dan DevTools Network](evidence/01_google_earth_kml_export_devtools.jpg)

### Bukti 2: Automasi Deteksi Anomali (Python & SQL)
Skrip deteksi dijalankan pada dataset simulasi untuk menandai akun dengan total ekspor KML melebihi ambang batas (`threshold >= 5`):

![Eksekusi Skrip Deteksi Anomali Python di Google Colab](evidence/02_python_anomaly_detection_colab.png)

- **Kueri Investigasi SQL**: [`scripts/investigate_logs.sql`](scripts/investigate_logs.sql)
- **Skrip Automasi Python**: [`scripts/detect_kml_exfiltration.py`](scripts/detect_kml_exfiltration.py)
- **Notebook Eksperimen**: [`scripts/simulated_google_earth_logs.ipynb`](scripts/simulated_google_earth_logs.ipynb)

---

## 5. Peta Jalan Mitigasi (30 / 60 / 90 Hari)

- **30 Hari (Containment & Quick Wins)**: Pencabutan sesi aktif mencurigakan, kewajiban *Multi-Factor Authentication* (MFA), dan pengembalian izin proyek publik menjadi privat.
- **60 Hari (Hardening & Policy Control)**: Penerapan kebijakan *Data Loss Prevention* (DLP) untuk membatasi berbagi proyek ke domain eksternal serta validasi skema ketat pada pemrosesan KML.
- **90 Hari (Continuous Monitoring & Governance)**: Integrasi aturan deteksi ekspor KML ke dalam SIEM organisasi dan audit berkala hak akses *Owner*.

---

## Cara Menjalankan Skrip Secara Lokal

Pastikan Python 3 telah terpasang, lalu jalankan perintah berikut dari direktori utama repositori:

```bash
python scripts/detect_kml_exfiltration.py
```

Output yang diharapkan:

```text
[ALERT] Anomali Terdeteksi! User: analyst_demo@workspace.local | IP: 203.0.113.45 | Total KML Exports: 5
```