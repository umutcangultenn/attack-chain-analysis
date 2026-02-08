# 🛡️ Attack Chain & Root Cause Analysis System

![Status](https://img.shields.io/badge/Status-Active-success)
![Python](https://img.shields.io/badge/Python-3.9+-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.109-green)
![License](https://img.shields.io/badge/License-MIT-purple)

**Attack Chain**, güvenlik test raporlarını (QA) ve canlı sistem loglarını (Runtime) birleştirerek siber saldırı senaryolarını analiz eden yeni nesil bir güvenlik aracıdır.

---

## 🚀 Proje Hakkında

Geleneksel güvenlik araçları genellikle tek bir bulguya odaklanır: *"Burada SQL Injection var."* veya *"Burada 500 hatası alındı."*

**Attack Chain** ise bütüncül yaklaşır:
> *"SQL Injection zafiyeti kullanılarak, saat 14:05'te `/admin` paneline yetkisiz erişim sağlandı ve veritabanından veri sızdırıldı."*

Bu sistem, **OWASP ZAP** gibi tarama araçlarının çıktılarını, sunucu **Access/Auth Logları** ile korele ederek saldırının hikayesini (Attack Chain) oluşturur ve kök neden (Root Cause) analizi yapar.

## ✨ Temel Özellikler

- **🔍 Hibrit Analiz:** Statik zafiyet tarama sonuçları ile dinamik log verilerini eşleştirir.
- **🔗 Zincirleme (Chaining):** İlişkisiz görünen olayları birleştirip saldırı zinciri oluşturur.
- **🎯 Kök Neden Analizi:** Saldırının hangi güvenlik açığından kaynaklandığını nokta atışı tespit eder.
- **📊 Risk Skorlama:** Olayın ciddiyetine ve etki alanına göre dinamik risk puanı hesaplar (0-100).
- **🎨 Modern Dashboard:** Analist dostu, karanlık mod (Dark Mode) arayüz.

## 🛠️ Kurulum

### Gereksinimler
- Python 3.9 veya üzeri
- Modern bir web tarayıcısı

### Adım 1: Depoyu Klonlayın
```bash
git clone https://github.com/umutcangultenn/attack-chain-analysis.git
cd attack-chain-analysis
```

### Adım 2: Backend'i Başlatın
```bash
cd backend
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

### Adım 3: Frontend'i Başlatın
Yeni bir terminalde:
```bash
cd frontend
python3 -m http.server 3000
```

Tarayıcınızda **`http://localhost:3000`** adresine gidin.

## 🧪 Nasıl Test Edilir?

Proje içerisinde hazır test verileri (Demo Data) bulunmaktadır. Hızlıca test etmek için:

1. Arayüzde **"Load Demo Data (Scenario 2)"** butonuna tıklayın.
   - *Bu işlem, sisteminize örnek bir "Path Traversal" saldırı senaryosu yükler.*
2. **"Start Analysis"** butonuna tıklayın.
3. Aşağıda beliren **kırmızı riskli** senaryo kartına tıklayarak detayları inceleyin.

Alternatif olarak `backend/sample_data` klasöründeki dosyaları manuel yükleyebilirsiniz.

## 🏗️ Mimari Yapı

| Bileşen | Teknoloji | Açıklama |
|---------|-----------|-----------|
| **Backend** | Python, FastAPI | Rest API, Korelasyon Motoru, Log Parser |
| **Frontend** | HTML5, CSS3, JS | Kullanıcı Arayüzü, API Entegrasyonu |
| **Veri Tabanı** | In-Memory | Prototip aşaması için RAM üzerinde çalışır |

## 🔒 Güvenlik Notları
- Bu uygulama **sadece analiz amaçlıdır**. Gerçek saldırı gerçekleştirmez.
- Upload edilen dosyalar geçici olarak işlenir ve saklanmaz (In-memory DB kullanıldığı için restart sonrası silinir).
- Prodüksiyon ortamında kullanmadan önce Auth mekanizması eklenmesi önerilir.

---
*Geliştirici: Umut*
