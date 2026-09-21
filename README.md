# 🛡️ PhishGuard - Automated Phishing & Malicious URL Detector

![License](https://img.shields.io/badge/license-MIT-blue)
![Python](https://img.shields.io/badge/Python-3.x-green)
![TailwindCSS](https://img.shields.io/badge/Tailwind-CSS-38bdf8)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

**PhishGuard** คือระบบตรวจจับและวิเคราะห์ความเสี่ยงของ URL/ลิงก์หลอกลวงแบบอัตโนมัติ พัฒนาขึ้นด้วย Multi-check Framework เพื่อช่วยประเมินภัยคุกคาม Cyber Security เบื้องต้น เช่น Phishing, Typosquatting และ Malicious Links ก่อนเข้าใช้งานจริง

🌐 **Live Demo Website:** [https://qazwsx4297-a11y.github.io/phishguard/](https://qazwsx4297-a11y.github.io/phishguard/)

---

## ✨ Key Features (คุณสมบัติหลัก)
- **Multi-check Framework Analysis:** วิเคราะห์ความเสี่ยงแบบหลายมิติ ครอบคลุมทั้ง Structure, Heuristics, SSL Certificate และ HTTP Responses
- **Dynamic Risk Score (0-100):** ประมวลผลคะแนนความเสี่ยงพร้อมจัดเกรดระดับความปลอดภัย (Low Risk / Medium Risk / High Risk)
- **Interactive Dark Mode Web UI:** หน้าจอแดชบอร์ดสไตล์ Cybersecurity อ่านง่าย ใช้งานสะดวก
- **Custom Blacklist Database Management:** มีระบบจัดการบันทึกและลบ URL ต้องสงสัยในฐานข้อมูลเฝ้าระวัง

---

## 🔍 Detection Framework (เกณฑ์การวิเคราะห์)
1. **URL Structure Check:** ตรวจสอบ Direct IP Address, สัญลักษณ์พิเศษ (`@`), Subdomains หลายชั้น และ High-Risk TLDs (`.xyz`, `.top`, `.free`)
2. **Heuristic & Brand Impersonation Check:** ตรวจจับคำคีย์เวิร์ดต้องสงสัย (`login`, `verify`, `account`) และสแกนการแอบอ้างแบรนด์ดังนอกโดเมนจริง
3. **SSL/TLS Inspection:** ตรวจสอบการเข้ารหัส HTTPS และสถานะความถูกต้องของใบรับรอง SSL
4. **HTTP Response & Blacklist Check:** ตรวจสอบ Status Code และเช็กประวัติกับฐานข้อมูลเฝ้าระวัง

---

## 🛠️ Tech Stack & Dependencies
- **Core Engine:** Python 3 (`urllib.parse`, `re`, `ssl`, `socket`, `requests`)
- **Frontend UI:** HTML5, Tailwind CSS, JavaScript (ES6)
- **Deployment:** GitHub Pages / Static Web Hosting

---

## 💻 How to Run Locally (การติดตั้งและทดสอบในเครื่อง)

1. Clone Repository นี้ลงเครื่อง:
   ```bash
   git clone [https://github.com/qazwsx4297-a11y/phishguard.git](https://github.com/qazwsx4297-a11y/phishguard.git)
