import re
import socket
import ssl
import sys
from datetime import datetime
from urllib.parse import urlparse

# รายการคำต้องสงสัยและแบรนด์เสี่ยง
SUSPICIOUS_KEYWORDS = ['login', 'verify', 'account', 'update', 'bank', 'secure', 'bonus', 'claim', 'free']
TARGET_BRANDS = ['paypal', 'binance', 'kbank', 'google', 'facebook']
HIGH_RISK_TLDS = ['.xyz', '.top', '.tk', '.free', '.zip']
CUSTOM_BLACKLIST = [
    "http://104.28.18.2/paypal-login-verify.xyz",
    "https://free-bonus-claim-updates.com"
]

def analyze_url(url):
    score = 0
    findings = []
    
    # 1. ทำความสะอาดข้อความ URL
    clean_url = re.sub(r'[()\[\]\'"]', '', url).strip()
    
    if not clean_url.startswith(('http://', 'https://')):
        clean_url = 'http://' + clean_url

    parsed = urlparse(clean_url)
    domain = parsed.netloc.split(':')[0]

    # 2. ตรวจสอบ Blacklist
    for bl_item in CUSTOM_BLACKLIST:
        if bl_item.lower() in clean_url.lower():
            score += 50
            findings.append("🚨 ตรวจพบในฐานข้อมูลความเสี่ยงอันตราย (Custom Blacklist)")
            break

    # 3. ตรวจสอบการใช้ IP Address ตรงๆ
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
        score += 30
        findings.append("⚠️ ใช้หมายเลข IP Address ตรงๆ แทนชื่อโดเมนหลัก")

    # 4. ตรวจสอบ HTTPS
    if parsed.scheme != 'https':
        score += 20
        findings.append("⚠️ ไม่มีการเข้ารหัสความปลอดภัย HTTPS (HTTP Unsecured)")

    # 5. ตรวจสอบคำคีย์เวิร์ดต้องสงสัย
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in clean_url.lower():
            score += 10
            findings.append(f"🔍 พบคำคีย์เวิร์ดต้องสงสัย '{kw}' ใน URL")

    # 6. ตรวจสอบการแอบอ้างแบรนด์ดัง
    for brand in TARGET_BRANDS:
        if brand in clean_url.lower() and not domain.endswith(f"{brand}.com"):
            score += 25
            findings.append(f"🚨 มีแนวโน้มแอบอ้างแบรนด์ดัง '{brand.upper()}' นอกโดเมนจริง")

    # 7. ตรวจสอบ High-Risk TLD
    for tld in HIGH_RISK_TLDS:
        if domain.endswith(tld):
            score += 15
            findings.append(f"⚠️ ใช้นามสกุลโดเมนความเสี่ยงสูง ({tld})")

    # สรุปคะแนนสูงสุดไม่เกิน 100
    final_score = min(score, 100)
    
    if final_score >= 45:
        risk_level = "HIGH RISK ⚠️"
    elif final_score >= 20:
        risk_level = "MEDIUM RISK ⚡"
    else:
        risk_level = "LOW RISK ✅"

    return {
        "url": clean_url,
        "score": final_score,
        "level": risk_level,
        "findings": findings
    }

def main():
    print("=" * 60)
    print(" 🛡️  PhishGuard Core Engine - CLI Test Mode")
    print("=" * 60)
    
    test_url = input("กรอก URL ที่ต้องการทดสอบสแกน: ").strip()
    if not test_url:
        test_url = "http://104.28.18.2/paypal-login-verify.xyz"
        print(f"[*] ใช้ค่าเริ่มต้น: {test_url}")

    result = analyze_url(test_url)
    
    print("\n--- ผลการวิเคราะห์ ---")
    print(f"URL: {result['url']}")
    print(f"Risk Score: {result['score']} / 100")
    print(f"Risk Level: {result['level']}")
    print("รายละเอียดสิ่งผิดปกติ:")
    if result['findings']:
        for item in result['findings']:
            print(f"  - {item}")
    else:
        print("  - ไม่พบปัจจัยเสี่ยงในโครงสร้าง URL นี้")
    print("=" * 60)

if __name__ == "__main__":
    main()
