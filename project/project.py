#!/usr/bin/env python3
"""
===================================================================
Project: Automated Phishing & Malicious URL Detector
ระบบตรวจจับและวิเคราะห์ลิงก์หลอกลวงอัตโนมัติ (User-Friendly CLI)
===================================================================
"""

import os
import re
import ssl
import socket
import sys
import time
import urllib.parse
import requests
from datetime import datetime

# -------------------------------------------------------------------
# ANSI Colors & Formatting Helpers
# -------------------------------------------------------------------
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

# เปิดใช้งานสีบน Windows Command Prompt
if os.name == 'nt':
    os.system('')

SUSPICIOUS_KEYWORDS = ["login", "verify", "account", "update", "bank", "secure", "bonus", "claim", "free"]
HIGH_RISK_TLDS = [".xyz", ".top", ".tk", ".free", ".zip", ".review", ".country"]
SUSPICIOUS_BRANDS = ["paypal", "google", "facebook", "apple", "microsoft", "binance", "kbank"]


# -------------------------------------------------------------------
# Core Engine Class
# -------------------------------------------------------------------
class URLAnalyzer:
    """Class หลักสำหรับประมวลผลและคำนวณความเสี่ยงของ URL"""

    def __init__(self, url: str):
        # ลบขยะและวงเล็บ (), [], '' ออกจาก URL ที่ผู้ใช้พิมพ์มา
        cleaned = re.sub(r"[()\[\]'\" ]", "", url.strip())

        # จัดการ Prefix ของ Scheme
        if not cleaned.startswith("http://") and not cleaned.startswith("https://"):
            self.raw_url = f"http://{cleaned}"
        else:
            self.raw_url = cleaned

        try:
            self.parsed_url = urllib.parse.urlparse(self.raw_url)
            self.domain = self.parsed_url.netloc.split(":")[0]
        except Exception:
            self.parsed_url = None
            self.domain = self.raw_url

        self.risk_score = 0
        self.findings = []

    def check_structure(self):
        """1. ตรวจสอบโครงสร้างองค์ประกอบของ URL"""
        if not self.domain:
            return

        # เช็กการใช้ Direct IP Address
        ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
        if re.match(ip_pattern, self.domain):
            self.risk_score += 30
            self.findings.append(("CRITICAL", "ใช้หมายเลข IP Address ตรงๆ แทนชื่อโดเมนหลัก (+30)"))

        # เช็กความยาว URL
        if len(self.raw_url) > 75:
            self.risk_score += 10
            self.findings.append(("WARNING", f"ความยาว URL ยาวผิดปกติ ({len(self.raw_url)} ตัวอักษร) (+10)"))

        # เช็กสัญลักษณ์พิเศษ @
        if "@" in self.raw_url:
            self.risk_score += 15
            self.findings.append(("WARNING", "พบสัญลักษณ์พิเศษ '@' ซึ่งมักใช้ซ่อนที่อยู่เว็บแท้จริง (+15)"))

        # เช็ก Subdomains หลายชั้น
        subdomains = self.domain.split(".")
        if len(subdomains) > 3:
            self.risk_score += 10
            self.findings.append(("WARNING", f"มีการใช้ Subdomain ซ้อนกันหลายชั้น ({len(subdomains)} ชั้น) (+10)"))

        # เช็ก High Risk TLDs
        for tld in HIGH_RISK_TLDS:
            if self.domain.endswith(tld):
                self.risk_score += 15
                self.findings.append(("WARNING", f"ใช้นามสกุลโดเมนกลุ่มความเสี่ยงสูง '{tld}' (+15)"))
                break

    def check_keywords_and_brands(self):
        """2. ตรวจสอบคำต้องสงสัยและการแอบอ้างแบรนด์"""
        # สแกน Keyword
        for kw in SUSPICIOUS_KEYWORDS:
            if kw in self.raw_url.lower():
                self.risk_score += 10
                self.findings.append(("SUSPICIOUS", f"พบคำคีย์เวิร์ดต้องสงสัย '{kw}' (+10)"))

        # สแกนการแอบอ้างแบรนด์
        for brand in SUSPICIOUS_BRANDS:
            if brand in self.raw_url.lower() and not self.domain.endswith(f"{brand}.com"):
                self.risk_score += 25
                self.findings.append(
                    ("CRITICAL", f"มีแนวโน้มแอบอ้างชื่อแบรนด์ดัง '{brand.upper()}' นอกโดเมนจริง (+25)"))

    def check_ssl(self):
        """3. ตรวจสอบใบรับรองความปลอดภัย SSL/TLS"""
        if self.parsed_url and self.parsed_url.scheme != "https":
            self.risk_score += 20
            self.findings.append(("WARNING", "ไม่มีการเข้ารหัสความปลอดภัย HTTPS (โปรโตคอล HTTP แบบไม่ปลอดภัย) (+20)"))
            return

        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    exp_date = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                    if exp_date < datetime.now():
                        self.risk_score += 20
                        self.findings.append(("CRITICAL", "ใบรับรองความปลอดภัย SSL หมดอายุแล้ว (+20)"))
        except Exception:
            self.risk_score += 15
            self.findings.append(("WARNING", "ไม่สามารถยืนยันใบรับรอง SSL ของเว็บไซต์ได้ (+15)"))

    def check_http_response(self):
        """4. ตรวจสอบการตอบรับของเว็บไซต์และการ Redirect"""
        try:
            response = requests.get(self.raw_url, timeout=3, allow_redirects=True)
            if len(response.history) > 2:
                self.risk_score += 10
                self.findings.append(("WARNING",
                                      f"มีการเปลี่ยนเส้นทางเว็บ (Redirect) ซ้อนกันหลายครั้ง ({len(response.history)} ครั้ง) (+10)"))
        except Exception:
            pass

    def analyze(self):
        """รันกระบวนการตรวจสอบทั้งหมดและจำกัดคะแนนสูงสุดที่ 100"""
        self.check_structure()
        self.check_keywords_and_brands()
        self.check_ssl()
        self.check_http_response()

        # ควบคุมคะแนนให้อยู่ในช่วง 0 - 100
        final_score = min(self.risk_score, 100)
        return final_score, self.findings


# -------------------------------------------------------------------
# User Interface & Visual Helper Functions
# -------------------------------------------------------------------
def draw_header():
    """วาด Banner ส่วนหัวโปรแกรม"""
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"{CYAN}{BOLD}========================================================================={RESET}")
    print(f"{CYAN}{BOLD}          🔍 AUTOMATED PHISHING & MALICIOUS URL DETECTOR               {RESET}")
    print(f"{CYAN}            ระบบตรวจจับและวิเคราะห์ลิงก์หลอกลวงอัตโนมัติ                 {RESET}")
    print(f"{CYAN}{BOLD}========================================================================={RESET}\n")


def show_loading_animation():
    """แสดงแอนิเมชันหลอกตาเพิ่มความน่าสนใจระหว่างสแกน"""
    sys.stdout.write(f"{BOLD}[*] กำลังวิเคราะห์โครงสร้าง URL และความปลอดภัย... {RESET}")
    sys.stdout.flush()
    for _ in range(3):
        time.sleep(0.3)
        sys.stdout.write(f"{CYAN}.{RESET}")
        sys.stdout.flush()
    print("\n")


def make_progress_bar(score: int, length: int = 30) -> str:
    """สร้างหลอดแสดงระดับความเสี่ยง (Progress Bar)"""
    filled_length = int(length * score // 100)

    if score >= 45:
        color = RED
    elif score >= 20:
        color = YELLOW
    else:
        color = GREEN

    bar = '█' * filled_length + '░' * (length - filled_length)
    return f"{color}[{bar}] {score}/100 คะแนน{RESET}"


def print_result_card(url: str, score: int, findings: list):
    """แสดงผลลัพธ์การตรวจสอบในรูปแบบการ์ดที่อ่านง่ายที่สุด"""
    print(f"{BOLD}📌 รายงานผลการตรวจสอบ (Scan Report):{RESET}")
    print(f"• URL ที่ส่งเช็ก : {BOLD}{url}{RESET}")
    print(f"• เวลาที่สแกน    : {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n")

    # กำหนดสถานะ คำแนะนำ และสี
    if score >= 45:
        level_tag = f"{RED}{BOLD} [ HIGH RISK / อันตรายสูง ] ⚠️{RESET}"
        recommendation = f"{RED}คำแนะนำ: ห้ามคลิกเข้าใช้งานเด็ดขาด! มีแนวโน้มสูงมากว่าเป็นลิงก์ Phishing หรือเว็บอันตราย{RESET}"
    elif score >= 20:
        level_tag = f"{YELLOW}{BOLD} [ MEDIUM RISK / ความเสี่ยงปานกลาง ] ⚡{RESET}"
        recommendation = f"{YELLOW}คำแนะนำ: ควรเพิ่มความระมัดระวัง ตรวจสอบชื่อโดเมนให้แน่ชัดก่อนกรอกข้อมูลสำคัญ{RESET}"
    else:
        level_tag = f"{GREEN}{BOLD} [ LOW RISK / ปลอดภัย ] ✅{RESET}"
        recommendation = f"{GREEN}คำแนะนำ: ไม่พบปัจจัยเสี่ยงเด่นชัด สามารถใช้งานได้ตามปกติ{RESET}"

    print(f"ระดับความเสี่ยง : {level_tag}")
    print(f"ดัชนีความเสี่ยง : {make_progress_bar(score)}\n")

    print(f"{BOLD}🔍 รายละเอียดสิ่งที่ตรวจพบ (Scan Findings):{RESET}")
    if not findings:
        print(f"  {GREEN}✓ ไม่พบสิ่งผิดปกติหรือปัจจัยเสี่ยงในโครงสร้าง URL{RESET}")
    else:
        for tag, desc in findings:
            if tag == "CRITICAL":
                tag_str = f"{RED}[วิกฤต]{RESET}"
            elif tag == "WARNING":
                tag_str = f"{YELLOW}[เตือน]{RESET}"
            else:
                tag_str = f"{CYAN}[สงสัย]{RESET}"
            print(f"  • {tag_str} {desc}")

    print(f"\n💡 {BOLD}ข้อเสนอแนะระบบ:{RESET} {recommendation}")
    print(f"{CYAN}-------------------------------------------------------------------------{RESET}\n")


# -------------------------------------------------------------------
# Main Menu & Interactive Flow
# -------------------------------------------------------------------
def main():
    while True:
        draw_header()
        print(f"{BOLD}เลือกโหมดการใช้งาน:{RESET}")
        print("  [1] พิมพ์ URL เพื่อทำการตรวจจับเอง")
        print("  [2] รันตัวอย่างทดสอบที่ 1: โดเมนปลอดภัย (Safe Domain)")
        print("  [3] รันตัวอย่างทดสอบที่ 2: โดเมนต้องสงสัย (Suspicious Domain)")
        print("  [4] รันตัวอย่างทดสอบที่ 3: ลิงก์อันตราย/Phishing (Malicious Domain)")
        print("  [0] ออกจากโปรแกรม\n")

        choice = input(f"{BOLD}เลือกลำดับรายการ (0-4): {RESET}").strip()

        target_url = ""
        if choice == "1":
            target_url = input(f"\n{BOLD}กรอก URL ที่ต้องการตรวจสอบ: {RESET}").strip()
            if not target_url:
                continue
        elif choice == "2":
            target_url = "https://www.google.com"
        elif choice == "3":
            target_url = "https://free-bonus-claim-updates.com"
        elif choice == "4":
            target_url = "http://binance-secure-login-verify.free-account-update.com"
        elif choice == "0":
            print(f"\n{CYAN}ขอบคุณที่ใช้งานระบบ Automated Phishing Detector สวัสดีครับ!{RESET}\n")
            sys.exit(0)
        else:
            print(f"\n{RED}กรุณาเลือกรายการ 0-4 เท่านั้น{RESET}")
            time.sleep(1)
            continue

        print("\n")
        show_loading_animation()

        analyzer = URLAnalyzer(target_url)
        score, findings = analyzer.analyze()

        print_result_card(target_url, score, findings)

        input(f"{BOLD}กด [Enter] เพื่อกลับสู่เมนูหลัก...{RESET}")


if __name__ == "__main__":
    main()