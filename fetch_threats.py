import csv
import json
import os
import re
import urllib.error
import urllib.request
from urllib.parse import urlparse

# --- ÇIKTI DOSYALARI ---
OUTPUT_IP = "threat_ip.txt"
OUTPUT_DOMAIN = "threat_domain.txt"
OUTPUT_URL = "threat_url.txt"
OUTPUT_HASH = "threat_hash.txt"

HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ThreatBot/4.0'}

# --- REGEX KALIPLARI ---
IP_REGEX = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/[0-9]{1,2})?$')
DOMAIN_REGEX = re.compile(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')
HASH_MD5_REGEX = re.compile(r'^[a-fA-F0-9]{32}$')
HASH_SHA256_REGEX = re.compile(r'^[a-fA-F0-9]{64}$')

def fetch_data(url, custom_headers=None, timeout=15):
    try:
        headers = custom_headers if custom_headers else HEADERS
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode('utf-8', errors='ignore')
    except Exception as e:
        print(f"[-] Hata [{url}]: {e}")
        return None

def classify_and_add(raw_entry, target_set):
    if not raw_entry:
        return
    entry = raw_entry.strip().strip("'\"")
    if entry and not entry.startswith("#") and not entry.startswith(";"):
        target_set.add(entry)

def load_existing_set(filepath):
    """Mevcut yerel dosyayı okuyup set olarak döndürür."""
    if not os.path.exists(filepath):
        return set()
    with open(filepath, "r", encoding="utf-8") as f:
        return set(line.strip() for line in f if line.strip())

def save_and_report_diff(filename, new_set, label):
    """Eski dosya ile yenisini karşılaştırır, farkları basar ve dosyayı kaydeder."""
    old_set = load_existing_set(filename)
    added = new_set - old_set
    removed = old_set - new_set

    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(new_set)))

    print(f"\n--- {label} İSTATİSTİKLERİ ---")
    print(f"  Toplam Kayıt  : {len(new_set)}")
    print(f"  ➕ Yeni Eklenen : {len(added)}")
    print(f"  ➖ Listeden Çıkan: {len(removed)}")

# ==========================================
# 🌐 İSTİHBARAT KAYNAKLARI
# ==========================================

# 1. TÜRKİYE (USOM)
def fetch_usom(all_entries):
    urls = ["https://www.usom.gov.tr/url-list.txt", "https://www.usom.gov.tr/api/address/index"]
    for url in urls:
        raw = fetch_data(url)
        if raw:
            for line in raw.splitlines():
                classify_and_add(line, all_entries)
    print("[+] USOM tamamlandı.")

# 2. ABD (CISA)
def fetch_cisa_usa(all_entries):
    raw = fetch_data("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    if raw:
        try:
            data = json.loads(raw)
            for item in data.get("vulnerabilities", []):
                if "notes" in item:
                    classify_and_add(item["notes"], all_entries)
        except Exception:
            pass
    print("[+] CISA USA tamamlandı.")

# 3. AVRUPA BİRLİĞİ (CERT-EU)
def fetch_cert_eu(all_entries):
    raw = fetch_data("https://cert.europa.eu/static/ioc/ioc-list.txt")
    if raw:
        for line in raw.splitlines():
            classify_and_add(line, all_entries)
    print("[+] CERT-EU tamamlandı.")

# 4. ALMANYA (CERT-Bund) & BLOCKLIST.DE
def fetch_germany(all_entries):
    urls = [
        "https://lists.blocklist.de/lists/all.txt",
        "https://raw.githubusercontent.com/bsi-kb/threat-intelligence/main/iocs.txt"
    ]
    for url in urls:
        raw = fetch_data(url)
        if raw:
            for line in raw.splitlines():
                classify_and_add(line, all_entries)
    print("[+] Almanya (Blocklist.de & BSI) tamamlandı.")

# 5. FRANSA (ANSSI / CERT-FR)
def fetch_france(all_entries):
    raw = fetch_data("https://raw.githubusercontent.com/cert-fr/ioc/main/iocs.txt")
    if raw:
        for line in raw.splitlines():
            classify_and_add(line, all_entries)
    print("[+] Fransa (CERT-FR) tamamlandı.")

# 6. İSVİÇRE (SWITCH / NCSC-CH)
def fetch_switzerland(all_entries):
    raw = fetch_data("https://www.switch.ch/export/sites/default/about/news/2021/CERT-iocs.txt")
    if raw:
        for line in raw.splitlines():
            classify_and_add(line, all_entries)
    print("[+] İsviçre (NCSC-CH) tamamlandı.")

# 7. AVUSTURYA (CERT.AT)
def fetch_austria(all_entries):
    raw = fetch_data("https://cert.at/static/iocs.txt")
    if raw:
        for line in raw.splitlines():
            classify_and_add(line, all_entries)
    print("[+] Avusturya (CERT.AT) tamamlandı.")

# 8. ABUSE.CH EKOSİSTEMİ (URLhaus, ThreatFox, Bazaar, Feodo)
def fetch_abuse_ch(all_entries):
    endpoints = [
        "https://urlhaus.abuse.ch/downloads/csv_online/",
        "https://threatfox.abuse.ch/export/csv/recent/",
        "https://bazaar.abuse.ch/export/txt/sha256/recent/",
        "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"
    ]
    for url in endpoints:
        raw = fetch_data(url)
        if raw:
            for line in raw.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    if '","' in line:
                        for part in line.split('","'):
                            clean_part = part.replace('"', '').strip()
                            if ":" in clean_part and not clean_part.startswith("http"):
                                clean_part = clean_part.split(":")[0]
                            classify_and_add(clean_part, all_entries)
                    else:
                        classify_and_add(line, all_entries)
    print("[+] Abuse.ch Full Ekosistemi tamamlandı.")

# 9. GLOBAL PHISHING & IP FEEDS (OpenPhish, PhishTank, Spamhaus, Emerging Threats)
def fetch_global_feeds(all_entries):
    # OpenPhish
    raw_op = fetch_data("https://openphish.com/feed.txt")
    if raw_op:
        for line in raw_op.splitlines():
            classify_and_add(line, all_entries)

    # PhishTank
    raw_pt = fetch_data("https://data.phishtank.com/data/online-valid.csv", timeout=12)
    if raw_pt:
        try:
            reader = csv.DictReader(raw_pt.splitlines())
            for row in reader:
                if row and row.get('url'):
                    classify_and_add(row['url'], all_entries)
        except Exception:
            pass

    # Emerging Threats
    raw_et = fetch_data("https://rules.emergingthreats.net/freetargets/compromised-ips.txt")
    if raw_et:
        for line in raw_et.splitlines():
            classify_and_add(line, all_entries)

    # Spamhaus DROP
    for sh_url in ["https://www.spamhaus.org/drop/drop.txt", "https://www.spamhaus.org/drop/edrop.txt"]:
        raw_sh = fetch_data(sh_url)
        if raw_sh:
            for line in raw_sh.splitlines():
                if line and not line.startswith(";"):
                    cidr = line.split(";")[0].strip()
                    classify_and_add(cidr, all_entries)

    print("[+] Global Phishing ve IP Feeds tamamlandı.")

# ==========================================
# ⚙️ AYRIŞTIRMA VE KATEGORİZE ETME
# ==========================================

def process_and_categorize(all_raw_entries):
    ip_set = set()
    domain_set = set()
    url_set = set()
    hash_set = set()

    for item in all_raw_entries:
        item = item.strip()
        if not item or len(item) < 3:
            continue

        # 1. Zararlı Hash Kontrolü (MD5 / SHA256)
        if HASH_MD5_REGEX.match(item) or HASH_SHA256_REGEX.match(item):
            hash_set.add(item.lower())
            continue

        # 2. Tam URL ise ayrıştır
        if item.startswith("http://") or item.startswith("https://"):
            url_set.add(item)
            try:
                parsed = urlparse(item)
                hostname = parsed.hostname
                if hostname:
                    hostname = hostname.strip()
                    if IP_REGEX.match(hostname):
                        ip_set.add(hostname)
                    elif DOMAIN_REGEX.match(hostname):
                        domain_set.add(hostname)
            except Exception:
                pass
            continue

        # 3. Yalın IP veya CIDR (1.2.3.4 veya 1.2.3.0/24)
        clean_ip = item.split('/')[0]
        if IP_REGEX.match(item) or IP_REGEX.match(clean_ip):
            ip_set.add(item)
            continue

        # 4. Yalın Domain
        if DOMAIN_REGEX.match(item):
            domain_set.add(item)
            continue

        # 5. Port içeren veya path içeren ham girdiler (ör. 1.2.3.4:8080)
        clean_host = item.split('/')[0].split(':')[0]
        if IP_REGEX.match(clean_host):
            ip_set.add(clean_host)
        elif DOMAIN_REGEX.match(clean_host):
            domain_set.add(clean_host)

    return ip_set, domain_set, url_set, hash_set

# ==========================================
# 🚀 ANA ÇALIŞTIRICI
# ==========================================

def main():
    print("=== TEHDİT İSTİHBARATI VERİ TOPLAMA BAŞLADI ===\n")
    raw_entries = set()

    # Tüm Kaynakları Çalıştır
    fetch_usom(raw_entries)
    fetch_cisa_usa(raw_entries)
    fetch_cert_eu(raw_entries)
    fetch_germany(raw_entries)
    fetch_france(raw_entries)
    fetch_switzerland(raw_entries)
    fetch_austria(raw_entries)
    fetch_abuse_ch(raw_entries)
    fetch_global_feeds(raw_entries)

    print("\n[+] Veriler ayrıştırılıyor ve kategorize ediliyor...")
    ip_list, domain_list, url_list, hash_list = process_and_categorize(raw_entries)

    # Karşılaştırmalı Kaydetme ve Raporlama
    save_and_report_diff(OUTPUT_IP, ip_list, "IP ADRESLERİ")
    save_and_report_diff(OUTPUT_DOMAIN, domain_list, "DOMAINLER")
    save_and_report_diff(OUTPUT_URL, url_list, "URL'LER")
    save_and_report_diff(OUTPUT_HASH, hash_list, "HASH'LER (MD5/SHA256)")

    print("\n[İŞLEM TAMAMLANDI]")

if __name__ == "__main__":
    main()
