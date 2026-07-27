import json
import re
import os
import urllib.request
import urllib.parse
import urllib.error
from urllib.parse import urlparse

# --- ÇIKTI DOSYALARI ---
OUTPUT_IP = "threat_ip.txt"
OUTPUT_DOMAIN = "threat_domain.txt"
OUTPUT_URL = "threat_url.txt"
OUTPUT_HASH = "threat_hash.txt"

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ThreatIntelEngine/10.0',
    'Accept': 'application/json, text/plain, */*'
}

# --- BEYAZ LİSTE (WHITELIST) ---
WHITELIST_IPS = {
    "8.8.8.8", "8.8.4.4",          # Google DNS
    "1.1.1.1", "1.0.0.1",          # Cloudflare DNS
    "9.9.9.9", "149.112.112.112",  # Quad9 DNS
    "208.67.222.222", "208.67.220.220", # OpenDNS
    "127.0.0.1", "::1"             # Localhost
}

WHITELIST_DOMAINS = {
    "google.com", "cloudflare.com", "microsoft.com", 
    "apple.com", "github.com", "amazon.com"
}

# --- REGEX TANIMLARI ---
IP_REGEX = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/[0-9]{1,2})?$')
DOMAIN_REGEX = re.compile(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')
HASH_MD5_REGEX = re.compile(r'^[a-fA-F0-9]{32}$')
HASH_SHA256_REGEX = re.compile(r'^[a-fA-F0-9]{64}$')

def fetch_http(url, method="GET", payload=None, custom_headers=None, timeout=15):
    try:
        headers = custom_headers if custom_headers else HEADERS
        data = json.dumps(payload).encode('utf-8') if payload else None
        
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode('utf-8', errors='ignore')
    except Exception as e:
        print(f"[-] Bağlantı Hatası [{url}]: {e}")
        return None

def is_whitelisted(entry):
    clean_entry = str(entry).strip().lower()
    IP_base = clean_entry.split('/')[0]
    if IP_base in WHITELIST_IPS:
        return True
    for d in WHITELIST_DOMAINS:
        if clean_entry == d or clean_entry.endswith("." + d):
            return True
    return False

def classify_and_add(raw_entry, target_set):
    if not raw_entry:
        return
    entry = str(raw_entry).strip().strip("'\"")
    if entry and not entry.startswith("#") and not entry.startswith(";"):
        if not is_whitelisted(entry):
            target_set.add(entry)

def load_existing_set(filepath):
    if not os.path.exists(filepath):
        return set()
    with open(filepath, "r", encoding="utf-8") as f:
        return set(line.strip() for line in f if line.strip())

def save_and_report_diff(filename, new_set, label):
    old_set = load_existing_set(filename)
    added = new_set - old_set
    removed = old_set - new_set

    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(new_set)))

    print(f"\n--- {label} İSTATİSTİKLERİ ---")
    print(f"  Toplam Kayıt   : {len(new_set)}")
    print(f"  ➕ Yeni Eklenen : {len(added)}")
    print(f"  ➖ Listeden Çıkan: {len(removed)}")

# ==========================================
# 🚀 1. TÜRKİYE (USOM REST API)
# ==========================================
def fetch_usom_api(all_entries):
    print("[*] USOM API'den veriler çekiliyor...")
    base_url = "https://siberguvenlik.gov.tr/api/incident/index"
    page = 1
    max_pages = 5
    
    while page <= max_pages:
        url = f"{base_url}?page={page}"
        raw_data = fetch_http(url)
        if not raw_data:
            break
        
        try:
            json_data = json.loads(raw_data)
            items = json_data.get("models", []) if isinstance(json_data.get("models"), list) else json_data.get("data", [])
            if not items:
                break
                
            for item in items:
                url_val = item.get("url") or item.get("target") or item.get("domain")
                if url_val:
                    classify_and_add(url_val, all_entries)
                    
            page += 1
        except Exception:
            break
    print("    -> USOM API tamamlandı.")

# ==========================================
# 🚀 2. ABD (CISA & OPENPHISH)
# ==========================================
def fetch_usa_sources(all_entries):
    print("[*] ABD Kaynakları (CISA & OpenPhish) çekiliyor...")
    cisa_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    raw_cisa = fetch_http(cisa_url)
    if raw_cisa:
        try:
            data = json.loads(raw_cisa)
            for vuln in data.get("vulnerabilities", []):
                notes = vuln.get("notes", "")
                if notes:
                    classify_and_add(notes, all_entries)
        except Exception:
            pass
            
    openphish_raw = fetch_http("https://openphish.com/feed.txt")
    if openphish_raw:
        for line in openphish_raw.splitlines():
            classify_and_add(line, all_entries)
    print("    -> ABD Kaynakları tamamlandı.")

# ==========================================
# 🚀 3. AVRUPA RESMİ & DOĞRUDAN KAYNAKLAR (DE, NL, EU)
# ==========================================
def fetch_european_sources(all_entries):
    print("[*] Avrupa Resmi Kaynakları (Almanya, Hollanda, Spamhaus) çekiliyor...")
    sources = [
        # Almanya (Blocklist.de - Doğrudan resmi IP reputation ağ beslemesi)
        "https://lists.blocklist.de/lists/all.txt",
        "https://lists.blocklist.de/lists/ssh.txt",
        # İsviçre / Küresel GreenSnow Doğrudan Akış
        "https://blocklist.greensnow.co/greensnow.txt",
        # Hollanda / Küresel Ağlar (Spamhaus DROP / EDROP - Orijinal Spamhaus Resmi Kaynağı)
        "https://www.spamhaus.org/drop/drop.txt",
        "https://www.spamhaus.org/drop/edrop.txt"
    ]
    
    for src in sources:
        raw = fetch_http(src)
        if raw:
            for line in raw.splitlines():
                classify_and_add(line, all_entries)
    print("    -> Avrupa Resmi Kaynakları tamamlandı.")

# ==========================================
# 🚀 4. ÖZEL İSTİHBARAT & KÖTÜ AMAÇLI SERVİSLER (ABUSE.CH, EMERGING THREATS)
# ==========================================
def fetch_special_intel(all_entries):
    print("[*] Özel Tehdit Servisleri (URLhaus, ThreatFox, Feodo, EmergingThreats) çekiliyor...")
    
    endpoints = [
        "https://urlhaus.abuse.ch/downloads/text/",
        "https://threatfox.abuse.ch/export/csv/recent/",
        "https://bazaar.abuse.ch/export/txt/sha256/recent/",
        "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
        "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
    ]
    
    for feed in endpoints:
        raw = fetch_http(feed)
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
    print("    -> Özel Tehdit Servisleri tamamlandı.")

# ==========================================
# ⚙️ MİKRO AYRIŞTIRICI & KATEGORİZASYON
# ==========================================
def process_and_categorize(all_raw_entries):
    ip_set = set()
    domain_set = set()
    url_set = set()
    hash_set = set()

    for item in all_raw_entries:
        item = str(item).strip()
        if not item or len(item) < 3:
            continue

        if is_whitelisted(item):
            continue

        if HASH_MD5_REGEX.match(item) or HASH_SHA256_REGEX.match(item):
            hash_set.add(item.lower())
            continue

        if item.startswith("http://") or item.startswith("https://"):
            url_set.add(item)
            try:
                parsed = urlparse(item)
                hostname = parsed.hostname
                if hostname:
                    hostname = hostname.strip()
                    if not is_whitelisted(hostname):
                        if IP_REGEX.match(hostname):
                            ip_set.add(hostname)
                        elif DOMAIN_REGEX.match(hostname):
                            domain_set.add(hostname)
            except Exception:
                pass
            continue

        clean_ip = item.split('/')[0]
        if IP_REGEX.match(item) or IP_REGEX.match(clean_ip):
            if not is_whitelisted(clean_ip):
                ip_set.add(item)
            continue

        if DOMAIN_REGEX.match(item):
            if not is_whitelisted(item):
                domain_set.add(item)
            continue

        clean_host = item.split('/')[0].split(':')[0]
        if not is_whitelisted(clean_host):
            if IP_REGEX.match(clean_host):
                ip_set.add(clean_host)
            elif DOMAIN_REGEX.match(clean_host):
                domain_set.add(clean_host)

    return ip_set, domain_set, url_set, hash_set

# ==========================================
# 🚀 ANA ÇALIŞTIRICI
# ==========================================
def main():
    print("=== TAM KAPSAMLI TEHDİT İSTİHBARATI ÇEKİMİ BAŞLADI ===\n")
    all_raw_entries = set()

    fetch_usom_api(all_raw_entries)
    fetch_usa_sources(all_raw_entries)
    fetch_european_sources(all_raw_entries)
    fetch_special_intel(all_raw_entries)

    print("\n[*] Toplanan veriler süzülüyor ve kategorize ediliyor...")
    ips, domains, urls, hashes = process_and_categorize(all_raw_entries)

    print("\n=== SONUÇLARI KAYDETME VE İSTATİSTİKLER ===")
    save_and_report_diff(OUTPUT_IP, ips, "IP ADRESLERİ")
    save_and_report_diff(OUTPUT_DOMAIN, domains, "DOMAINLER")
    save_and_report_diff(OUTPUT_URL, urls, "URL'LER")
    save_and_report_diff(OUTPUT_HASH, hashes, "HASH'LER (MD5/SHA256)")

    print("\n[✔] İşlem başarıyla tamamlandı!")

if __name__ == "__main__":
    main()
