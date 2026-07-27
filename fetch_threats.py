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
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ThreatIntelEngine/6.0',
    'Accept': 'application/json, text/plain, */*'
}

# --- REGEX TANIMLARI ---
IP_REGEX = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/[0-9]{1,2})?$')
DOMAIN_REGEX = re.compile(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')
HASH_MD5_REGEX = re.compile(r'^[a-fA-F0-9]{32}$')
HASH_SHA256_REGEX = re.compile(r'^[a-fA-F0-9]{64}$')

def fetch_http(url, method="GET", payload=None, custom_headers=None, timeout=15):
    """HTTP/REST API İsteklerini Yöneten Genel Fonksiyon"""
    try:
        headers = custom_headers if custom_headers else HEADERS
        data = json.dumps(payload).encode('utf-8') if payload else None
        
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            content = resp.read().decode('utf-8', errors='ignore')
            return content
    except Exception as e:
        print(f"[-] Bağlantı Hatası [{url}]: {e}")
        return None

def classify_and_add(raw_entry, target_set):
    """Gelen veriyi temizler ve kümeye ekler"""
    if not raw_entry:
        return
    entry = str(raw_entry).strip().strip("'\"")
    if entry and not entry.startswith("#") and not entry.startswith(";"):
        target_set.add(entry)

# ==========================================
# 🚀 KAYNAK 1: TÜRKİYE (USOM REST API)
# ==========================================
def fetch_usom_api(all_entries):
    """USOM REST API üzerinden sayfalı veri çeker"""
    print("[*] USOM API'den veriler çekiliyor...")
    # USOM API Endpoint (Apex domain API)
    base_url = "https://siberguvenlik.gov.tr/api/incident/index"
    
    page = 1
    max_pages = 5  # İhtiyaca göre sayfa sayısını artırabilirsiniz
    
    while page <= max_pages:
        url = f"{base_url}?page={page}"
        raw_data = fetch_http(url)
        if not raw_data:
            break
        
        try:
            json_data = json.loads(raw_data)
            # USOM API yanıt yapısındaki modüller (models / models.data)
            items = json_data.get("models", []) if isinstance(json_data.get("models"), list) else json_data.get("data", [])
            
            if not items:
                break
                
            for item in items:
                # Target URL / IP / Domain alanları
                url_val = item.get("url") or item.get("target") or item.get("domain")
                if url_val:
                    classify_and_add(url_val, all_entries)
                    
            print(f"    -> USOM API Sayfa {page} işlendi.")
            page += 1
        except Exception as e:
            print(f"[-] USOM API Parse Hatası: {e}")
            break

# ==========================================
# 🚀 KAYNAK 2: ABD (CISA API & OPENPHISH)
# ==========================================
def fetch_usa_sources(all_entries):
    print("[*] ABD Kaynakları (CISA & OpenPhish) çekiliyor...")
    # CISA Known Exploited Vulnerabilities JSON
    cisa_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    raw_cisa = fetch_http(cisa_url)
    if raw_cisa:
        try:
            data = json.loads(raw_cisa)
            for vuln in data.get("vulnerabilities", []):
                # Ek referans URL'leri IoC olarak çekilir
                notes = vuln.get("notes", "")
                if notes:
                    classify_and_add(notes, all_entries)
        except Exception:
            pass
            
    # OpenPhish Global Feed
    openphish_raw = fetch_http("https://openphish.com/feed.txt")
    if openphish_raw:
        for line in openphish_raw.splitlines():
            classify_and_add(line, all_entries)

# ==========================================
# 🚀 KAYNAK 3: AVRUPA BİRLİĞİ, ALMANYA, AVUSTURYA, HOLLANDA, İSVİÇRE
# ==========================================
def fetch_european_sources(all_entries):
    print("[*] Avrupa Kaynakları (DE, AT, NL, CH, EU) çekiliyor...")
    sources = [
        # Almanya (Blocklist.de API)
        "https://lists.blocklist.de/lists/all.txt",
        "https://lists.blocklist.de/lists/ssh.txt",
        # İsviçre (GreenSnow & NCSC-CH Threat Feeds)
        "https://blocklist.greensnow.co/greensnow.txt",
        # Avusturya (CERT-AT Feeds)
        "https://cert.at/static/misp-warninglist.json",
        # Hollanda & Genel AB Feeds
        "https://www.spamhaus.org/drop/drop.txt",
        "https://www.spamhaus.org/drop/edrop.txt"
    ]
    
    for src in sources:
        raw = fetch_http(src)
        if raw:
            if src.endswith(".json"):
                try:
                    js = json.loads(raw)
                    for val in js.get("list", []):
                        classify_and_add(val, all_entries)
                except Exception:
                    pass
            else:
                for line in raw.splitlines():
                    classify_and_add(line, all_entries)

# ==========================================
# 🚀 KAYNAK 4: ÖZEL İSTİHBARAT (URLHAUS API, CISCO, ABUSE.CH)
# ==========================================
def fetch_special_intel(all_entries):
    print("[*] Özel Tehdit Servisleri (URLhaus, Cisco, Abuse.ch) çekiliyor...")
    
    # 1. URLhaus API v1 (Recent URLs)
    urlhaus_api = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
    raw_urlhaus = fetch_http(urlhaus_api)
    if raw_urlhaus:
        try:
            js = json.loads(raw_urlhaus)
            for u in js.get("urls", []):
                classify_and_add(u.get("url"), all_entries)
                classify_and_add(u.get("host"), all_entries)
        except Exception:
            pass

    # 2. Feodo Tracker API (Botnet C2 IP'leri)
    feodo_api = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json"
    raw_feodo = fetch_http(feodo_api)
    if raw_feodo:
        try:
            js = json.loads(raw_feodo)
            for item in js:
                classify_and_add(item.get("ip_address"), all_entries)
        except Exception:
            pass

    # 3. Cisco Umbrella / Malicious Infrastructure Feeds & Emerging Threats
    extra_feeds = [
        "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/cisco_ucs.ipset",
        "https://bazaar.abuse.ch/export/txt/sha256/recent/"
    ]
    
    for feed in extra_feeds:
        raw = fetch_http(feed)
        if raw:
            for line in raw.splitlines():
                classify_and_add(line, all_entries)

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

        # 1. Zararlı Hashler (MD5 / SHA256)
        if HASH_MD5_REGEX.match(item) or HASH_SHA256_REGEX.match(item):
            hash_set.add(item.lower())
            continue

        # 2. Tam URL
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

        # 3. Yalın IP / CIDR
        clean_ip = item.split('/')[0]
        if IP_REGEX.match(item) or IP_REGEX.match(clean_ip):
            ip_set.add(item)
            continue

        # 4. Yalın Domain
        if DOMAIN_REGEX.match(item):
            domain_set.add(item)
            continue

        # 5. Port/Path İçeren Hibrit Tanımlar
        clean_host = item.split('/')[0].split(':')[0]
        if IP_REGEX.match(clean_host):
            ip_set.add(clean_host)
        elif DOMAIN_REGEX.match(clean_host):
            domain_set.add(clean_host)

    return ip_set, domain_set, url_set, hash_set

def save_output(filename, data_set, label):
    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(data_set)))
    print(f"[+] {label}: Toplam {len(data_set)} adet kayıt '{filename}' dosyasına yazıldı.")

# ==========================================
# 🚀 ANA ÇALIŞTIRICI
# ==========================================
def main():
    print("=== TAM KAPSAMLI TEHDİT İSTİHBARATI ÇEKİMİ BAŞLADI ===\n")
    all_raw_entries = set()

    # Tüm Kaynaklar Tek Tek Çağrılıyor (Eksiksiz)
    fetch_usom_api(all_raw_entries)
    fetch_usa_sources(all_raw_entries)
    fetch_european_sources(all_raw_entries)
    fetch_special_intel(all_raw_entries)

    print("\n[*] Toplanan tüm veriler işleniyor ve kategorize ediliyor...")
    ips, domains, urls, hashes = process_and_categorize(all_raw_entries)

    print("\n=== SONUÇLARI KAYDETME ===")
    save_output(OUTPUT_IP, ips, "IP Adresleri")
    save_output(OUTPUT_DOMAIN, domains, "Domain Adresleri")
    save_output(OUTPUT_URL, urls, "Tam URL'ler")
    save_output(OUTPUT_HASH, hashes, "Zararlı Hash'ler")

    print("\n[✔] İşlem başarıyla tamamlandı!")

if __name__ == "__main__":
    main()
