import csv
import json
import re
import urllib.request
import urllib.error
from urllib.parse import urlparse

OUTPUT_IP = "threat_ip.txt"
OUTPUT_DOMAIN = "threat_domain.txt"
OUTPUT_URL = "threat_url.txt"

HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ThreatBot/3.0'}

IP_REGEX = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/[0-9]{1,2})?$')
DOMAIN_REGEX = re.compile(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')

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

# --- İSTİHBARAT KAYNAKLARI ---

def fetch_usom(all_entries):
    try:
        raw = fetch_data("https://www.usom.gov.tr/url-list.txt")
        if raw:
            for line in raw.splitlines():
                classify_and_add(line, all_entries)
            print("[+] USOM tamamlandı.")
    except Exception as e:
        print(f"[-] USOM Hata: {e}")

def fetch_urlhaus(all_entries):
    try:
        raw_urls = fetch_data("https://urlhaus.abuse.ch/downloads/text/")
        if raw_urls:
            for line in raw_urls.splitlines():
                if line and not line.startswith("#"):
                    classify_and_add(line, all_entries)
        print("[+] URLhaus tamamlandı.")
    except Exception as e:
        print(f"[-] URLhaus Hata: {e}")

def fetch_openphish(all_entries):
    try:
        raw = fetch_data("https://openphish.com/feed.txt")
        if raw:
            for line in raw.splitlines():
                classify_and_add(line, all_entries)
        print("[+] OpenPhish tamamlandı.")
    except Exception as e:
        print(f"[-] OpenPhish Hata: {e}")

def fetch_phishtank(all_entries):
    try:
        raw = fetch_data("https://data.phishtank.com/data/online-valid.csv", timeout=12)
        if raw:
            lines = raw.splitlines()
            reader = csv.DictReader(lines)
            for row in reader:
                if row and row.get('url'):
                    classify_and_add(row['url'], all_entries)
        print("[+] PhishTank tamamlandı.")
    except Exception as e:
        print(f"[-] PhishTank Hata: {e}")

# --- DOĞRUDAN IP ODAKLI KAYNAKLAR ---

def fetch_blocklist_de(all_entries):
    try:
        raw = fetch_data("https://lists.blocklist.de/lists/all.txt")
        if raw:
            for line in raw.splitlines():
                classify_and_add(line, all_entries)
            print("[+] Blocklist.de (IP) tamamlandı.")
    except Exception as e:
        print(f"[-] Blocklist.de Hata: {e}")

def fetch_feodo_tracker(all_entries):
    try:
        raw = fetch_data("https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt")
        if raw:
            for line in raw.splitlines():
                if line and not line.startswith("#"):
                    classify_and_add(line, all_entries)
            print("[+] Feodo Tracker C2 (IP) tamamlandı.")
    except Exception as e:
        print(f"[-] Feodo Tracker Hata: {e}")

def fetch_emerging_threats(all_entries):
    try:
        raw = fetch_data("https://rules.emergingthreats.net/freetargets/compromised-ips.txt")
        if raw:
            for line in raw.splitlines():
                if line and not line.startswith("#"):
                    classify_and_add(line, all_entries)
            print("[+] Emerging Threats (IP) tamamlandı.")
    except Exception as e:
        print(f"[-] Emerging Threats Hata: {e}")

def fetch_spamhaus(all_entries):
    try:
        urls = [
            "https://www.spamhaus.org/drop/drop.txt",
            "https://www.spamhaus.org/drop/edrop.txt"
        ]
        for url in urls:
            raw = fetch_data(url)
            if raw:
                for line in raw.splitlines():
                    line = line.strip()
                    if line and not line.startswith(";"):
                        cidr = line.split(";")[0].strip()
                        if cidr:
                            classify_and_add(cidr, all_entries)
        print("[+] Spamhaus DROP (IP/CIDR) tamamlandı.")
    except Exception as e:
        print(f"[-] Spamhaus Hata: {e}")

# --- AYRIŞTIRMA VE KATEGORİZE ETME ---

def process_and_categorize(all_raw_entries):
    ip_set = set()
    domain_set = set()
    url_set = set()

    for item in all_raw_entries:
        item = item.strip()
        if not item:
            continue

        # 1. Tam URL ise ayrıştır
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

        # 2. Yalın IP veya CIDR (1.2.3.4 veya 1.2.3.0/24)
        elif IP_REGEX.match(item):
            ip_set.add(item)

        # 3. Yalın Domain
        elif DOMAIN_REGEX.match(item):
            domain_set.add(item)

        # 4. Port içeren veya path içeren ham girdiler (ör. 1.2.3.4:8080)
        else:
            clean_host = item.split('/')[0].split(':')[0]
            if IP_REGEX.match(clean_host):
                ip_set.add(clean_host)
            elif DOMAIN_REGEX.match(clean_host):
                domain_set.add(clean_host)

    return ip_set, domain_set, url_set

def main():
    print("=== TEHDİT İSTİHBARATI VERİ TOPLAMA BAŞLADI ===\n")
    raw_entries = set()

    # URL / Phishing Kaynakları
    fetch_usom(raw_entries)
    fetch_urlhaus(raw_entries)
    fetch_openphish(raw_entries)
    fetch_phishtank(raw_entries)

    # IP Odaklı Kaynaklar
    fetch_blocklist_de(raw_entries)
    fetch_feodo_tracker(raw_entries)
    fetch_emerging_threats(raw_entries)
    fetch_spamhaus(raw_entries)

    print("\n[+] Veriler ayrıştırılıyor ve kategorize ediliyor...")
    ip_list, domain_list, url_list = process_and_categorize(raw_entries)

    with open(OUTPUT_IP, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(ip_list)))
    print(f"[✓] {len(ip_list)} IP -> {OUTPUT_IP}")

    with open(OUTPUT_DOMAIN, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(domain_list)))
    print(f"[✓] {len(domain_list)} Domain -> {OUTPUT_DOMAIN}")

    with open(OUTPUT_URL, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(url_list)))
    print(f"[✓] {len(url_list)} URL -> {OUTPUT_URL}")

    print("\n[İŞLEM TAMAMLANDI]")

if __name__ == "__main__":
    main()
