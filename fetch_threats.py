import csv
import json
import re
import urllib.request
import urllib.error

OUTPUT_IP = "threat_ip.txt"
OUTPUT_DOMAIN = "threat_domain.txt"
OUTPUT_URL = "threat_url.txt"

HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) ThreatBot/3.0'}

IP_REGEX = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/[0-9]{1,2})?$')
DOMAIN_REGEX = re.compile(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')

def fetch_data(url, custom_headers=None, timeout=10):
    """Sessiz ve güvenli veri çekme fonksiyonu"""
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
        raw = fetch_data("https://siberguvenlik.gov.tr/api/url-list")
        if raw:
            data = json.loads(raw)
            items = data.get("models", data) if isinstance(data, dict) else data
            count = 0
            for item in items:
                if isinstance(item, dict):
                    val = item.get("url") or item.get("domain")
                    if val:
                        classify_and_add(val, all_entries)
                        count += 1
            print(f"[+] USOM: {count} kayıt.")
    except Exception as e:
        print(f"[-] USOM Genel Hata: {e}")

def fetch_urlhaus(all_entries):
    try:
        count = 0
        raw_urls = fetch_data("https://urlhaus.abuse.ch/downloads/text/")
        if raw_urls:
            for line in raw_urls.splitlines():
                if line and not line.startswith("#"):
                    classify_and_add(line, all_entries)
                    count += 1

        raw_domains = fetch_data("https://urlhaus.abuse.ch/downloads/hostfile/")
        if raw_domains:
            for line in raw_domains.splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "127.0.0.1" in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        classify_and_add(parts[1], all_entries)
                        count += 1
        print(f"[+] URLhaus: {count} kayıt.")
    except Exception as e:
        print(f"[-] URLhaus Genel Hata: {e}")

def fetch_threatfox(all_entries):
    try:
        count = 0
        raw = fetch_data("https://threatfox.abuse.ch/downloads/hostfile/")
        if raw:
            for line in raw.splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "127.0.0.1" in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        classify_and_add(parts[1], all_entries)
                        count += 1
        print(f"[+] ThreatFox: {count} kayıt.")
    except Exception as e:
        print(f"[-] ThreatFox Genel Hata: {e}")

def fetch_blocklist_de(all_entries):
    try:
        count = 0
        raw = fetch_data("https://lists.blocklist.de/lists/all.txt")
        if raw:
            for line in raw.splitlines():
                if line and not line.startswith("#"):
                    classify_and_add(line, all_entries)
                    count += 1
        print(f"[+] Blocklist.de: {count} kayıt.")
    except Exception as e:
        print(f"[-] Blocklist.de Genel Hata: {e}")

def fetch_openphish(all_entries):
    try:
        count = 0
        raw = fetch_data("https://openphish.com/feed.txt")
        if raw:
            for line in raw.splitlines():
                if line:
                    classify_and_add(line, all_entries)
                    count += 1
        print(f"[+] OpenPhish: {count} kayıt.")
    except Exception as e:
        print(f"[-] OpenPhish Genel Hata: {e}")

def fetch_phishtank(all_entries):
    try:
        count = 0
        raw = fetch_data("https://data.phishtank.com/data/online-valid.csv", timeout=8)
        if raw:
            lines = raw.splitlines()
            reader = csv.DictReader(lines)
            for row in reader:
                if row and row.get('url'):
                    classify_and_add(row['url'], all_entries)
                    count += 1
        print(f"[+] PhishTank: {count} kayıt.")
    except Exception as e:
        print(f"[-] PhishTank Genel Hata: {e}")

def fetch_feodo_tracker(all_entries):
    try:
        count = 0
        raw = fetch_data("https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt")
        if raw:
            for line in raw.splitlines():
                if line and not line.startswith("#"):
                    classify_and_add(line, all_entries)
                    count += 1
        print(f"[+] Feodo Tracker: {count} kayıt.")
    except Exception as e:
        print(f"[-] Feodo Tracker Genel Hata: {e}")

def fetch_spamhaus(all_entries):
    try:
        count = 0
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
                            count += 1
        print(f"[+] Spamhaus: {count} kayıt.")
    except Exception as e:
        print(f"[-] Spamhaus Genel Hata: {e}")

def fetch_emerging_threats(all_entries):
    try:
        count = 0
        raw = fetch_data("https://rules.emergingthreats.net/freetargets/compromised-ips.txt")
        if raw:
            for line in raw.splitlines():
                if line and not line.startswith("#"):
                    classify_and_add(line, all_entries)
                    count += 1
        print(f"[+] Emerging Threats: {count} kayıt.")
    except Exception as e:
        print(f"[-] Emerging Threats Genel Hata: {e}")

def fetch_malwaredomains(all_entries):
    try:
        count = 0
        raw = fetch_data("https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts")
        if raw:
            for line in raw.splitlines():
                line = line.strip()
                if line and not line.startswith("#") and line.startswith("0.0.0.0"):
                    parts = line.split()
                    if len(parts) >= 2 and parts[1] != "0.0.0.0":
                        classify_and_add(parts[1], all_entries)
                        count += 1
        print(f"[+] StevenBlack Hosts: {count} kayıt.")
    except Exception as e:
        print(f"[-] StevenBlack Hosts Genel Hata: {e}")

def process_and_categorize(all_raw_entries):
    ip_set = set()
    domain_set = set()
    url_set = set()

    for item in all_raw_entries:
        if item.startswith("http://") or item.startswith("https://"):
            url_set.add(item)
        elif IP_REGEX.match(item):
            ip_set.add(item)
        elif DOMAIN_REGEX.match(item):
            domain_set.add(item)
        elif "/" in item:
            url_set.add(item)
        else:
            domain_set.add(item)

    return ip_set, domain_set, url_set

def main():
    print("=== TEHDİT İSTİHBARATI VERİ TOPLAMA BAŞLADI ===\n")
    raw_entries = set()

    fetch_usom(raw_entries)
    fetch_urlhaus(raw_entries)
    fetch_threatfox(raw_entries)
    fetch_blocklist_de(raw_entries)
    fetch_openphish(raw_entries)
    fetch_phishtank(raw_entries)
    fetch_feodo_tracker(raw_entries)
    fetch_spamhaus(raw_entries)
    fetch_emerging_threats(raw_entries)
    fetch_malwaredomains(raw_entries)

    print("\n[+] Veriler kategorilere ayrıştırılıyor...")
    ip_list, domain_list, url_list = process_and_categorize(raw_entries)

    print("\n[+] Dosyalar oluşturuluyor...")
    
    with open(OUTPUT_IP, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(ip_list)))
    print(f"[✓] {len(ip_list)} adet IP kaydedildi -> {OUTPUT_IP}")

    with open(OUTPUT_DOMAIN, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(domain_list)))
    print(f"[✓] {len(domain_list)} adet Domain kaydedildi -> {OUTPUT_DOMAIN}")

    with open(OUTPUT_URL, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(url_list)))
    print(f"[✓] {len(url_list)} adet URL kaydedildi -> {OUTPUT_URL}")

    print("\n[İSLEM TAMAMLANDI]")

if __name__ == "__main__":
    main()
