import csv
import json
import re
import urllib.request

# Çıktı dosyalarının isimleri
OUTPUT_IP = "threat_ip.txt"
OUTPUT_DOMAIN = "threat_domain.txt"
OUTPUT_URL = "threat_url.txt"

HEADERS = {'User-Agent': 'Mozilla/5.0 (ThreatIntelligenceBot/3.0)'}

# --- REGEX DESENLERİ (Ayrıştırma İçi) ---
# IPv4 adresi veya CIDR bloğu (Örn: 192.168.1.1 veya 10.0.0.0/24)
IP_REGEX = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/[0-9]{1,2})?$')
# Alan adı (Örn: malicioustrack.com veya sub.badsite.net)
DOMAIN_REGEX = re.compile(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')

def fetch_data(url, custom_headers=None, timeout=20):
    """Genel veri çekme fonksiyonu"""
    try:
        headers = custom_headers if custom_headers else HEADERS
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode('utf-8', errors='ignore')
    except Exception as e:
        print(f"[-] Erişim Hatası [{url}]: {e}")
        return None

def classify_and_add(raw_entry, target_set):
    """Gelen veriyi temizler ve kümeye ekler"""
    if not raw_entry:
        return
    entry = raw_entry.strip()
    # Yorum veya tırnak işaretlerini temizle
    entry = entry.strip("'\"")
    if entry and not entry.startswith("#") and not entry.startswith(";"):
        target_set.add(entry)

# --- 1. USOM ---
def fetch_usom(all_entries):
    raw = fetch_data("https://siberguvenlik.gov.tr/api/url-list")
    if raw:
        try:
            data = json.loads(raw)
            items = data.get("models", data) if isinstance(data, dict) else data
            count = 0
            for item in items:
                if isinstance(item, dict):
                    val = item.get("url") or item.get("domain")
                    if val:
                        classify_and_add(val, all_entries)
                        count += 1
            print(f"[+] USOM: {count} kayıt çekildi.")
        except Exception as e:
            print(f"[-] USOM JSON Parse Hatası: {e}")

# --- 2. URLhaus (URL & DNS) ---
def fetch_urlhaus(all_entries):
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
    print(f"[+] URLhaus (URL + DNS): {count} kayıt çekildi.")

# --- 3. ThreatFox (C2 & Malware) ---
def fetch_threatfox(all_entries):
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
    print(f"[+] ThreatFox C2: {count} kayıt çekildi.")

# --- 4. Blocklist.de ---
def fetch_blocklist_de(all_entries):
    count = 0
    raw = fetch_data("https://lists.blocklist.de/lists/all.txt")
    if raw:
        for line in raw.splitlines():
            if line and not line.startswith("#"):
                classify_and_add(line, all_entries)
                count += 1
    print(f"[+] Blocklist.de (Tüm IP Servisleri): {count} kayıt çekildi.")

# --- 5. OpenPhish ---
def fetch_openphish(all_entries):
    count = 0
    raw = fetch_data("https://openphish.com/feed.txt")
    if raw:
        for line in raw.splitlines():
            if line:
                classify_and_add(line, all_entries)
                count += 1
    print(f"[+] OpenPhish: {count} kayıt çekildi.")

# --- 6. PhishTank ---
def fetch_phishtank(all_entries):
    count = 0
    raw = fetch_data("https://data.phishtank.com/data/online-valid.csv", 
                     custom_headers={'User-Agent': 'phishtank/github_updater'})
    if raw:
        lines = raw.splitlines()
        reader = csv.DictReader(lines)
        for row in reader:
            if row.get('url'):
                classify_and_add(row['url'], all_entries)
                count += 1
    print(f"[+] PhishTank: {count} kayıt çekildi.")

# --- 7. Feodo Tracker ---
def fetch_feodo_tracker(all_entries):
    count = 0
    raw = fetch_data("https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt")
    if raw:
        for line in raw.splitlines():
            if line and not line.startswith("#"):
                classify_and_add(line, all_entries)
                count += 1
    print(f"[+] Feodo Tracker (Botnet IP): {count} kayıt çekildi.")

# --- 8. Spamhaus ---
def fetch_spamhaus(all_entries):
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
    print(f"[+] Spamhaus DROP/EDROP: {count} kayıt çekildi.")

# --- 9. Emerging Threats ---
def fetch_emerging_threats(all_entries):
    count = 0
    raw = fetch_data("https://rules.emergingthreats.net/freetargets/compromised-ips.txt")
    if raw:
        for line in raw.splitlines():
            if line and not line.startswith("#"):
                classify_and_add(line, all_entries)
                count += 1
    print(f"[+] Emerging Threats IP: {count} kayıt çekildi.")

# --- 10. StevenBlack / Malware Domains ---
def fetch_malwaredomains(all_entries):
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
    print(f"[+] StevenBlack Malware DNS: {count} kayıt çekildi.")


def process_and_categorize(all_raw_entries):
    """
    Toplanan tüm ham verileri Regex kullanarak IP, Domain ve URL olarak 3 ana kategoriye ayırır.
    """
    ip_set = set()
    domain_set = set()
    url_set = set()

    for item in all_raw_entries:
        # Protokol eki (http://, https://) varsa URL'dir
        if item.startswith("http://") or item.startswith("https://"):
            url_set.add(item)
        # Yol içeriyorsa (örneğin domain.com/test.php veya 1.2.3.4/malware.exe) URL kabul edilir
        elif "/" in item and not IP_REGEX.match(item):
            # Protokolü yoksa standart hale getirmek için eklenebilir veya ham bırakılabilir
            url_set.add(item)
        # Tam IP veya CIDR bloğu mu?
        elif IP_REGEX.match(item):
            ip_set.add(item)
        # Sadece Domain/FQDN mi?
        elif DOMAIN_REGEX.match(item):
            domain_set.add(item)
        # Diğer durumlar (Protokolsuz ama alt yollu yapılar)
        else:
            url_set.add(item)

    return ip_set, domain_set, url_set


def main():
    print("=== TEHDİT İSTİHBARATI VERİ TOPLAMA BAŞLADI ===\n")
    raw_entries = set()

    # Tüm kaynakları çağır
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

    print("\n[+] Veriler kategorilere ayrıştırılıyor (IP / DOMAIN / URL)...")
    ip_list, domain_list, url_list = process_and_categorize(raw_entries)

    # IP Dosyası
    with open(OUTPUT_IP, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(ip_list)))
    print(f"[SUCCESS] {len(ip_list)} benzersiz IP/Subnet -> {OUTPUT_IP}")

    # DOMAIN Dosyası
    with open(OUTPUT_DOMAIN, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(domain_list)))
    print(f"[SUCCESS] {len(domain_list)} benzersiz Domain -> {OUTPUT_DOMAIN}")

    # URL Dosyası
    with open(OUTPUT_URL, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(url_list)))
    print(f"[SUCCESS] {len(url_list)} benzersiz URL -> {OUTPUT_URL}")

    print("\n[İŞLEM TAMAMLANDI] Tüm dosyalar başarıyla oluşturuldu.")

if __name__ == "__main__":
    main()
