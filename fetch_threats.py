import csv
import json
import re
import urllib.request

OUTPUT_FILE = "threat_list.txt"

# Standart tarayıcı kimliği
HEADERS = {'User-Agent': 'Mozilla/5.0 (ThreatIntelligenceBot/2.0)'}

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

# --- 1. USOM (TR Siber Olaylara Müdahale) ---
def fetch_usom():
    entries = set()
    raw = fetch_data("https://siberguvenlik.gov.tr/api/url-list")
    if raw:
        try:
            data = json.loads(raw)
            items = data.get("models", data) if isinstance(data, dict) else data
            for item in items:
                if isinstance(item, dict):
                    val = item.get("url") or item.get("domain")
                    if val:
                        entries.add(val.strip())
            print(f"[+] USOM: {len(entries)} kayıt.")
        except Exception as e:
            print(f"[-] USOM JSON Parse Hatası: {e}")
    return entries

# --- 2. URLhaus (URL & DNS Domain Feed) ---
def fetch_urlhaus():
    entries = set()
    # URL Listesi
    raw_urls = fetch_data("https://urlhaus.abuse.ch/downloads/text/")
    if raw_urls:
        for line in raw_urls.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                entries.add(line)
    
    # DNS / Domain Listesi
    raw_domains = fetch_data("https://urlhaus.abuse.ch/downloads/hostfile/")
    if raw_domains:
        for line in raw_domains.splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "127.0.0.1" in line:
                parts = line.split()
                if len(parts) >= 2:
                    entries.add(parts[1])
                    
    print(f"[+] URLhaus (URL + DNS): {len(entries)} kayıt.")
    return entries

# --- 3. ThreatFox by abuse.ch (C2 & Malware IOCs) ---
def fetch_threatfox():
    entries = set()
    raw = fetch_data("https://threatfox.abuse.ch/downloads/hostfile/")
    if raw:
        for line in raw.splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "127.0.0.1" in line:
                parts = line.split()
                if len(parts) >= 2:
                    entries.add(parts[1])
    print(f"[+] ThreatFox C2: {len(entries)} kayıt.")
    return entries

# --- 4. Blocklist.de (Tüm Servisler: SSH, Mail, Apache, Botnet IP'leri) ---
def fetch_blocklist_de():
    entries = set()
    # Tüm kategorilerin birleşik IP listesi
    raw = fetch_data("https://lists.blocklist.de/lists/all.txt")
    if raw:
        for line in raw.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                entries.add(line)
    print(f"[+] Blocklist.de (Tüm IP Servisleri): {len(entries)} kayıt.")
    return entries

# --- 5. OpenPhish ---
def fetch_openphish():
    entries = set()
    raw = fetch_data("https://openphish.com/feed.txt")
    if raw:
        for line in raw.splitlines():
            line = line.strip()
            if line:
                entries.add(line)
    print(f"[+] OpenPhish: {len(entries)} kayıt.")
    return entries

# --- 6. PhishTank ---
def fetch_phishtank():
    entries = set()
    raw = fetch_data("https://data.phishtank.com/data/online-valid.csv", 
                     custom_headers={'User-Agent': 'phishtank/github_updater'})
    if raw:
        lines = raw.splitlines()
        reader = csv.DictReader(lines)
        for row in reader:
            if row.get('url'):
                entries.add(row['url'].strip())
    print(f"[+] PhishTank: {len(entries)} kayıt.")
    return entries

# --- 7. Feodo Tracker (Botnet C2 IP'leri) ---
def fetch_feodo_tracker():
    entries = set()
    raw = fetch_data("https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt")
    if raw:
        for line in raw.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                entries.add(line)
    print(f"[+] Feodo Tracker (Botnet IP): {len(entries)} kayıt.")
    return entries

# --- 8. Spamhaus DROP & EDROP (Zararlı Subnet ve IP'ler) ---
def fetch_spamhaus():
    entries = set()
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
                    # Örn: 1.10.16.0/20 ; SBL211326 -> Sadece CIDR kısmını alıyoruz
                    cidr = line.split(";")[0].strip()
                    if cidr:
                        entries.add(cidr)
    print(f"[+] Spamhaus DROP/EDROP: {len(entries)} kayıt.")
    return entries

# --- 9. Emerging Threats (Compromised IP Blocklist) ---
def fetch_emerging_threats():
    entries = set()
    raw = fetch_data("https://rules.emergingthreats.net/freetargets/compromised-ips.txt")
    if raw:
        for line in raw.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                entries.add(line)
    print(f"[+] Emerging Threats IP: {len(entries)} kayıt.")
    return entries

# --- 10. MalwareDomainList / DNS Blocklist (AdGuard/Pi-hole uyumlu) ---
def fetch_malwaredomains():
    entries = set()
    raw = fetch_data("https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts")
    if raw:
        for line in raw.splitlines():
            line = line.strip()
            if line and not line.startswith("#") and line.startswith("0.0.0.0"):
                parts = line.split()
                if len(parts) >= 2 and parts[1] != "0.0.0.0":
                    entries.add(parts[1])
    print(f"[+] AdGuard/StevenBlack Malware DNS: {len(entries)} kayıt.")
    return entries


def main():
    print("=== TEHDİT İSTİHBARATİ VERİ TOPLAMA BAŞLADI ===\n")
    all_threats = set()

    # Fonksiyonların çağrılması
    all_threats.update(fetch_usom())
    all_threats.update(fetch_urlhaus())
    all_threats.update(fetch_threatfox())
    all_threats.update(fetch_blocklist_de())
    all_threats.update(fetch_openphish())
    all_threats.update(fetch_phishtank())
    all_threats.update(fetch_feodo_tracker())
    all_threats.update(fetch_spamhaus())
    all_threats.update(fetch_emerging_threats())
    all_threats.update(fetch_malwaredomains())

    # Boş veya hatalı girdileri ayıkla
    cleaned_list = sorted([entry for entry in all_threats if entry and len(entry) > 3])

    # Dosyaya yaz
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(cleaned_list))

    print(f"\n[İŞLEM TAMAMLANDI] Toplam {len(cleaned_list)} benzersiz zararlı gösterge (IOC) {OUTPUT_FILE} dosyasına yazıldı.")

if __name__ == "__main__":
    main()
