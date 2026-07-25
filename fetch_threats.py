import csv
import json
import re
import urllib.request

# Çıktı olarak üretilecek dosya adı
OUTPUT_FILE = "threat_list.txt"

def fetch_usom():
    """USOM API / JSON verilerini çeker"""
    urls = set()
    try:
        url = "https://siberguvenlik.gov.tr/api/url-list" # Güncel USOM API adresi
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            items = data.get("models", data) if isinstance(data, dict) else data
            for item in items:
                if isinstance(item, dict):
                    val = item.get("url") or item.get("domain")
                    if val:
                        urls.add(val.strip())
        print(f"[+] USOM: {len(urls)} adres çekildi.")
    except Exception as e:
        print(f"[-] USOM Hata: {e}")
    return urls

def fetch_urlhaus():
    """URLhaus TXT verisini çeker"""
    urls = set()
    try:
        url = "https://urlhaus.abuse.ch/downloads/text/"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=15) as resp:
            lines = resp.read().decode('utf-8', errors='ignore').splitlines()
            for line in lines:
                line = line.strip()
                if line and not line.startswith("#"):
                    urls.add(line)
        print(f"[+] URLhaus: {len(urls)} adres çekildi.")
    except Exception as e:
        print(f"[-] URLhaus Hata: {e}")
    return urls

def fetch_openphish():
    """OpenPhish TXT verisini çeker"""
    urls = set()
    try:
        url = "https://openphish.com/feed.txt"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=15) as resp:
            lines = resp.read().decode('utf-8', errors='ignore').splitlines()
            for line in lines:
                line = line.strip()
                if line:
                    urls.add(line)
        print(f"[+] OpenPhish: {len(urls)} adres çekildi.")
    except Exception as e:
        print(f"[-] OpenPhish Hata: {e}")
    return urls

def fetch_phishtank():
    """PhishTank CSV verisini ayıklar"""
    urls = set()
    try:
        url = "https://data.phishtank.com/data/online-valid.csv"
        req = urllib.request.Request(url, headers={'User-Agent': 'phishtank/github_updater'})
        with urllib.request.urlopen(req, timeout=20) as resp:
            lines = resp.read().decode('utf-8', errors='ignore').splitlines()
            reader = csv.DictReader(lines)
            for row in reader:
                if row.get('url'):
                    urls.add(row['url'].strip())
        print(f"[+] PhishTank: {len(urls)} adres çekildi.")
    except Exception as e:
        print(f"[-] PhishTank Hata: {e}")
    return urls

def main():
    all_threats = set()
    
    # Tüm kaynakları birleştir
    all_threats.update(fetch_usom())
    all_threats.update(fetch_urlhaus())
    all_threats.update(fetch_openphish())
    all_threats.update(fetch_phishtank())

    # Başında http/https olmayan veya boş satırları temizle
    cleaned_list = sorted([u for u in all_threats if u])

    # Tek bir TXT dosyasına yaz
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(cleaned_list))

    print(f"\n[SUCCESS] Toplam {len(cleaned_list)} benzersiz zararlı adres {OUTPUT_FILE} dosyasına kaydedildi.")

if __name__ == "__main__":
    main()
