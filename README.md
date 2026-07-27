# 🛡️ Automated Cyber Threat Intelligence & Feed Engine
[![Threat Feed Automation](https://github.com/kennybayram/therat-feeds/actions/workflows/main.yml/badge.svg)](https://github.com/kennybayram/therat-feeds/actions)
[![LinkedIn Profile](https://img.shields.io/badge/LinkedIn-Connect-blue?style=flat&logo=linkedin)](https://www.linkedin.com/in/kenanbayram)

[Türkçe](#türkçe) | [English](#english) | [Deutsch](#deutsch) | [Français](#français) | [Italiano](#italiano)

---

## Türkçe
Bu depo, ulusal ve küresel yetkili siber güvenlik kurumları ile açık kaynaklı istihbarat servislerinden güncel tehdit verilerini (IP, Domain, URL ve Hash) otomatik olarak toplayan, doğrulayan ve kategorize eden yüksek performanslı bir tehdit istihbaratı (Threat Intelligence) motoru ile beslenmektedir. **GitHub Actions altyapısı sayesinde her 30 dakikada bir otomatik olarak güncellenmektedir.**

### 📡 Kullanılan Kaynaklar ve Servisler
* **Siber Güvenlik Başkanlığı (USOM API):** Türkiye merkezli resmi zararlı bağlantı ve olay verileri.
* **CISA (Known Exploited Vulnerabilities):** Amerika Birleşik Devletleri siber güvenlik açığı ve istihbarat beslemeleri.
* **OpenPhish:** Küresel oltalama (phishing) URL akışları.
* **Blocklist.de & GreenSnow:** Almanya ve İsviçre merkezli IP reputation ve SSH atak kaynakları.
* **Spamhaus (DROP & EDROP):** Hollanda / Küresel kritik zararlı ağ ve IP blokları.
* **Abuse.ch (URLhaus, ThreatFox, MalwareBazaar, Feodo Tracker):** Küresel kötü amaçlı URL, IOC, zararlı dosya hash'leri ve botnet C2 IP'leri.
* **Emerging Threats:** Komamine edilmiş küresel zararlı IP havuzları.

### 🛡️ Beyaz Liste (Whitelist) Politikası
Yanlış pozitifleri (False Positive) önlemek ve kritik altyapıların engellenmesini engellemek amacıyla şu kritik servisler ve adresler otomatik olarak filtrelenmektedir:
* **Güvenli DNS Sağlayıcıları:** Google (8.8.8.8, 8.8.4.4), Cloudflare (1.1.1.1, 1.0.0.1), Quad9 (9.9.9.9), OpenDNS.
* **Kritik Alan Adları:** google.com, cloudflare.com, microsoft.com, apple.com, github.com, amazon.com, siberguvenlik.gov.tr ve yerel ağ (localhost / 127.0.0.1).

**Yazar:** Kenan Bayram  
[LinkedIn Profilim](https://www.linkedin.com/in/kenanbayram)

---

## English
This repository is powered by a high-performance threat intelligence engine that automatically collects, verifies, and categorizes threat data (IPs, Domains, URLs, and Hashes) from national and global authoritative cybersecurity agencies and open-source intelligence services. **It is automatically updated every 30 minutes via GitHub Actions infrastructure.**

### 📡 Used Sources and Services
* **Cybersecurity Directorate (USOM API):** Official malicious connection and incident data originating from Turkey.
* **CISA (Known Exploited Vulnerabilities):** United States cybersecurity vulnerability and intelligence feeds.
* **OpenPhish:** Global phishing URL streams.
* **Blocklist.de & GreenSnow:** Germany and Switzerland-based IP reputation and SSH attack sources.
* **Spamhaus (DROP & EDROP):** Netherlands / Global critical malicious network and IP blocks.
* **Abuse.ch (URLhaus, ThreatFox, MalwareBazaar, Feodo Tracker):** Global malicious URLs, IOCs, malware file hashes, and botnet C2 IPs.
* **Emerging Threats:** Compromised global malicious IP pools.

### 🛡️ Whitelist Policy
To prevent false positives and blocklisting of critical infrastructure, the following trusted services and addresses are automatically filtered out:
* **Secure DNS Providers:** Google (8.8.8.8, 8.8.4.4), Cloudflare (1.1.1.1, 1.0.0.1), Quad9 (9.9.9.9), OpenDNS.
* **Critical Domains:** google.com, cloudflare.com, microsoft.com, apple.com, github.com, amazon.com, siberguvenlik.gov.tr and localhost / 127.0.0.1.

**Author:** Kenan Bayram  
[LinkedIn Profile](https://www.linkedin.com/in/kenanbayram)

---

## Deutsch
Dieses Repository wird von einer hochleistungsfähigen Bedrohungsinformations-Engine (Threat Intelligence Engine) betrieben, die Bedrohungsdaten (IPs, Domains, URLs und Hashes) von nationalen und globalen Cybersicherheitsbehörden sowie Open-Source-Inteligence-Diensten automatisch sammelt, verifiziert und kategorisiert. **Es wird über die GitHub Actions-Infrastruktur alle 30 Minuten automatisch aktualisiert.**

### 📡 Verwendete Quellen und Dienste
* **Präsidentschaft für Cybersicherheit (USOM API):** Offizielle Schadverbindungs- und Vorfalldaten aus der Türkei.
* **CISA (Known Exploited Vulnerabilities):** Cybersicherheits-Schwächen- und Intelligendatenfeeds der Vereinigten Staaten.
* **OpenPhish:** Globale Phishing-URL-Streams.
* **Blocklist.de & GreenSnow:** Deutschland- und schweizbasierte IP-Reputations- und SSH-Angriffsquellen.
* **Spamhaus (DROP & EDROP):** Niederlande / Globale kritische schädliche Netzwerk- und IP-Blöcke.
* **Abuse.ch (URLhaus, ThreatFox, MalwareBazaar, Feodo Tracker):** Globale schädliche URLs, IOCs, Malware-Dateihashes und Botnet-C2-IPs.
* **Emerging Threats:** Kompromittierte globale schädliche IP-Pools.

### 🛡️ Whitelist-Richtlinie
Um False Positives und die Sperrung kritischer Infrastrukturen zu verhindern, werden folgende vertrauenswürdige Dienste und Adressen automatisch herausgefiltert:
* **Sichere DNS-Anbieter:** Google (8.8.8.8, 8.8.4.4), Cloudflare (1.1.1.1, 1.0.0.1), Quad9 (9.9.9.9), OpenDNS.
* **Kritische Domains:** google.com, cloudflare.com, microsoft.com, apple.com, github.com, amazon.com, siberguvenlik.gov.tr und localhost / 127.0.0.1.

**Autor:** Kenan Bayram  
[LinkedIn-Profil](https://www.linkedin.com/in/kenanbayram)

---

## Français
Ce dépôt est alimenté par un moteur de renseignement sur les menaces (Threat Intelligence) haute performance qui collecte, vérifie et catégorise automatiquement les données de menaces (IP, Domaines, URL et Hashes) provenant d'agences de cybersécurité nationales et mondiales ainsi que de services de renseignement open-source. **Il est mis à jour automatiquement toutes les 30 minutes via l'infrastructure GitHub Actions.**

### 📡 Sources et Services Utilisés
* **Présidence de la Cybersécurité (USOM API):** Données officielles de connexions malveillantes et d'incidents de Turquie.
* **CISA (Known Exploited Vulnerabilities):** Flux de vulnérabilités et de renseignements sur la cybersécurité des États-Unis.
* **OpenPhish:** Flux mondiaux d'URL de phishing.
* **Blocklist.de & GreenSnow:** Sources de réputation IP et d'attaques SSH basées en Allemagne et en Suisse.
* **Spamhaus (DROP & EDROP):** Pays-Bas / Blocs IP et réseaux malveillants critiques mondiaux.
* **Abuse.ch (URLhaus, ThreatFox, MalwareBazaar, Feodo Tracker):** URL malveillantes mondiales, IOCs, hachages de fichiers malveillants et IP C2 de botnets.
* **Emerging Threats:** Pools d'IP malveillantes mondiales compromises.

### 🛡️ Politique de Liste Blanche (Whitelist)
Pour éviter les faux positifs et le blocage d'infrastructures critiques, les services et adresses de confiance suivants sont automatiquement filtrés :
* **Fournisseurs DNS Sécurisés :** Google (8.8.8.8, 8.8.4.4), Cloudflare (1.1.1.1, 1.0.0.1), Quad9 (9.9.9.9), OpenDNS.
* **Domaines Critiques :** google.com, cloudflare.com, microsoft.com, apple.com, github.com, amazon.com, siberguvenlik.gov.tr et localhost / 127.0.0.1.

**Auteur:** Kenan Bayram  
[Profil LinkedIn](https://www.linkedin.com/in/kenanbayram)

---

## Italiano
Questo repository è alimentato da un motore di threat intelligence ad alte prestazioni che raccoglie, verifica e categorizza automaticamente i dati sulle minacce (IP, Domini, URL e Hash) da agenzie di cybersicurezza nazionali e globali e da servizi di intelligence open-source. **Viene aggiornato automaticamente ogni 30 minuti tramite l'infrastruttura GitHub Actions.**

### 📡 Fonti e Servizi Utilizzati
* **Presidenza della Sicurezza Informatica (USOM API):** Dati ufficiali di connessioni dannose e incidenti provenienti dalla Turchia.
* **CISA (Known Exploited Vulnerabilities):** Feed di vulnerabilità e intelligence sulla cybersicurezza degli Stati Uniti.
* **OpenPhish:** Stream globali di URL di phishing.
* **Blocklist.de & GreenSnow:** Fonti di reputazione IP e attacchi SSH basate in Germania e Svizzera.
* **Spamhaus (DROP & EDROP):** Paesi Bassi / Blocchi di reti e IP dannosi critici globali.
* **Abuse.ch (URLhaus, ThreatFox, MalwareBazaar, Feodo Tracker):** URL dannosi globali, IOC, hash di file malware e IP C2 di botnet.
* **Emerging Threats:** Pool di IP dannosi globali compromessi.

### 🛡️ Politica di Whitelist
Per prevenire falsi positivi e il blocco di infrastrutture critiche, i seguenti servizi e indirizzi attendibili vengono filtrati automaticamente:
* **Provider DNS Sicuri:** Google (8.8.8.8, 8.8.4.4), Cloudflare (1.1.1.1, 1.0.0.1), Quad9 (9.9.9.9), OpenDNS.
* **Domini Critici:** google.com, cloudflare.com, microsoft.com, apple.com, github.com, amazon.com, siberguvenlik.gov.tr e localhost / 127.0.0.1.

**Autore:** Kenan Bayram  
[Profilo LinkedIn](https://www.linkedin.com/in/kenanbayram)
