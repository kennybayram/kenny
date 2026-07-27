# 🛡️ Automated Cyber Threat Intelligence & SIEM/Firewall Feed Engine
[![Threat Feed Automation](https://github.com/kennybayram/therat-feeds/actions/workflows/main.yml/badge.svg)](https://github.com/kennybayram/therat-feeds/actions)
[![LinkedIn Profile](https://img.shields.io/badge/LinkedIn-Connect-blue?style=flat&logo=linkedin)](https://www.linkedin.com/in/kennybayram/)

[Türkçe](#türkçe) | [English](#english) | [Deutsch](#deutsch) | [Français](#français) | [Italiano](#italiano)

---

## Türkçe
Bu depo; ulusal ve küresel yetkili siber güvenlik kurumları, CERT yapıları ve açık kaynaklı istihbarat (OSINT) servislerinden güncel tehdit göstergelerini (IoC - IP, Domain, URL ve Hash) otomatik olarak toplayan, doğrulayan, normalleştiren ve **Next-Generation Firewall (NGFW), SIEM (Wazuh, Splunk vb.) ve IDS/IPS sistemlerinde doğrudan kullanılmak üzere** yapılandıran kurumsal seviyede bir tehdit istihbaratı motorudur. **GitHub Actions altyapısı sayesinde her 30 dakikada bir periyodik olarak tamamen otomatik güncellenmektedir.**

### 📡 Entegre Edilen Tehdit Sağlayıcıları ve Kaynaklar
* **Siber Güvenlik Başkanlığı (USOM API):** Türkiye merkezli resmi zararlı bağlantı, zararlı yazılım ve siber olay verileri.
* **CISA (Known Exploited Vulnerabilities):** Amerika Birleşik Devletleri siber güvenlik ve altyapı güvenliği ajansının aktif istismar edilen zafiyet ve gösterge beslemeleri.
* **OpenPhish:** Küresel ölçekte gerçek zamanlı oltalama (phishing) URL akışları.
* **Blocklist.de & GreenSnow:** Avrupa (Almanya ve İsviçre) merkezli IP repütasyon, brute-force ve SSH atak kaynakları.
* **Spamhaus (DROP & EDROP):** Kritik düzeyde tehlikeli ağlar, botnet komuta-kontrol altyapıları ve siber suçlu IP blokları.
* **Abuse.ch (URLhaus, ThreatFox, MalwareBazaar, Feodo Tracker):** Kötü amaçlı URL'ler, tehdit göstergeleri (IOC), zararlı yazılım hash'leri (MD5/SHA256) ve botnet C2 IP adresleri.
* **Emerging Threats:** Komamine edilmiş (compromised) küresel zararlı IP havuzları.

### 🎯 Firewall & SIEM Entegrasyon Mimarisi
* **Firewall / Edge Cihazları:** `threat_ip.txt` ve `threat_domain.txt` dosyaları; harici dinamik blok listeleri (External Dynamic Lists - EDL), adres nesneleri veya ACL kuralları olarak beslenerek zararlı trafiğin çevre biriminde otomatik düşürülmesi sağlanır.
* **SIEM & EDR Sistemleri (Wazuh, Splunk, Elastic vb.):** `threat_url.txt` ve `threat_hash.txt` dosyaları; korelasyon kuralları, dosya bütünlüğü izleme (FIM), uç nokta zararlı tespiti ve tehdit avcılığı (threat hunting) süreçlerinde aktif olarak kullanılır.

### 🛡️ Beyaz Liste (Whitelist) Politikası
Kritik altyapıların ve operasyonel sistemlerin yanlışlıkla engellenmesini (false positive) önlemek amacıyla şu güvenli yapılar otomatik olarak filtrelenmektedir:
* **Güvenli DNS Sağlayıcıları:** Google (8.8.8.8, 8.8.4.4), Cloudflare (1.1.1.1, 1.0.0.1), Quad9 (9.9.9.9), OpenDNS.
* **Kritik Kurumsal ve Yerel Alan Adları:** google.com, cloudflare.com, microsoft.com, apple.com, github.com, amazon.com, siberguvenlik.gov.tr ve yerel loopback (127.0.0.1 / localhost).

**Yazar:** Kenan Bayram (CITO / CISO)  
[LinkedIn Profilim](https://www.linkedin.com/in/kennybayram/)

---

## English
This repository is an enterprise-grade threat intelligence engine designed to automatically collect, verify, normalize, and structure actionable Indicators of Compromise (IoCs - IPs, Domains, URLs, and Hashes) from national and global authoritative cybersecurity agencies, CERTs, and open-source intelligence (OSINT) feeds. **It is automatically updated every 30 minutes via GitHub Actions infrastructure for seamless integration into Next-Generation Firewalls (NGFW), SIEM platforms (Wazuh, Splunk, etc.), and IDS/IPS systems.**

### 📡 Integrated Threat Providers and Sources
* **Cybersecurity Directorate (USOM API):** Official malicious connection, malware, and incident data originating from Turkey.
* **CISA (Known Exploited Vulnerabilities):** United States Cybersecurity and Infrastructure Security Agency actively exploited vulnerability and indicator feeds.
* **OpenPhish:** Global real-time phishing URL streams.
* **Blocklist.de & GreenSnow:** European (Germany & Switzerland based) IP reputation, brute-force, and SSH attack source tracking.
* **Spamhaus (DROP & EDROP):** Critical malicious networks, botnet command-and-control infrastructures, and cybercriminal IP blocks.
* **Abuse.ch (URLhaus, ThreatFox, MalwareBazaar, Feodo Tracker):** Malicious URLs, threat indicators (IOCs), malware file hashes (MD5/SHA256), and botnet C2 IP pools.
* **Emerging Threats:** Compromised global malicious IP pools.

### 🎯 Firewall & SIEM Integration Architecture
* **Firewalls & Edge Devices:** Ingest `threat_ip.txt` and `threat_domain.txt` as External Dynamic Lists (EDL), address objects, or routing rules to automatically drop malicious traffic at the perimeter.
* **SIEM & EDR Platforms (Wazuh, Splunk, Elastic, etc.):** Utilize `threat_url.txt` and `threat_hash.txt` for real-time correlation rules, File Integrity Monitoring (FIM), endpoint protection, and threat hunting workflows.

### 🛡️ Whitelist Policy
To prevent operational disruptions caused by false positives, trusted infrastructure and services are automatically filtered:
* **Secure DNS Providers:** Google (8.8.8.8, 8.8.4.4), Cloudflare (1.1.1.1, 1.0.0.1), Quad9 (9.9.9.9), OpenDNS.
* **Critical Domains & Loopbacks:** google.com, cloudflare.com, microsoft.com, apple.com, github.com, amazon.com, siberguvenlik.gov.tr, and local loopback (127.0.0.1 / localhost).

**Author:** Kenan Bayram (CITO / CISO)  
[LinkedIn Profile](https://www.linkedin.com/in/kennybayram/)

---

## Deutsch
Dieses Repository ist eine Bedrohungsinformations-Engine auf Unternehmensniveau, die verwertbare Indikatoren für Kompromittierungen (IoCs - IPs, Domains, URLs und Hashes) von nationalen und globalen Cybersicherheitsbehörden, CERTs und Open-Source-Intelligence-Feeds (OSINT) automatisch sammelt, verifiziert, normalisiert und für die **direkte Integration in Next-Generation Firewalls (NGFW), SIEM-Plattformen (Wazuh, Splunk usw.) und IDS/IPS-Systeme** strukturiert. **Es wird über die GitHub Actions-Infrastruktur alle 30 Minuten vollautomatisch aktualisiert.**

### 📡 Integrierte Bedrohungsanbieter und Quellen
* **Präsidentschaft für Cybersicherheit (USOM API):** Offizielle Schadverbindungs-, Malware- und Vorfalldaten aus der Türkei.
* **CISA (Known Exploited Vulnerabilities):** Aktiv ausgenutzte Schwachstellen- und Indikator-Feeds der US-amerikanischen CISA.
* **OpenPhish:** Globale Echtzeit-Phishing-URL-Streams.
* **Blocklist.de & GreenSnow:** Europäische (Deutschland- und schweizbasierte) IP-Reputations-, Brute-Force- und SSH-Angriffsquellen.
* **Spamhaus (DROP & EDROP):** Kritische schädliche Netzwerke, Botnet-C2-Infrastrukturen und IP-Blöcke von Cyberkriminellen.
* **Abuse.ch (URLhaus, ThreatFox, MalwareBazaar, Feodo Tracker):** Schädliche URLs, Bedrohungsindikatoren (IOCs), Malware-Dateihashes (MD5/SHA256) und Botnet-C2-IPs.
* **Emerging Threats:** Kompromittierte globale schädliche IP-Pools.

### 🎯 Firewall- & SIEM-Integrationsarchitektur
* **Firewalls & Edge-Geräte:** Nutzen Sie `threat_ip.txt` und `threat_domain.txt` als externe dynamische Blocklisten (EDL) oder Adressobjekte, um schädlichen Datenverkehr am Perimeter automatisch zu blockieren.
* **SIEM- & EDR-Plattformen (Wazuh, Splunk, Elastic usw.):** Verwenden Sie `threat_url.txt` und `threat_hash.txt` für Korrelationsregeln, Dateiintegritätsüberwachung (FIM) und Threat Hunting.

### 🛡️ Whitelist-Richtlinie
Um Fehlalarme (False Positives) zu vermeiden, werden vertrauenswürdige Infrastrukturen und Dienste automatisch herausgefiltert:
* **Sichere DNS-Anbieter:** Google, Cloudflare, Quad9, OpenDNS.
* **Kritische Domains & Netzwerke:** google.com, cloudflare.com, microsoft.com, apple.com, github.com, amazon.com, siberguvenlik.gov.tr und localhost / 127.0.0.1.

**Autor:** Kenan Bayram (CITO / CISO)  
[LinkedIn-Profil](https://www.linkedin.com/in/kennybayram/)

---

## Français
Ce dépôt est un moteur de renseignement sur les menaces de niveau entreprise conçu pour collecter, vérifier, normaliser et structurer automatiquement les indicateurs de compromission (IoCs - IP, Domaines, URL et Hashes) provenant d'agences de cybersécurité nationales et mondiales, de CERTs et de flux de renseignement open-source (OSINT). **Il est mis à jour automatiquement toutes les 30 minutes via l'infrastructure GitHub Actions pour une intégration transparente dans les pare-feu nouvelle génération (NGFW), les plates-formes SIEM (Wazuh, Splunk, etc.) et les systèmes IDS/IPS.**

### 📡 Fournisseurs et Sources de Menaces Intégrés
* **Présidence de la Cybersécurité (USOM API) :** Données officielles de connexions malveillantes, de logiciels malveillants et d'incidents de Turquie.
* **CISA (Known Exploited Vulnerabilities) :** Flux de vulnérabilités activement exploitées et d'indicateurs de l'agence américaine CISA.
* **OpenPhish :** Flux mondiaux d'URL de phishing en temps réel.
* **Blocklist.de & GreenSnow :** Sources européennes (Allemagne et Suisse) de réputation IP, de force brute et d'attaques SSH.
* **Spamhaus (DROP & EDROP) :** Réseaux malveillants critiques, infrastructures de commande et de contrôle de botnets et blocs IP cybercriminels.
* **Abuse.ch (URLhaus, ThreatFox, MalwareBazaar, Feodo Tracker) :** URL malveillantes, indicateurs de menaces (IOC), hachages de fichiers malveillants (MD5/SHA256) et adresses IP C2 de botnets.
* **Emerging Threats :** Pools d'IP malveillantes mondiales compromises.

### 🎯 Architecture d'Intégration Firewall & SIEM
* **Pare-feu et Périphériques de Bord :** Intégrez `threat_ip.txt` et `threat_domain.txt` en tant que listes dynamiques externes (EDL) ou objets d'adresse pour bloquer automatiquement le trafic malveillant au périmètre.
* **Plates-formes SIEM & EDR (Wazuh, Splunk, Elastic, etc.) :** Utilisez `threat_url.txt` et `threat_hash.txt` pour les règles de corrélation en temps réel, la surveillance de l'intégrité des fichiers (FIM) et la recherche de menaces.

### 🛡️ Politique de Liste Blanche
Pour éviter les faux positifs sur les infrastructures critiques, les services de confiance suivants sont automatiquement filtrés :
* **Fournisseurs DNS Sécurisés :** Google, Cloudflare, Quad9, OpenDNS.
* **Domaines Critiques et Boucles Locales :** google.com, cloudflare.com, microsoft.com, apple.com, github.com, amazon.com, siberguvenlik.gov.tr et la boucle locale (127.0.0.1 / localhost).

**Auteur:** Kenan Bayram (CITO / CISO)  
[Profil LinkedIn](https://www.linkedin.com/in/kennybayram/)

---

## Italiano
Questo repository è un motore di threat intelligence di livello aziendale progettato per raccogliere, verificare, normalizzare e strutturare automaticamente gli indicatori di compromissione (IoCs - IP, Domini, URL e Hash) da agenzie di cybersicurezza nazionali e globali, CERT e feed di intelligence open-source (OSINT). **Viene aggiornato automaticamente ogni 30 minuti tramite l'infrastruttura GitHub Actions per un'integrazione perfetta in Firewall di nuova generazione (NGFW), piattaforme SIEM (Wazuh, Splunk, ecc.) e sistemi IDS/IPS.**

### 📡 Fornitori di Minacce e Fonti Integrate
* **Presidenza della Sicurezza Informatica (USOM API):** Dati ufficiali di connessioni dannose, malware e incidenti provenienti dalla Turchia.
* **CISA (Known Exploited Vulnerabilities):** Feed di vulnerabilità attivamente sfruttate e indicatori dell'agenzia statunitense CISA.
* **OpenPhish:** Stream globali in tempo reale di URL di phishing.
* **Blocklist.de & GreenSnow:** Fonti europee (basate in Germania e Svizzera) di reputazione IP, brute-force e attacchi SSH.
* **Spamhaus (DROP & EDROP):** Reti dannose critiche, infrastrutture di comando e controllo (C2) di botnet e blocchi IP di cybercriminali.
* **Abuse.ch (URLhaus, ThreatFox, MalwareBazaar, Feodo Tracker):** URL dannosi, indicatori di minaccia (IOC), hash di file malware (MD5/SHA256) e IP C2 di botnet.
* **Emerging Threats:** Pool di IP dannosi globali compromessi.

### 🎯 Architettura di Integrazione Firewall & SIEM
* **Firewall e Dispositivi Perimetrali:** Utilizza `threat_ip.txt` e `threat_domain.txt` come elenchi dinamici esterni (EDL) o oggetti di indirizzo per bloccare automaticamente il traffico dannoso al perimetro.
* **Piattaforme SIEM & EDR (Wazuh, Splunk, Elastic, ecc.):** Sfrutta `threat_url.txt` e `threat_hash.txt` per regole di correlazione in tempo reale, monitoraggio dell'integrità dei file (FIM) e flussi di threat hunting.

### 🛡️ Politica di Whitelist
Per prevenire falsi positivi su sistemi critici, i servizi e le infrastrutture attendibili vengono filtrati automaticamente:
* **Provider DNS Sicuri:** Google, Cloudflare, Quad9, OpenDNS.
* **Domini Critici e Loop Locali:** google.com, cloudflare.com, microsoft.com, apple.com, github.com, amazon.com, siberguvenlik.gov.tr e local loopback (127.0.0.1 / localhost).

**Autore:** Kenan Bayram (CITO / CISO)  
[Profilo LinkedIn](https://www.linkedin.com/in/kennybayram/)
