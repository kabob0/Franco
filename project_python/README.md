# 🛡️ IP Malicious Checker

Script Python per controllare indirizzi IP su whitelist/blacklist e verificarli su VirusTotal.

## 🚀 Quick Start

```bash
cd project_python
python main.py
```

## 📝 File Necessari

| File | Descrizione |
|------|------------|
| `whitelist.txt` | IP fidati (uno per riga) |
| `ips_to_check.txt` | IP da controllare (uno per riga) |
| `blacklist.txt` | IP bloccati (aggiornato automaticamente) |

## ✨ Come Funziona

1. **Whitelist** → IP consentiti ✅
2. **Blacklist** → IP bloccati 🚫
3. **VirusTotal** → Verifica IP sospetti (opzionale)
4. **Log** → Salva risultati in `ip_check.log`

## 🔑 API Key VirusTotal (Opzionale)

Lo script chiede la API key all'avvio. Senza di essa funziona comunque con whitelist/blacklist.

```
Registrati: https://www.virustotal.com/
```

## 📊 Output

```
✅ WHITELIST    → IP in lista fidata
✓ CONSENTITO    → Verificato sicuro
❌ BLOCCATO     → Malevolo o in blacklist
❓ SOSPETTO     → Non verificato
```

## 📂 Struttura

```
project_python/
├── main.py
├── whitelist.txt
├── ips_to_check.txt
├── blacklist.txt
├── ip_check.log
└── README.md
```

## ⚙️ Requisiti

- Python 3.7+
- Nessuna dipendenza obbligatoria
