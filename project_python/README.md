# 🛡️ IP Malicious Checker v1.2

Verificatore IP per whitelist/blacklist con controllo su VirusTotal mediante RIPE AS expansion.

## 🚀 Quick Start

```bash
cd project_python
python main.py
```

Lo script:
1. Chiede API key VirusTotal (opzionale, con `getpass()` sicuro)
2. Carica whitelist/blacklist
3. Recupera prefissi RIPE AS 16276 (configurabile)
4. Espande blocchi di IP
5. Verifica su VirusTotal
6. Genera report e log

## 📋 File Necessari

| File | Descrizione |
|------|------------|
| `whitelist.txt` | IP fidati (uno per riga) |
| `blacklist.txt` | IP bloccati (aggiornato automaticamente) |
| `ip_check.log` | Log risultati (generato automaticamente) |

## ⚙️ Configurazione (main.py: CONFIG dict)

```python
CONFIG = {
    'VIRUSTOTAL_URL': 'https://www.virustotal.com/api/v3/ip_addresses/',
    'RATE_LIMIT_DELAY': 15,           # Secondi tra richieste VT
    'MALICIOUS_THRESHOLD': 1,         # Detections per considerare malevolo (test=1, prod=5)
    'REQUEST_TIMEOUT': 10,            # Timeout URLopen
    'RETRY_COUNT': 2,                 # Retry su errori transitori
    'USE_RIPE_AS': True,              # Fetch RIPE prefissi
    'RIPE_AS_NUMBER': 'AS16276',      # ASN da espandere
    'USE_RIPE_EXPAND': True,          # Espandi prefissi a blocchi di IP
    'RIPE_EXPANSION_BLOCK_SIZE': 10,  # IP per blocco (test=10, prod=1024)
    'RIPE_EXPANSION_MAX_WARN': 5000000,  # Max IP prima di chiedere conferma
    'RIPE_FILTER_PREFIX': '151.245.54.0/24',  # Test-only: filtra su prefisso
}
```

### Per Modalità Produzione
Modificare in `main.py`:
```python
'MALICIOUS_THRESHOLD': 5,              # Più rigoroso
'RIPE_EXPANSION_BLOCK_SIZE': 1024,     # Blocchi normali
'RIPE_FILTER_PREFIX': None,            # Usa tutti i prefissi RIPE
```

## ✨ Output Report

```
📊 REPORT FINALE
✅ Whitelist:      123
✓ Consentiti:      456
❌ Bloccati:       7
❓ Sospetti:       2
⚠️  Invalidi:       0
📊 TOTALE:         588
```

## 🔑 API Key VirusTotal

**Opzionale** - Senza key, funziona offline con whitelist/blacklist.

```bash
# All'avvio dello script, inserisci key in modo sicuro (getpass - non visibile)
# Registrati: https://www.virustotal.com/
```

## 📊 Flusso Logico

```
1. Carica whitelist/blacklist   ← Batch read
2. Recupera RIPE prefissi       ← AS16276
3. [Filter prefisso opzionale]  ← Se RIPE_FILTER_PREFIX set
4. Account IP totali            ← Warn se >5M
5. Loop blocchi IP:
   - Processa IP singoli
   - Valida formato
   - Blacklist check
   - Whitelist check
   - VirusTotal check (se API key)
   - Batch save malevoli
6. Report cumulativo + Log
```

## 🛠️ Testing (Cliente Demo)

Configurazione è **già impostata per test** su 151.245.54.0/24 (25 blocchi × 10 IP):
- All'avvio, lo script espande automaticamente il prefisso test
- Processa 254 indirizzi in blocchi di 10
- MALICIOUS_THRESHOLD=1 (sensibile a 1+ detection)

```bash
python main.py          # Configurazione test pronta
# Quando chiede API key: inserisci (o premi Enter per offline)
# Script espande automaticamente blocchi di 10 IP su 151.245.54.0/24
```

## 📝 Struttura File

```
project_python/
├── main.py                    # Script principale (396 linee, ottimizzato)
├── README.md                  # Questa documentazione
├── requirements.txt           # Dipendenze (nulla per stdlib)
├── whitelist.txt              # IP fidati
├── blacklist.txt              # IP bloccati (aggiornato)
├── ip_check.log               # Log risultati
├── .gitignore                 # File ignore
└── __pycache__/               # Cache Python
```

## ⚙️ Requisiti

- **Python 3.7+** (Testato su 3.14.3)
- **Zero dipendenze esterne** - Solo librerie standard:
  - `urllib` (RIPE API, VirusTotal)
  - `json` (parsing risposta)
  - `logging` (file log)
  - `ipaddress` (validazione/espansione IP)
  - `pathlib` (I/O file)
  - `dataclasses` (result types)
  - `getpass` (API key sicura)

## 🔧 Funzioni Principali

| Funzione | Ruolo |
|----------|-------|
| `chiedi_api_key()` | Input sicuro API key |
| `carica_file()` | Batch load whitelist/blacklist |
| `fetch_prefixes_from_ripe()` | RIPE API AS lookup |
| `generate_ip_blocks()` | Generator blocchi IP |
| `valida_ip()` | Format check IPv4/IPv6 |
| `controlla_su_virustotal()` | VT query con retry |
| `processa_ips()` | Loop verifica IP |
| `scrivi_blacklist()` | Batch save malevoli |
| `stampa_report()` | Report finale |
| `main()` | Orchestrazione |

## 📊 Ottimizzazioni

Script è stato **aggressivamente ottimizzato** per alleggerezza:

- **Docstring compattate**: Multi-linea → One-liner (quando logico)
- **Consolidation**: Removed verbose comments
- **Batch I/O**: File read/write in singoli batch (non per IP)
- **Generatori**: `generate_ip_blocks()` usa `yield` per memoria efficiente
- **Logger-only**: Niente `print()` per debug (solo log)

**Risultato**: 570 linee (originale) → **396 linee** (-174 linee, -30%)

## 🐛 Troubleshooting

### "401 - API key non valida"
- Verifica API key su https://www.virustotal.com/
- Key deve avere permesso `ip-addresses` read

### "404 - IP non trovato VirusTotal"
- IP potrebbe non essere mai stato sottomesso a VT
- Script continua normalmente

### "429 - Rate limit"
- Script automaticamente attende CONFIG['RATE_LIMIT_DELAY'] * (tentativo+1)
- Retry fino a RETRY_COUNT

### Nessun prefisso RIPE
- Verificare `USE_RIPE_AS=True` e `RIPE_AS_NUMBER='AS16276'`
- Controllare connessione rete
- Log per dettagli in `ip_check.log`

## 📚 Informazioni Tecniche

### RIPE API Integration
- Endpoint: `https://rest.db.ripe.net/ripe/as-set/AS16276/set`
- Ritorna set di prefissi per AS16276
- Per AS diverso, modificare `RIPE_AS_NUMBER`
- Prefisso filtrabile con `RIPE_FILTER_PREFIX` (testing)

### VirusTotal API
- Endpoint: `https://www.virustotal.com/api/v3/ip_addresses/{ip}`
- Response JSON: `data.attributes.last_analysis_stats`
- Field: `malicious` + `suspicious` vs `MALICIOUS_THRESHOLD`
- Rate limit: 4 query/minuto (free tier)

### Iterazione RIPE Expansion
```python
for block in generate_ip_blocks(ripe_prefixes, block_size):
    # block = lista IP
    res = processa_ips(set(block), whitelist, blacklist, api_key, logger)
    # Accumula risultati cumulativamente
```

Ogni blocco processato con sleep tra query VirusTotal.

## 📄 Licenza & Note

- Script produzione-ready per cliente demo
- Configurazione test pre-caricata (151.245.54.0/24, 10 IP/blocco)
- Logging completo per debugging
- Nessuna dipendenza esterna (stdlib only)
