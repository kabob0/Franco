#!/usr/bin/env python3
"""
Guida di Integrazione - Fonte Esterna di IP

Questo file spiega come integrare il sito di login con IP Malicious Checker
quando sarà disponibile.

STATUS: DISATTIVATO (funzione pronta, in attesa di specifiche del sito)
"""

# ============================================================================
# CONFIGURAZIONE BASE
# ============================================================================

# Nel file main.py, sezione CONFIG:
CONFIG_TEMPLATE = {
    'USE_EXTERNAL_SOURCE': False,  # ← Cambiare a True quando pronto
    'EXTERNAL_SOURCE_URL': None,   # ← Inserire URL del sito qui
}

# Esempio:
CONFIG_READY = {
    'USE_EXTERNAL_SOURCE': True,
    'EXTERNAL_SOURCE_URL': 'https://tonositosicurezza.com/api/suspicious-ips',
}


# ============================================================================
# STEP 1: FORNIRE URL DEL SITO DI LOGIN
# ============================================================================
"""
Per attivare la funzione:

1. Nel file main.py, sezione CONFIG (linea 29-37), modifica:

    CONFIG = {
        ...
        'USE_EXTERNAL_SOURCE': True,                    # ← Cambia a True
        'EXTERNAL_SOURCE_URL': 'https://TUO_SITO.com',  # ← Inserisci URL
    }

2. Il sito può rispondere in vari formati:
   - JSON: {"ips": ["1.1.1.1", "2.2.2.2"]}
   - JSON alt: {"data": [{"ip": "1.1.1.1"}, ...]}
   - CSV: "1.1.1.1\n2.2.2.2\n"
   - Plaintext: "1.1.1.1\n2.2.2.2\n"
   - HTML: <span class="ip">1.1.1.1</span>

3. La funzione carica_ips_da_fonte_esterna() sarà automaticamente chiamata
"""


# ============================================================================
# STEP 2: SPECIFICARE IL FORMATO DI RISPOSTA
# ============================================================================
"""
Una volta fornito l'URL, comunica il formato di risposta.

Esempi di parsing per diversi formati:
"""

# FORMATO 1: JSON con array di IP
PARSING_JSON_SIMPLE = """
def carica_ips_da_fonte_esterna(url: str, logger: logging.Logger) -> Set[str]:
    if not CONFIG['USE_EXTERNAL_SOURCE']:
        return set()

    logger.info(f"Caricamento da fonte esterna: {url}")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "IP-Malicious-Checker/1.2"})
        with urllib.request.urlopen(req, timeout=CONFIG['REQUEST_TIMEOUT']) as response:
            content = response.read().decode('utf-8')
            data = json.loads(content)

            # Adatta a seconda della struttura JSON:
            ips = set(data.get('ips', []))  # ← Se è {"ips": ["1.1.1.1", ...]}
            # oppure:
            # ips = {item['ip'] for item in data.get('data', [])}  # ← Se è {"data": [{"ip": "..."}, ...]}

            logger.info(f"Caricati {len(ips)} IP da fonte esterna")
            return ips

    except json.JSONDecodeError as e:
        logger.error(f"Errore parsing JSON: {e}")
        return set()
    except Exception as e:
        logger.error(f"Errore fonte esterna {url}: {e}", exc_info=True)
        return set()
"""

# FORMATO 2: CSV o Plaintext (uno per linea)
PARSING_CSV = """
def carica_ips_da_fonte_esterna(url: str, logger: logging.Logger) -> Set[str]:
    if not CONFIG['USE_EXTERNAL_SOURCE']:
        return set()

    logger.info(f"Caricamento da fonte esterna: {url}")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "IP-Malicious-Checker/1.2"})
        with urllib.request.urlopen(req, timeout=CONFIG['REQUEST_TIMEOUT']) as response:
            content = response.read().decode('utf-8')

            # Parse plaintext/CSV - uno per linea
            ips = {
                line.strip()
                for line in content.split('\\n')
                if line.strip() and not line.startswith('#')
            }

            logger.info(f"Caricati {len(ips)} IP da fonte esterna")
            return ips

    except Exception as e:
        logger.error(f"Errore fonte esterna {url}: {e}", exc_info=True)
        return set()
"""

# FORMATO 3: HTML con regex
PARSING_HTML = """
import re

def carica_ips_da_fonte_esterna(url: str, logger: logging.Logger) -> Set[str]:
    if not CONFIG['USE_EXTERNAL_SOURCE']:
        return set()

    logger.info(f"Caricamento da fonte esterna: {url}")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "IP-Malicious-Checker/1.2"})
        with urllib.request.urlopen(req, timeout=CONFIG['REQUEST_TIMEOUT']) as response:
            content = response.read().decode('utf-8')

            # Estrai IP usando regex
            # Esempio: <span class="ip">1.1.1.1</span>
            pattern = r'<span class="ip">(\\d+\\.\\d+\\.\\d+\\.\\d+)</span>'
            ips = set(re.findall(pattern, content))

            logger.info(f"Caricati {len(ips)} IP da fonte esterna")
            return ips

    except re.error as e:
        logger.error(f"Errore regex: {e}")
        return set()
    except Exception as e:
        logger.error(f"Errore fonte esterna {url}: {e}", exc_info=True)
        return set()
"""


# ============================================================================
# STEP 3: AUTENTICAZIONE (SE RICHIESTA)
# ============================================================================
"""
Se il sito richiede autenticazione (API key, token, basic auth):
"""

PARSING_WITH_AUTH = """
def carica_ips_da_fonte_esterna(url: str, logger: logging.Logger, auth_token: str = None) -> Set[str]:
    if not CONFIG['USE_EXTERNAL_SOURCE']:
        return set()

    logger.info(f"Caricamento da fonte esterna: {url}")
    try:
        headers = {
            "User-Agent": "IP-Malicious-Checker/1.2",
            "Authorization": f"Bearer {auth_token}"  # ← Aggiungere token
        }

        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=CONFIG['REQUEST_TIMEOUT']) as response:
            if response.status == 200:
                content = response.read().decode('utf-8')
                data = json.loads(content)
                ips = set(data.get('ips', []))

                logger.info(f"Caricati {len(ips)} IP da fonte esterna")
                return ips

    except urllib.error.HTTPError as e:
        if e.code == 401:
            logger.error("Errore autenticazione fonte esterna (401)")
        elif e.code == 403:
            logger.error("Accesso negato a fonte esterna (403)")
        else:
            logger.error(f"HTTP {e.code}: {e}")

    except Exception as e:
        logger.error(f"Errore fonte esterna {url}: {e}", exc_info=True)

    return set()

# Nel main(), passare il token:
# auth_token = os.getenv('EXTERNAL_SOURCE_API_KEY')  # Da variabile d'ambiente
# ips_esterni = carica_ips_da_fonte_esterna(url, logger, auth_token)
"""


# ============================================================================
# STEP 4: TESTING DELLA INTEGRAZIONE
# ============================================================================
"""
Una volta configurato, testare così:

1. Verificare che la funzione viene chiamata
   → Controllare il log con il messaggio "Caricamento da fonte esterna"

2. Verificare il parsing
   → Nel log dovrebbe apparire "Caricati N IP da fonte esterna"

3. Verificare che gli IP vengono processati
   → Nel report finale, il TOTALE dovrebbe includere gli IP della fonte

4. Eseguire test end-to-end
   ```bash
   cd project_python
   python main.py
   # → Dovrebbe caricare IP da:
    #   1. File locale contenente IP da verificare (uno per riga)
   #   2. Fonte esterna (se abilitata)
   #   3. Verificarli tutti contro VirusTotal
   ```

Esempio log atteso:
```
[2025-02-17 14:30:10] INFO     | Elenco operazioni completate
[2025-02-17 14:30:11] INFO     | Caricamenti da whitelist e blacklist (file locali)
[2025-02-17 14:30:11] INFO     | Caricamento da fonte esterna: https://tonositosicurezza.com/api/ips
[2025-02-17 14:30:12] INFO     | Caricati 42 IP da fonte esterna
[2025-02-17 14:30:12] INFO     | Verificazione di 48 IP totali (6 locali + 42 esterni)
...
```
"""


# ============================================================================
# STEP 5: SICUREZZA E BEST PRACTICES
# ============================================================================
"""
Considerazioni di sicurezza per la fonte esterna:

1. **HTTPS OBBLIGATORIO**
   - Verificare che l'URL sia https://, non http://
   - urllib valida automaticamente il certificato SSL

2. **TIMEOUT**
   - Configurato a CONFIG['REQUEST_TIMEOUT'] = 10 secondi
   - Aumentare se il sito è lento (es. 30 secondi)

3. **AUTENTICAZIONE**
   - Se richiesta, usare Bearer token o API key
   - NON inserire credenziali hardcoded nel codice
   - Usare variabili d'ambiente:
     import os
     api_key = os.getenv('EXTERNAL_SOURCE_API_KEY')

4. **VALIDAZIONE INPUT**
   - Gli IP caricati vengono validati con valida_ip()
   - IP invalidi vengono scartati automaticamente

5. **LOGGING**
   - Ogni errore viene loggato con stack trace completo
   - Non vengono loggati token o dati sensibili

6. **CACHING** (opzionale)
   - Se il sito è lento, si può implementare caching:
     import hashlib
     cache_file = SCRIPT_DIR / f".cache_ips_{hashlib.md5(url.encode()).hexdigest()}"
     if cache_file.exists() and (datetime.now() - cache_file.stat().st_mtime).seconds < 3600:
         # Usa cache se meno di 1 ora fa
"""


# ============================================================================
# RIEPILOGO CHECKLIST PER L'INTEGRAZIONE
# ============================================================================
"""
Quando il sito è pronto, completare:

FORNIRE AL TEAM:
☐ URL endpoint del sito
☐ Metodo HTTP (GET/POST)
☐ Formato risposta (JSON/CSV/HTML)
☐ Autenticazione richiesta? (token/API key/basic auth)
☐ Rate limit? (richieste al minuto)
☐ Documentazione API

DA IMPLEMENTARE:
☐ Abilitare CONFIG['USE_EXTERNAL_SOURCE'] = True
☐ Impostare CONFIG['EXTERNAL_SOURCE_URL']
☐ Implementare parser nella funzione carica_ips_da_fonte_esterna()
☐ Aggiungere autenticazione se necessaria
☐ Testare end-to-end
☐ Aggiungere documentazione nel codice

SUPPORTO POST-INTEGRAZIONE:
☐ Monitorare log per errori di connessione
☐ Testare fallback se il sito è down
☐ Implementare retry se necessario
☐ Aggiungere caching se performance è critica
"""

# ============================================================================
# CONTATTI E SUPPORTO
# ============================================================================
"""
Per domande sulla integrazione:
- Consultare REFACTORING_NOTES.md per l'architettura generale
- Leggere docstrings della funzione carica_ips_da_fonte_esterna()
- Controllare il log per debug (ip_check.log)

Pronto per iniziare! 🚀
"""
