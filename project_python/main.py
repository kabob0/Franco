#!/usr/bin/env python3
"""
IP Malicious Checker v1.2 - Verifica indirizzi IP su VirusTotal
Supporta whitelist/blacklist e genera report dettagliati con logging.
"""

import ipaddress
import os
import sys
import time
import json
import logging
import getpass
import urllib.request
import urllib.error
from typing import Set, List, Dict, Optional, TextIO
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field

# Forza UTF-8 per Windows
if sys.stdout.encoding != 'utf-8':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

# Configurazione
SCRIPT_DIR = Path(__file__).parent
CONFIG = {
    'VIRUSTOTAL_URL': 'https://www.virustotal.com/api/v3/ip_addresses/',
    'RATE_LIMIT_DELAY': 15,
    'MALICIOUS_THRESHOLD': 5,
    'REQUEST_TIMEOUT': 10,
    'RETRY_COUNT': 2,
    'USE_EXTERNAL_SOURCE': False,  # Disattivato per adesso
    'EXTERNAL_SOURCE_URL': None,   # Sarà configurato dopo
}

FILE_PATHS = {
    'log': SCRIPT_DIR / 'ip_check.log',
    'whitelist': SCRIPT_DIR / 'whitelist.txt',
    'blacklist': SCRIPT_DIR / 'blacklist.txt',
    'ips_to_check': SCRIPT_DIR / 'ips_to_check.txt',
}

# Configurazione logging
def setup_logger(log_file: Path) -> logging.Logger:
    """Configura logging standard con file e console"""
    logger = logging.getLogger('ip_checker')
    logger.setLevel(logging.DEBUG)

    # Handler file
    file_handler = logging.FileHandler(log_file, encoding='utf-8', mode='a')
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(
        '[%(asctime)s] %(levelname)-8s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(file_formatter)

    logger.addHandler(file_handler)
    return logger


@dataclass
class IpCheckResults:
    """Risultati del controllo IP"""
    whitelist: List[str] = field(default_factory=list)
    blacklist: List[str] = field(default_factory=list)
    allowed: List[str] = field(default_factory=list)
    suspicious: List[str] = field(default_factory=list)
    invalid: List[str] = field(default_factory=list)

    def total(self) -> int:
        """Totale IP processati"""
        return len(self.whitelist) + len(self.blacklist) + len(self.allowed) + len(self.suspicious)


def chiedi_api_key() -> Optional[str]:
    """
    Chiede API key all'utente in modo sicuro usando getpass.
    Valida la lunghezza (min 20 caratteri tipici VirusTotal).
    """
    print("\n🔐 API KEY VirusTotal (oppure premi INVIO per saltare):")
    try:
        api_key = getpass.getpass(">>> ").strip()
        if not api_key:
            return None
        if len(api_key) >= 20:
            return api_key
        else:
            print("⚠️  API key troppo corta (minimo 20 caratteri)")
            return None
    except (KeyboardInterrupt, EOFError):
        print("\n⚠️  Input interrotto")
        return None
    except Exception as e:
        print(f"❌ Errore lettura API key: {e}")
        return None


def carica_file(file_path: Path, logger: logging.Logger) -> Set[str]:
    """
    Carica indirizzi IP da file, ignorando commenti e linee vuote.

    Args:
        file_path: Percorso del file
        logger: Logger per messaggi di debug

    Returns:
        Set di indirizzi IP validi
    """
    try:
        if not file_path.exists():
            print(f"⚠️  File non trovato: {file_path}")
            logger.warning(f"File non trovato: {file_path}")
            return set()

        with open(file_path, 'r', encoding='utf-8') as f:
            ips = {line.strip() for line in f if line.strip() and not line.startswith('#')}

        logger.info(f"Caricati {len(ips)} IP da {file_path.name}")
        return ips

    except Exception as e:
        print(f"❌ Errore lettura {file_path.name}: {e}")
        logger.error(f"Errore lettura {file_path.name}: {e}", exc_info=True)
        return set()


def valida_ip(ip: str) -> bool:
    """
    Valida formato IPv4 o IPv6.

    Args:
        ip: Stringa indirizzo IP

    Returns:
        True se valido, False altrimenti
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def controlla_su_virustotal(ip: str, api_key: str, logger: logging.Logger) -> Optional[Dict]:
    """
    Controlla IP su VirusTotal con retry automatico.

    Args:
        ip: Indirizzo IP da controllare
        api_key: API key VirusTotal
        logger: Logger per debug

    Returns:
        Dict con statistics o None se errore
    """
    if not api_key:
        return None

    headers = {
        "x-apikey": api_key,
        "User-Agent": "IP-Malicious-Checker/1.2"
    }

    retry_count = CONFIG['RETRY_COUNT']
    for tentativo in range(retry_count):
        try:
            url = f"{CONFIG['VIRUSTOTAL_URL']}{ip}"
            req = urllib.request.Request(url, headers=headers)

            with urllib.request.urlopen(req, timeout=CONFIG['REQUEST_TIMEOUT']) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode('utf-8'))
                    stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                    logger.debug(f"VirusTotal {ip}: {stats}")
                    return stats

        except urllib.error.HTTPError as e:
            if e.code == 401:
                print("❌ API key non valida")
                logger.error("API key VirusTotal non valida (401)")
                return None
            elif e.code == 429:
                # Rate limit
                if tentativo < retry_count - 1:
                    attesa = CONFIG['RATE_LIMIT_DELAY'] * (tentativo + 1)
                    logger.warning(f"Rate limit VirusTotal, attesa {attesa}s...")
                    time.sleep(attesa)
                    continue
            elif e.code == 404:
                logger.debug(f"IP {ip} non trovato su VirusTotal")
                return {}
            else:
                logger.warning(f"HTTP {e.code} per {ip}: {e}")

        except urllib.error.URLError as e:
            if tentativo < retry_count - 1:
                logger.warning(f"Errore connessione {ip}, tentativo {tentativo + 1}/{retry_count}")
                time.sleep(2 * (tentativo + 1))
                continue
            else:
                logger.error(f"Errore URLError permanente per {ip}: {e}")

        except Exception as e:
            logger.error(f"Errore VirusTotal per {ip}: {e}", exc_info=True)

    return None


def scrivi_blacklist(ips_malevoli: List[tuple], logger: logging.Logger) -> None:
    """
    Scrive IP malevoli su blacklist file in batch per efficienza.

    Args:
        ips_malevoli: Lista di tuple (ip, motivo)
        logger: Logger per debug
    """
    if not ips_malevoli:
        return

    try:
        with open(FILE_PATHS['blacklist'], 'a', encoding='utf-8') as f:
            for ip, motivo in ips_malevoli:
                f.write(f"{ip}  # {motivo}\n")

        logger.info(f"Salvati {len(ips_malevoli)} IP su blacklist")

    except Exception as e:
        print(f"⚠️  Errore salvataggio blacklist: {e}")
        logger.error(f"Errore salvataggio blacklist: {e}", exc_info=True)


def carica_ips_da_fonte_esterna(url: str, logger: logging.Logger) -> Set[str]:
    """
    Carica indirizzi IP da una fonte esterna (es. form di login web).
    DISATTIVATA per default - attivare con CONFIG['USE_EXTERNAL_SOURCE'] = True

    Args:
        url: URL della fonte esterna
        logger: Logger per debug

    Returns:
        Set di indirizzi IP

    Note:
        Questa funzione sarà integrata con il sito di login fornito successivamente.
        Supporterà POST/GET per retrievare lista IP dinamicamente.
    """
    if not CONFIG['USE_EXTERNAL_SOURCE']:
        return set()

    logger.info(f"Caricamento da fonte esterna: {url}")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "IP-Malicious-Checker/1.2"})
        with urllib.request.urlopen(req, timeout=CONFIG['REQUEST_TIMEOUT']) as response:
            content = response.read().decode('utf-8')
            # TODO: Parse il formato della risposta (JSON, CSV, plaintext, ecc.)
            # Esempio: se JSON con campo "ips"
            # data = json.loads(content)
            # return set(data.get('ips', []))
            logger.warning("carica_ips_da_fonte_esterna: parser non implementato")
            return set()

    except Exception as e:
        print(f"⚠️  Errore caricamento fonte esterna: {e}")
        logger.error(f"Errore fonte esterna {url}: {e}", exc_info=True)
        return set()


def processa_ips(ips: Set[str], whitelist: Set[str], blacklist: Set[str],
                api_key: Optional[str], logger: logging.Logger) -> IpCheckResults:
    """
    Processa lista di IP verificando contro whitelist/blacklist e VirusTotal.

    Args:
        ips: Set di IP da controllare
        whitelist: Set di IP fidati
        blacklist: Set di IP bloccati
        api_key: API key VirusTotal (opzionale)
        logger: Logger per debug

    Returns:
        IpCheckResults con classificazione IP
    """
    risultati = IpCheckResults()
    ips_malevoli = []
    ips_ordinati = sorted(ips)
    totale = len(ips_ordinati)

    for idx, ip in enumerate(ips_ordinati, 1):
        # Validazione
        if not valida_ip(ip):
            print(f"⚠️  [{idx}/{totale}] {ip} - FORMATO INVALIDO")
            risultati.invalid.append(ip)
            logger.warning(f"IP invalido: {ip}")
            continue

        # Blacklist check
        if ip in blacklist:
            print(f"🚫 [{idx}/{totale}] {ip} - BLOCCATO (blacklist)")
            risultati.blacklist.append(ip)
            logger.info(f"{ip} - BLOCCATO (blacklist)")
            continue

        # Whitelist check
        if ip in whitelist:
            print(f"✅ [{idx}/{totale}] {ip} - WHITELIST")
            risultati.whitelist.append(ip)
            logger.info(f"{ip} - WHITELIST")
            continue

        # VirusTotal check
        if api_key:
            print(f"🔍 [{idx}/{totale}] {ip} - Verifica VirusTotal...", end=" ", flush=True)
            stats = controlla_su_virustotal(ip, api_key, logger)

            if stats is not None:
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                total = malicious + suspicious

                if total >= CONFIG['MALICIOUS_THRESHOLD']:
                    print(f"❌ MALEVOLO ({malicious} rilevamenti)")
                    risultati.blacklist.append(ip)
                    logger.warning(f"{ip} - MALEVOLO ({malicious} rilevamenti VirusTotal)")
                    ips_malevoli.append((ip, f"Malevolo - {malicious} rilevamenti"))
                else:
                    print(f"✓ SICURO ({total} rilevamenti)")
                    risultati.allowed.append(ip)
                    logger.info(f"{ip} - SICURO ({total} rilevamenti VirusTotal)")
            else:
                print("⚠ Verifica fallita")
                risultati.suspicious.append(ip)
                logger.warning(f"{ip} - Verifica VirusTotal fallita")

            time.sleep(CONFIG['RATE_LIMIT_DELAY'])
        else:
            print(f"❓ [{idx}/{totale}] {ip} - SOSPETTO (nessuna API key)")
            risultati.suspicious.append(ip)
            logger.info(f"{ip} - SOSPETTO (API key non fornita)")

    # Salva batch di IP malevoli
    if ips_malevoli:
        scrivi_blacklist(ips_malevoli, logger)

    return risultati


def stampa_report(risultati: IpCheckResults, logger: logging.Logger) -> None:
    """
    Stampa report formattato dei risultati.

    Args:
        risultati: IpCheckResults dal processing
        logger: Logger per salvataggio
    """
    print("\n" + "="*70)
    print("📊 REPORT FINALE")
    print("="*70)

    report_lines = [
        f"✅ Whitelist:      {len(risultati.whitelist):>3}",
        f"✓ Consentiti:      {len(risultati.allowed):>3}",
        f"❌ Bloccati:       {len(risultati.blacklist):>3}",
        f"❓ Sospetti:       {len(risultati.suspicious):>3}",
        f"⚠️  Invalidi:       {len(risultati.invalid):>3}",
        f"📊 TOTALE:         {risultati.total():>3}",
    ]

    for line in report_lines:
        print(line)

    print("="*70)

    # Log report
    for line in report_lines:
        logger.info(line)


def main():
    """Funzione principale - orchestrazione del flusso"""
    print("="*70)
    print("🛡️  IP MALICIOUS CHECKER v1.2")
    print("="*70)

    try:
        # Setup logging
        logger = setup_logger(FILE_PATHS['log'])
        logger.info("="*70)
        logger.info(f"Avvio IP Malicious Checker v1.2 - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        logger.info("="*70)

        # Chiedi API key
        api_key = chiedi_api_key()
        if api_key:
            logger.info("API key VirusTotal fornita")
        else:
            logger.info("Nessuna API key - verrà usata modalità offline")

        # Carica file
        print("\n📂 Caricamento dati...")
        whitelist = carica_file(FILE_PATHS['whitelist'], logger)
        blacklist = carica_file(FILE_PATHS['blacklist'], logger)
        ips_da_controllare = carica_file(FILE_PATHS['ips_to_check'], logger)

        # Carica da fonte esterna se abilitato
        if CONFIG['USE_EXTERNAL_SOURCE'] and CONFIG['EXTERNAL_SOURCE_URL']:
            ips_esterni = carica_ips_da_fonte_esterna(CONFIG['EXTERNAL_SOURCE_URL'], logger)
            ips_da_controllare.update(ips_esterni)
            logger.info(f"IP da fonte esterna: {len(ips_esterni)}")

        # Validazione
        if not ips_da_controllare:
            print("❌ Nessun IP da controllare!")
            logger.error("Nessun IP disponibile per il controllo")
            return

        print(f"✓ Whitelist: {len(whitelist)} IP")
        print(f"✓ Blacklist: {len(blacklist)} IP")
        print(f"✓ Da controllare: {len(ips_da_controllare)} IP")

        # Processa IP
        print("\n" + "="*70)
        print("🔍 CONTROLLO IP")
        print("="*70)

        risultati = processa_ips(ips_da_controllare, whitelist, blacklist, api_key, logger)

        # Stampa report
        stampa_report(risultati, logger)

        print(f"\n📝 Log salvato: {FILE_PATHS['log'].name}")
        print("✓ Controllo completato!")

        logger.info(f"Controllo completato - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        logger.info("="*70)

    except KeyboardInterrupt:
        print("\n\n⚠️  Controllo interrotto dall'utente")
        logger.warning("Esecuzione interrotta da utente (KeyboardInterrupt)")

    except Exception as e:
        print(f"\n❌ Errore critico: {e}")
        logger.critical(f"Errore critico durante esecuzione: {e}", exc_info=True)
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
