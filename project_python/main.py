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
from typing import Set, List, Dict, Optional
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
    # API VirusTotal
    'VIRUSTOTAL_URL': 'https://www.virustotal.com/api/v3/ip_addresses/',
    'REQUEST_TIMEOUT': 10,
    'RETRY_COUNT': 2,
    
    # Rate limiting e timing
    'RATE_LIMIT_DELAY': 15,  # Secondi di attesa tra richieste VirusTotal
    
    # Criteri di classificazione
    'MALICIOUS_THRESHOLD': 1,  # Blocca IP con 1+ rilevamenti
    
    # Elaborazione blocchi
    'BLOCK_SIZE': 255,  # Numero di IP per blocco (default: 254 usabili per /24, + 1 per sicurezza)
    'AUTO_PROCESS_BLOCKS': False,  # True = skip della conferma tra blocchi, False = chiede conferma
    'MAX_BATCHES': 0,  # 0 = illimitato, N = numero massimo di blocchi da processare
    
    # Output e logging
    'VERBOSE_MODE': True,  # True = output dettagliato, False = output minimalista
    'SAVE_RESULTS_JSON': True,  # Salva risultati in JSON
    'SAVE_RESULTS_CSV': False,  # Salva risultati in CSV (non implementato ancora)
    
    # Ottimizzazioni
    'SKIP_WHITELIST_CHECK': False,  # True = non controlla whitelist (per velocizzare)
    'SKIP_BLACKLIST_CHECK': False,  # True = non controlla blacklist (usa solo VirusTotal)
    'CACHE_ENABLED': True,  # True = sfrutta blacklist come cache
    
    # Limiti di sicurezza
    'RIPE_EXPANSION_MAX_WARN': 5000000,  # Limite prima di chiedere conferma
    
    # LEGACY (mantenuti per compatibilità)
    'USE_RIPE_AS': False,  # Disabilitato: usa input_ips.txt invece
    'RIPE_AS_NUMBER': 'AS16276',
    'RIPE_FILTER_PREFIX': '151.245.54.0/24',
}

FILE_PATHS = {
    'log': SCRIPT_DIR / 'ip_check.log',
    'whitelist': SCRIPT_DIR / 'whitelist.txt',
    'blacklist': SCRIPT_DIR / 'blacklist.txt',
    'input_ips': SCRIPT_DIR / 'input_ips.txt',  # File di input per analisi reti /24
    'results': SCRIPT_DIR / 'results.json',  # File risultati JSON
}

# Configurazione logging
def setup_logger(log_file: Path) -> logging.Logger:
    """Configura logging con file"""
    logger = logging.getLogger('ip_checker')
    logger.setLevel(logging.DEBUG)
    handler = logging.FileHandler(log_file, encoding='utf-8', mode='a')
    handler.setFormatter(logging.Formatter('[%(asctime)s] %(levelname)-8s | %(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
    logger.addHandler(handler)
    return logger
 
@dataclass
class IpCheckResults:
    """Risultati del controllo IP"""
    whitelist: List[str] = field(default_factory=list)
    blacklist: List[str] = field(default_factory=list)
    allowed: List[str] = field(default_factory=list)
    suspicious: List[str] = field(default_factory=list)
    invalid: List[str] = field(default_factory=list)
    network_stats: Dict[str, Dict] = field(default_factory=dict)  # Stats per rete /24

    def total(self) -> int:
        """Totale IP processati"""
        return len(self.whitelist) + len(self.blacklist) + len(self.allowed) + len(self.suspicious)


def chiedi_api_key() -> Optional[str]:
    """Chiede API key VirusTotal (INVIO = chiave di test)"""
    test_api_key = "5de14f31ce79d7f88b6420af21d14e26942780cc0bdb43d9c0df86447eabb4c5"  # Rimuovibile per produzione
    prompt = "\n🔐 Inserisci API KEY VirusTotal (premi INVIO per chiave di test): "
    try:
        api_key = input(prompt).strip()
        if not api_key:
            print("ℹ️  Usando chiave di test per VirusTotal")
            return test_api_key
        if len(api_key) >= 20:
            print("ℹ️  Usando chiave VirusTotal fornita")
            return api_key
        print("⚠️  Chiave inserita troppo corta (<20 car), uso chiave di test")
        return test_api_key
    except (KeyboardInterrupt, EOFError):
        return None
    except Exception as e:
        print(f"\n⚠️  Errore lettura API key: {e}")
        return None


def carica_file(file_path: Path, logger: logging.Logger) -> Set[str]:
    """Carica IP da file (ignora linee vuote e #commenti)"""
    try:
        if not file_path.exists():
            logger.warning(f"File non trovato: {file_path}")
            return set()
        with open(file_path, 'r', encoding='utf-8') as f:
            ips = {line.strip() for line in f if line.strip() and not line.startswith('#')}
        logger.info(f"Caricati {len(ips)} IP da {file_path.name}")
        return ips
    except Exception as e:
        logger.error(f"Errore lettura {file_path.name}: {e}")
        return set()


def fetch_prefixes_from_ripe(asn: str, logger: logging.Logger) -> Set[str]:
    """Recupera prefissi AS da RIPEstat API"""
    if not asn:
        return set()
    url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "IP-Malicious-Checker/1.2"})
        with urllib.request.urlopen(req, timeout=CONFIG['REQUEST_TIMEOUT']) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            prefixes = [item.get('prefix') for item in data.get('data', {}).get('prefixes', []) if item.get('prefix')]
            prefixes = sorted(prefixes)
            logger.info(f"RIPE: recuperati {len(prefixes)} prefissi per {asn}")
            return set(prefixes)
    except Exception as e:
        logger.error(f"Errore RIPE {asn}: {e}")
        return set()


def _count_total_addresses(prefixes: Set[str]) -> int:
    """Conta totale indirizzi IPv4 nei prefissi"""
    total = 0
    for p in prefixes:
        try:
            net = ipaddress.ip_network(p, strict=False)
            if net.version == 4:
                total += net.num_addresses
            if total > 10**9:
                return total
        except:
            continue
    return total


def ips_to_networks_24(ips: Set[str], logger: logging.Logger) -> Set[str]:
    """Converte una lista di IP nelle loro reti /24"""
    networks = set()
    for ip in ips:
        try:
            ip_obj = ipaddress.ip_address(ip.strip())
            if ip_obj.version == 4:
                # Crea una rete /24 che contiene l'IP
                net = ipaddress.ip_network(f"{ip_obj}/24", strict=False)
                networks.add(str(net))
            else:
                logger.warning(f"IP non IPv4 ignorato: {ip}")
        except Exception as e:
            logger.warning(f"IP non valido '{ip}': {e}")
    return networks


def get_network_24(ip: str) -> Optional[str]:
    """Ottiene la rete /24 per un dato IP"""
    try:
        ip_obj = ipaddress.ip_address(ip.strip())
        if ip_obj.version == 4:
            net = ipaddress.ip_network(f"{ip_obj}/24", strict=False)
            return str(net)
    except Exception:
        pass
    return None


def generate_ip_blocks(prefixes: Set[str], block_size: int):
    """Generatore di blocchi IP dai prefissi"""
    current = []
    for p in prefixes:
        try:
            for addr in ipaddress.ip_network(p, strict=False).hosts():
                current.append(str(addr))
                if len(current) >= block_size:
                    yield current
                    current = []
        except:
            continue
    if current:
        yield current


def valida_ip(ip: str) -> bool:
    """Valida IPv4/IPv6"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def controlla_su_virustotal(ip: str, api_key: str, logger: logging.Logger) -> Optional[Dict]:
    """Controlla IP su VirusTotal con retry"""
    if not api_key:
        logger.warning(f"Nessuna API key disponibile per {ip}")
        return None
    
    headers = {"x-apikey": api_key, "User-Agent": "IP-Malicious-Checker/1.2"}
    for tentativo in range(CONFIG['RETRY_COUNT']):
        try:
            req = urllib.request.Request(f"{CONFIG['VIRUSTOTAL_URL']}{ip}", headers=headers)
            with urllib.request.urlopen(req, timeout=CONFIG['REQUEST_TIMEOUT']) as r:
                if r.status == 200:
                    data = json.loads(r.read().decode('utf-8'))
                    stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                    logger.debug(f"VirusTotal {ip}: {stats}")
                    return stats
        except urllib.error.HTTPError as e:
            if e.code == 401:
                logger.error(f"API key 401 Unauthorized per {ip} - Verifica validità chiave")
                return None
            elif e.code == 404:
                logger.debug(f"IP {ip} non trovato VirusTotal")
                return {}
            elif e.code == 429 and tentativo < CONFIG['RETRY_COUNT'] - 1:
                attesa = CONFIG['RATE_LIMIT_DELAY'] * (tentativo + 1)
                logger.warning(f"Rate limit, attesa {attesa}s...")
                time.sleep(attesa)
        except urllib.error.URLError as ue:
            if tentativo < CONFIG['RETRY_COUNT'] - 1:
                logger.warning(f"Errore connessione {ip}, tentativo {tentativo + 1}: {ue}")
                time.sleep(2 * (tentativo + 1))
            else:
                logger.error(f"Errore URLError permanente {ip}: {ue}")
        except Exception as e:
            logger.error(f"Errore VirusTotal {ip}: {e}")
    return None


def scrivi_blacklist(ips_malevoli: List[tuple], logger: logging.Logger) -> None:
    """Scrive IP malevoli su blacklist file in batch"""
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


def processa_ips(ips: Set[str], whitelist: Set[str], blacklist: Set[str],
                api_key: Optional[str], logger: logging.Logger) -> IpCheckResults:
    """Processa IP contro whitelist/blacklist e VirusTotal"""
    risultati = IpCheckResults()
    ips_malevoli = []
    totale = len(ips)
    
    for idx, ip in enumerate(sorted(ips), 1):
        network = get_network_24(ip)
        
        # Inizializza statistiche per rete se non esiste
        if network and network not in risultati.network_stats:
            risultati.network_stats[network] = {
                'total': 0,
                'whitelist': 0,
                'blacklist': 0,
                'allowed': 0,
                'suspicious': 0,
                'invalid': 0
            }
        
        if not valida_ip(ip):
            print(f"⚠️  [{idx}/{totale}] {ip} - FORMATO INVALIDO")
            risultati.invalid.append(ip)
            if network:
                risultati.network_stats[network]['invalid'] += 1
            logger.warning(f"IP invalido: {ip}")
        elif ip in blacklist:
            print(f"🚫 [{idx}/{totale}] {ip} - BLOCCATO (blacklist)")
            risultati.blacklist.append(ip)
            if network:
                risultati.network_stats[network]['blacklist'] += 1
            logger.info(f"{ip} - BLOCCATO (blacklist)")
        elif ip in whitelist:
            print(f"✅ [{idx}/{totale}] {ip} - WHITELIST")
            risultati.whitelist.append(ip)
            if network:
                risultati.network_stats[network]['whitelist'] += 1
            logger.info(f"{ip} - WHITELIST")
        elif api_key:
            print(f"🔍 [{idx}/{totale}] {ip} - Verifica VirusTotal...", end=" ", flush=True)
            stats = controlla_su_virustotal(ip, api_key, logger)
            if stats is not None:
                total = stats.get('malicious', 0) + stats.get('suspicious', 0)
                if total >= CONFIG['MALICIOUS_THRESHOLD']:
                    print(f"❌ MALEVOLO ({total} rilevamenti)")
                    risultati.blacklist.append(ip)
                    if network:
                        risultati.network_stats[network]['blacklist'] += 1
                    logger.warning(f"{ip} - MALEVOLO ({total} rilevamenti)")
                    ips_malevoli.append((ip, f"Malevolo - {stats.get('malicious', 0)} rilevamenti"))
                else:
                    print(f"✓ SICURO ({total} rilevamenti)")
                    risultati.allowed.append(ip)
                    if network:
                        risultati.network_stats[network]['allowed'] += 1
                    logger.info(f"{ip} - SICURO ({total} rilevamenti)")
            else:
                print("⚠ Verifica fallita")
                risultati.suspicious.append(ip)
                if network:
                    risultati.network_stats[network]['suspicious'] += 1
                logger.warning(f"{ip} - Verifica VirusTotal fallita")
            time.sleep(CONFIG['RATE_LIMIT_DELAY'])
        else:
            print(f"❓ [{idx}/{totale}] {ip} - SOSPETTO (nessuna API key)")
            risultati.suspicious.append(ip)
            if network:
                risultati.network_stats[network]['suspicious'] += 1
            logger.info(f"{ip} - SOSPETTO (nessuna API key)")
        
        if network and network in risultati.network_stats:
            risultati.network_stats[network]['total'] += 1
    
    if ips_malevoli:
        scrivi_blacklist(ips_malevoli, logger)
    return risultati


def salva_risultati_json(risultati: IpCheckResults, networks: Set[str], logger: logging.Logger) -> None:
    """Salva risultati in formato JSON"""
    try:
        output = {
            'timestamp': datetime.now().isoformat(),
            'networks_analizzate': sorted(list(networks)),
            'statistiche_globali': {
                'whitelist': len(risultati.whitelist),
                'blacklist': len(risultati.blacklist),
                'allowed': len(risultati.allowed),
                'suspicious': len(risultati.suspicious),
                'invalid': len(risultati.invalid),
                'totale': risultati.total()
            },
            'statistiche_per_rete': risultati.network_stats,
            'ips_malevoli': risultati.blacklist,
            'ips_consentiti': risultati.allowed,
            'ips_sospetti': risultati.suspicious
        }
        
        with open(FILE_PATHS['results'], 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Risultati salvati in {FILE_PATHS['results'].name}")
    except Exception as e:
        logger.error(f"Errore salvataggio JSON: {e}")


def stampa_report(risultati: IpCheckResults, networks: Set[str], logger: logging.Logger) -> None:
    """Stampa report risultati con statistiche per rete /24"""
    lines = [
        "\n" + "="*70,
        "📊 REPORT FINALE",
        "="*70,
        f"✅ Whitelist:      {len(risultati.whitelist):>3}",
        f"✓ Consentiti:      {len(risultati.allowed):>3}",
        f"❌ Bloccati:       {len(risultati.blacklist):>3}",
        f"❓ Sospetti:       {len(risultati.suspicious):>3}",
        f"⚠️  Invalidi:       {len(risultati.invalid):>3}",
        f"📊 TOTALE:         {risultati.total():>3}",
        "="*70
    ]
    
    # Aggiungi statistiche per rete
    if risultati.network_stats:
        lines.extend([
            "\n📡 STATISTICHE PER RETE /24",
            "="*70
        ])
        for network in sorted(risultati.network_stats.keys()):
            stats = risultati.network_stats[network]
            lines.append(
                f"{network:20} | Tot:{stats['total']:3} | OK:{stats['allowed']:3} | "
                f"⚠️ :{stats['suspicious']:3} | ❌:{stats['blacklist']:3} | "
                f"✅:{stats['whitelist']:3}"
            )
        lines.append("="*70)
    
    for line in lines:
        print(line)
        if line.startswith(("✅", "✓", "❌", "❓", "⚠️", "📊", "📡")) or "=" in line:
            logger.info(line)


def main():
    """Orchestrazione controllo IP - Analizza IP da file e derives reti /24"""
    print("="*70)
    print("🛡️  IP MALICIOUS CHECKER v1.2 - RETE /24 ANALYZER")
    print("="*70)
    
    try:
        logger = setup_logger(FILE_PATHS['log'])
        logger.info("="*70)
        logger.info(f"Avvio v1.2 - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        logger.info("="*70)
        
        # Richiedi API key
        api_key = chiedi_api_key()
        if api_key:
            print(f"✓ API key: {api_key[:10]}...{api_key[-10:]}")
            logger.info(f"API key: fornita")
        else:
            print("❌ Nessuna API key disponibile")
            logger.warning("API key non fornita - Modalità offline")
        
        # Carica file di configurazione
        print("\n📂 Caricamento dati...")
        whitelist = carica_file(FILE_PATHS['whitelist'], logger)
        blacklist = carica_file(FILE_PATHS['blacklist'], logger)
        input_ips = carica_file(FILE_PATHS['input_ips'], logger)
        
        print(f"✓ Whitelist: {len(whitelist)} IP")
        print(f"✓ Blacklist: {len(blacklist)} IP")
        print(f"✓ IP di input: {len(input_ips)} IP")
        
        if not input_ips:
            print("❌ Nessun IP trovato in input_ips.txt")
            logger.error("Nessun IP trovato in input_ips.txt")
            return
        
        # Derivi le reti /24 dagli IP di input
        print("\n🔧 Derivazione reti /24...")
        networks_24 = ips_to_networks_24(input_ips, logger)
        print(f"✓ Reti /24 identificate: {len(networks_24)}")
        
        if not networks_24:
            print("❌ Nessuna rete /24 potrebbe essere derivata")
            logger.error("Nessuna rete /24 derivata")
            return
        
        print("\n📡 Reti da analizzare:")
        for net in sorted(networks_24):
            print(f"   - {net}")
        
        # Conta totale IP
        total_ips = _count_total_addresses(networks_24)
        print(f"\n📊 Totale IP nelle reti: {total_ips}")
        
        if total_ips > int(CONFIG.get('RIPE_EXPANSION_MAX_WARN', 5000000)):
            print(f"⚠️  {total_ips} indirizzi. Digitare YES per procedere: ", end="")
            if input().strip().lower() not in ('yes', 'y', 'si', 's'):
                print("❌ Annullato")
                logger.info("Annullato per motivo di sicurezza")
                return
        
        risultati_cumulativi = IpCheckResults()
        block_size = int(CONFIG.get('RIPE_EXPANSION_BLOCK_SIZE', 255))
        
        print("\nℹ️  Premi CTRL-C per interrompere.")
        print("\n" + "="*70)
        
        try:
            for idx, block in enumerate(generate_ip_blocks(networks_24, block_size), 1):
                # Informazioni blocco
                if block:
                    first_ip = ipaddress.ip_address(block[0])
                    last_ip = ipaddress.ip_address(block[-1])
                    
                    # Trova la rete /24 che contiene questi IP
                    network_info = None
                    for prefix in networks_24:
                        net = ipaddress.ip_network(prefix, strict=False)
                        if first_ip in net:
                            network_info = str(net)
                            break
                    
                    print(f"\n📡 Blocco {idx}")
                    print(f"   Rete: {network_info if network_info else 'N/A'}")
                    print(f"   Range: {first_ip} - {last_ip}")
                    print(f"   IP nel blocco: {len(block)}")
                
                # Processing blocco
                res = processa_ips(set(block), whitelist, blacklist, api_key, logger)
                
                # Accumula risultati
                risultati_cumulativi.whitelist.extend(res.whitelist)
                risultati_cumulativi.blacklist.extend(res.blacklist)
                risultati_cumulativi.allowed.extend(res.allowed)
                risultati_cumulativi.suspicious.extend(res.suspicious)
                risultati_cumulativi.invalid.extend(res.invalid)
                
                # Merge network stats
                for net, stats in res.network_stats.items():
                    if net in risultati_cumulativi.network_stats:
                        for key in stats:
                            risultati_cumulativi.network_stats[net][key] += stats[key]
                    else:
                        risultati_cumulativi.network_stats[net] = stats
        
        except KeyboardInterrupt:
            print("\n⚠️  Interrotto")
            logger.warning("Interrotto (KeyboardInterrupt)")
        
        # Stampa report finale
        stampa_report(risultati_cumulativi, networks_24, logger)
        
        # Salva risultati
        salva_risultati_json(risultati_cumulativi, networks_24, logger)
        
        print(f"\n📝 Log: {FILE_PATHS['log'].name}")
        print(f"📊 Risultati JSON: {FILE_PATHS['results'].name}")
        print("✓ Completato!")
        logger.info(f"Completato - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        logger.info("="*70)
        
    except KeyboardInterrupt:
        print("\n⚠️  Interrotto")
        logger.warning("Esecuzione interrotta")
    except Exception as e:
        print(f"\n❌ Errore: {e}")
        logger.critical(f"Errore critico: {e}", exc_info=True)
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
