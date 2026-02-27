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
    'VIRUSTOTAL_URL': 'https://www.virustotal.com/api/v3/ip_addresses/',
    'RATE_LIMIT_DELAY': 15,
    'MALICIOUS_THRESHOLD': 1,  # Blocca IP con 1+ rilevamenti
    'REQUEST_TIMEOUT': 10,
    'RETRY_COUNT': 2,
    'USE_RIPE_AS': True,
    'RIPE_AS_NUMBER': 'AS16276',
    'USE_RIPE_EXPAND': True,
    'RIPE_EXPANSION_BLOCK_SIZE': 10,  # Test: blocchi da 10 IP
    'RIPE_EXPANSION_MAX_WARN': 5000000,
    #'RIPE_FILTER_PREFIX': '151.245.54.0/24',  # Filtro disattivato
}

FILE_PATHS = {
    'log': SCRIPT_DIR / 'ip_check_debug.log',
    'malicious_log': SCRIPT_DIR / 'ip_check.log',
    'whitelist': SCRIPT_DIR / 'whitelist.txt',
    'blacklist': SCRIPT_DIR / 'blacklist.txt',
    'networks': SCRIPT_DIR / 'networks.txt',
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
    malicious_details: List[Dict] = field(default_factory=list)

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


def carica_networks(file_path: Path, logger: logging.Logger) -> set:
    """Carica reti/IP da networks.txt (supporta CIDR e IP singoli)."""
    raw_values = carica_file(file_path, logger)
    networks = set()

    for value in raw_values:
        try:
            if '/' in value:
                networks.add(ipaddress.ip_network(value, strict=False))
            else:
                ip_obj = ipaddress.ip_address(value)
                if ip_obj.version == 4:
                    networks.add(ipaddress.ip_network(f"{value}/32", strict=False))
                else:
                    networks.add(ipaddress.ip_network(f"{value}/128", strict=False))
        except ValueError:
            logger.warning(f"Networks.txt - valore non valido ignorato: {value}")

    logger.info(f"Caricate {len(networks)} reti/IP validi da {file_path.name}")
    return networks


def filtra_prefissi_ripe_con_networks(prefixes: Set[str], target_networks: set,
                                      logger: logging.Logger) -> Set[str]:
    """Filtra prefissi RIPE mantenendo solo quelli che intersecano reti/IP target."""
    if not target_networks:
        logger.info("Nessun filtro da networks.txt: uso tutti i prefissi RIPE.")
        return prefixes

    filtered = set()
    for prefix in prefixes:
        try:
            prefix_net = ipaddress.ip_network(prefix, strict=False)
        except ValueError:
            logger.warning(f"Prefisso RIPE non valido ignorato: {prefix}")
            continue

        for target in target_networks:
            if prefix_net.version != target.version:
                continue
            if prefix_net.overlaps(target):
                filtered.add(prefix)
                break

    logger.info(f"Filtro networks.txt applicato: {len(filtered)}/{len(prefixes)} prefissi RIPE mantenuti")
    return filtered


def _intersezione_reti_as(target_networks: set, as_prefixes: Set[str], logger: logging.Logger) -> Set[str]:
    """Restituisce reti CIDR risultanti dall'intersezione tra networks.txt e prefissi AS RIPE."""
    scoped_networks = set()
    parsed_prefixes = []

    for p in as_prefixes:
        try:
            parsed_prefixes.append(ipaddress.ip_network(p, strict=False))
        except ValueError:
            logger.warning(f"Prefisso RIPE non valido ignorato: {p}")

    for target in target_networks:
        for prefix_net in parsed_prefixes:
            if target.version != prefix_net.version:
                continue
            if not target.overlaps(prefix_net):
                continue

            start_ip = max(int(target.network_address), int(prefix_net.network_address))
            end_ip = min(int(target.broadcast_address), int(prefix_net.broadcast_address))
            start_addr = ipaddress.ip_address(start_ip)
            end_addr = ipaddress.ip_address(end_ip)
            for net in ipaddress.summarize_address_range(start_addr, end_addr):
                scoped_networks.add(str(net))

    logger.info(
        f"Scope finale networks.txt ∩ AS: {len(scoped_networks)} reti CIDR da processare"
    )
    return scoped_networks


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


def conta_host_scansionabili(network: ipaddress._BaseNetwork) -> int:
    """Conta host effettivamente scansionabili in una rete."""
    if network.version == 4 and network.prefixlen < 31:
        return max(network.num_addresses - 2, 0)
    return network.num_addresses


def generate_ip_blocks_for_network(network: ipaddress._BaseNetwork, block_size: int):
    """Generatore di blocchi IP da una singola rete."""
    current = []
    for addr in network.hosts():
        current.append(str(addr))
        if len(current) >= block_size:
            yield current
            current = []
    if current:
        yield current


def scrivi_log_malevoli_per_rete(file_path: Path, malevoli_per_rete: Dict[str, List[Dict]],
                                 logger: logging.Logger) -> None:
    """Scrive un report leggibile con soli IP malevoli, raggruppati per rete."""
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write("REPORT IP MALEVOLI PER RETE\n")
            f.write("=" * 70 + "\n\n")

            if not malevoli_per_rete:
                f.write("Nessun IP malevolo rilevato.\n")
                logger.info("Report malevoli: nessun IP malevolo rilevato")
                return

            for network in sorted(malevoli_per_rete.keys()):
                f.write(f"Rete: {network}\n")
                entries = malevoli_per_rete[network]
                dedup = {}
                for item in entries:
                    dedup[item['ip']] = item

                for ip in sorted(dedup.keys(), key=lambda x: ipaddress.ip_address(x)):
                    item = dedup[ip]
                    f.write(
                        f"  - {ip} (malicious={item['malicious']}, suspicious={item['suspicious']}, total={item['total']})\n"
                    )
                f.write("\n")

        logger.info(f"Report malevoli scritto su {file_path.name}")
    except Exception as e:
        logger.error(f"Errore scrittura report malevoli: {e}", exc_info=True)


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
                api_key: Optional[str], logger: logging.Logger,
                source_tag: str = "RIPE", parent_network: str = "") -> IpCheckResults:
    """Processa IP contro whitelist/blacklist e VirusTotal"""
    risultati = IpCheckResults()
    ips_malevoli = []
    totale = len(ips)
    
    for idx, ip in enumerate(sorted(ips), 1):
        if not valida_ip(ip):
            print(f"⚠️  [{idx}/{totale}] {ip} - FORMATO INVALIDO")
            risultati.invalid.append(ip)
            logger.warning(f"IP invalido: {ip}")
        elif ip in blacklist:
            print(f"🚫 [{idx}/{totale}] {ip} - BLOCCATO (blacklist)")
            risultati.blacklist.append(ip)
            logger.info(f"{ip} - BLOCCATO (blacklist)")
        elif ip in whitelist:
            print(f"✅ [{idx}/{totale}] {ip} - WHITELIST")
            risultati.whitelist.append(ip)
            logger.info(f"{ip} - WHITELIST")
        elif api_key:
            print(f"🔍 [{idx}/{totale}] {ip} - Verifica VirusTotal...", end=" ", flush=True)
            stats = controlla_su_virustotal(ip, api_key, logger)
            if stats:
                total = stats.get('malicious', 0) + stats.get('suspicious', 0)
                if total >= CONFIG['MALICIOUS_THRESHOLD']:
                    print(f"❌ MALEVOLO ({total} rilevamenti)")
                    risultati.blacklist.append(ip)
                    logger.warning(f"{ip} - MALEVOLO ({total} rilevamenti)")
                    ips_malevoli.append((ip, f"Malevolo - {stats.get('malicious', 0)} rilevamenti"))
                    logger.warning(f"[{source_tag}] MALEVOLO: {ip} | malicious={stats.get('malicious', 0)} suspicious={stats.get('suspicious', 0)}")
                    risultati.malicious_details.append({
                        'network': parent_network,
                        'ip': ip,
                        'malicious': stats.get('malicious', 0),
                        'suspicious': stats.get('suspicious', 0),
                        'total': total,
                    })
                else:
                    print(f"✓ SICURO ({total} rilevamenti)")
                    risultati.allowed.append(ip)
                    logger.info(f"{ip} - SICURO ({total} rilevamenti)")
            else:
                print("⚠ Verifica fallita")
                risultati.suspicious.append(ip)
                logger.warning(f"{ip} - Verifica VirusTotal fallita")
            time.sleep(CONFIG['RATE_LIMIT_DELAY'])
        else:
            print(f"❓ [{idx}/{totale}] {ip} - SOSPETTO (nessuna API key)")
            risultati.suspicious.append(ip)
            logger.info(f"{ip} - SOSPETTO (nessuna API key)")
    
    if ips_malevoli:
        scrivi_blacklist(ips_malevoli, logger)
    return risultati


def stampa_report(risultati: IpCheckResults, logger: logging.Logger) -> None:
    """Stampa report risultati"""
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
    for line in lines:
        print(line)
        if line.startswith(("✅", "✓", "❌", "❓", "⚠️", "📊")):
            logger.info(line)


def main():
    """Orchestrazione controllo IP"""
    print("="*70)
    print("🛡️  IP MALICIOUS CHECKER v1.2")
    print("="*70)
    
    try:
        logger = setup_logger(FILE_PATHS['log'])
        logger.info("="*70)
        logger.info(f"Avvio v1.2 - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        logger.info("="*70)
        
        api_key = chiedi_api_key()
        if api_key:
            print(f"✓ API key: {api_key[:10]}...{api_key[-10:]}")  # Mostra primi e ultimi 10 caratteri
            logger.info(f"API key: {'fornita' if api_key else 'offline mode'}")
        else:
            print("❌ Nessuna API key disponibile")
        
        print("\n📂 Caricamento dati...")
        whitelist = carica_file(FILE_PATHS['whitelist'], logger)
        blacklist = carica_file(FILE_PATHS['blacklist'], logger)
        network_filters = carica_networks(FILE_PATHS['networks'], logger)
        print(f"✓ Whitelist: {len(whitelist)} IP")
        print(f"✓ Blacklist: {len(blacklist)} IP")
        print(f"✓ Networks.txt: {len(network_filters)} reti/IP validi")
        
        if not network_filters:
            print("❌ networks.txt non contiene reti/IP validi. Processo annullato.")
            logger.error("Nessuna rete valida in networks.txt")
            return

        ripe_prefixes = set()
        reti_scope = set()
        if CONFIG.get('USE_RIPE_AS') and CONFIG.get('RIPE_AS_NUMBER'):
            ripe_prefixes = fetch_prefixes_from_ripe(CONFIG['RIPE_AS_NUMBER'], logger)
            logger.info(f"RIPE AS {CONFIG['RIPE_AS_NUMBER']}: {len(ripe_prefixes)} prefissi")
            print(f"✓ RIPE prefissi: {len(ripe_prefixes)}")
            ripe_prefixes = filtra_prefissi_ripe_con_networks(ripe_prefixes, network_filters, logger)
            print(f"✓ RIPE prefissi in overlap con networks.txt: {len(ripe_prefixes)}")
            
            if CONFIG.get('RIPE_FILTER_PREFIX'):
                filter_prefix = CONFIG['RIPE_FILTER_PREFIX']
                if any(p == filter_prefix for p in ripe_prefixes):
                    ripe_prefixes = {filter_prefix}
                    logger.info(f"Filter: {filter_prefix}")
                    print(f"ℹ️  Filtro: {filter_prefix}")
                else:
                    ripe_prefixes = {filter_prefix}
                    logger.info(f"Override: {filter_prefix}")
                    print(f"ℹ️  Override: {filter_prefix}")

            reti_scope = _intersezione_reti_as(network_filters, ripe_prefixes, logger)
            print(f"✓ Scope finale (networks.txt ∩ AS): {len(reti_scope)} reti")
        
        if not reti_scope or not CONFIG.get('USE_RIPE_EXPAND'):
            print("❌ Nessuna rete target nello scope AS RIPE. Processo annullato.")
            logger.error("Scope reti vuoto o espansione disabilitata")
            return
        
        total_ips = _count_total_addresses(reti_scope)
        if total_ips > int(CONFIG.get('RIPE_EXPANSION_MAX_WARN', 5000000)):
            print(f"⚠️  {total_ips} indirizzi. Digitare YES per procedere: ", end="")
            if input().strip().lower() not in ('yes', 'y', 'si', 's'):
                print("❌ Annullato")
                logger.info("Annullato per motivo di sicurezza")
                return
        
        risultati_cumulativi = IpCheckResults()
        block_size = int(CONFIG.get('RIPE_EXPANSION_BLOCK_SIZE', 10))
        malevoli_per_rete: Dict[str, List[Dict]] = {}
        reti_scope_obj = sorted(
            [ipaddress.ip_network(p, strict=False) for p in reti_scope],
            key=lambda n: (n.version, int(n.network_address), n.prefixlen)
        )

        print("\n🔧 Reti da espandere (priorità networks.txt):")
        for net in reti_scope_obj:
            hosts = conta_host_scansionabili(net)
            blocchi = (hosts + block_size - 1) // block_size if hosts else 0
            print(f"   - {net} | host da verificare: {hosts} | blocchi da {block_size}: {blocchi}")

        print("ℹ️  Premi CTRL-C per interrompere.")

        try:
            for rete_idx, net in enumerate(reti_scope_obj, 1):
                hosts = conta_host_scansionabili(net)
                blocchi = (hosts + block_size - 1) // block_size if hosts else 0
                print(f"\n🌐 Rete [{rete_idx}/{len(reti_scope_obj)}]: {net} | host={hosts} | blocchi={blocchi}")
                logger.info(f"Rete in lavorazione: {net} | host={hosts} | blocchi={blocchi}")

                for block_idx, block in enumerate(generate_ip_blocks_for_network(net, block_size), 1):
                    first_ip = ipaddress.ip_address(block[0])
                    last_ip = ipaddress.ip_address(block[-1])
                    print(f"\n📡 Blocco {block_idx}/{blocchi} - {net}")
                    print(f"   Range: {first_ip} - {last_ip}")
                    print(f"   IP nel blocco: {len(block)}")

                    if not CONFIG.get('AUTO_PROCESS_BLOCKS'):
                        print("\n   Premi INVIO (o 'q' per fermare): ", end="")
                        if input().strip().lower() in ('q', 'quit'):
                            print("❌ Interrotto")
                            raise KeyboardInterrupt
                    else:
                        print("   Processamento...")

                    res = processa_ips(
                        set(block),
                        whitelist,
                        blacklist,
                        api_key,
                        logger,
                        source_tag="NETWORKS_RIPE_SCOPE",
                        parent_network=str(net)
                    )
                    risultati_cumulativi.whitelist.extend(res.whitelist)
                    risultati_cumulativi.blacklist.extend(res.blacklist)
                    risultati_cumulativi.allowed.extend(res.allowed)
                    risultati_cumulativi.suspicious.extend(res.suspicious)
                    risultati_cumulativi.invalid.extend(res.invalid)
                    risultati_cumulativi.malicious_details.extend(res.malicious_details)

                    if res.malicious_details:
                        malevoli_per_rete.setdefault(str(net), []).extend(res.malicious_details)
        except KeyboardInterrupt:
            print("\n⚠️  Interrotto")
            logger.warning("Interrotto (KeyboardInterrupt)")

        scrivi_log_malevoli_per_rete(FILE_PATHS['malicious_log'], malevoli_per_rete, logger)
        stampa_report(risultati_cumulativi, logger)
        print(f"\n📝 Log tecnico: {FILE_PATHS['log'].name}")
        print(f"🧾 Log malevoli: {FILE_PATHS['malicious_log'].name}")
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
