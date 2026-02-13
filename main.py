#!/usr/bin/env python3
"""
Script per filtrare indirizzi IP dalla whitelist e controllare quelli malevoli
"""

import ipaddress
import os
from typing import List, Set, Optional, Dict, Tuple
import time
from datetime import datetime

# Configurazione
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/ip_addresses/"
RATE_LIMIT_DELAY = 15  # Secondi tra le richieste (free tier: 4 req/min)
MALICIOUS_THRESHOLD = 5  # Numero minimo di rilevamenti per considerare IP malevolo
LOG_FILE = "ip_check.log"

def chiedi_api_key() -> str:
    """Chiede la API key all'utente all'avvio"""
    print("\n" + "="*70)
    print("🔐 CONFIGURAZIONE API KEY")
    print("="*70)
    print("\nPer controllare gli IP su VirusTotal hai bisogno di una API key")
    print("Ottienila gratuitamente da: https://www.virustotal.com/\n")
    
    while True:
        api_key = input("Inserisci la tua API key VirusTotal (o premi INVIO per saltare): ").strip()
        
        if not api_key:
            print("⚠️  Nessuna API key fornita. Lo script funzionerà solo con la whitelist.\n")
            return None
        
        if len(api_key) < 20:
            print("❌ API key troppo corta. Riprova.\n")
            continue
        
        print(f"✓ API key salvata (primissimi caratteri: {api_key[:10]}...)\n")
        return api_key

def scrivi_log(ip: str, stato: str, dettagli: str) -> None:
    """Scrive un log su file ogni volta che un IP viene controllato"""
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] IP: {ip:<18} | STATO: {stato:<15} | DETTAGLI: {dettagli}\n"
        
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(log_entry)
    except Exception as e:
        print(f"❌ Errore nella scrittura del log: {e}")

def crea_header_log() -> None:
    """Crea l'header del file log se non esiste"""
    if not os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, 'w', encoding='utf-8') as f:
                f.write("="*100 + "\n")
                f.write("🛡️  IP MALICIOUS CHECKER - LOG FILE\n")
                f.write(f"Creato: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("="*100 + "\n\n")
            print(f"✓ Creato file log: {LOG_FILE}")
        except Exception as e:
            print(f"❌ Errore nella creazione del log: {e}")

def crea_file_template(file_path: str, contenuto: str) -> None:
    """Crea un file template se non esiste"""
    if not os.path.exists(file_path):
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(contenuto)
        print(f"✓ Creato file template: {file_path}")

def carica_whitelist(file_path: str) -> Set[str]:
    """Carica gli IP dalla whitelist"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            whitelist = {
                line.strip() for line in f 
                if line.strip() and not line.startswith('#')
            }
        print(f"✓ Caricati {len(whitelist)} IP dalla whitelist")
        return whitelist
    except FileNotFoundError:
        print(f"⚠ File whitelist non trovato: {file_path}")
        return set()
    except Exception as e:
        print(f"❌ Errore nel caricamento della whitelist: {e}")
        return set()

def carica_blacklist(file_path: str) -> Set[str]:
    """Carica gli IP dalla blacklist"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            blacklist = {
                line.strip() for line in f 
                if line.strip() and not line.startswith('#')
            }
        if blacklist:
            print(f"✓ Caricati {len(blacklist)} IP dalla blacklist")
        return blacklist
    except FileNotFoundError:
        return set()
    except Exception as e:
        print(f"❌ Errore nel caricamento della blacklist: {e}")
        return set()

def carica_ip_da_controllare(file_path: str) -> List[str]:
    """Carica gli IP da controllare"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            ips = [
                line.strip() for line in f 
                if line.strip() and not line.startswith('#')
            ]
        print(f"✓ Caricati {len(ips)} IP da controllare")
        return ips
    except FileNotFoundError:
        print(f"⚠ File IP non trovato: {file_path}")
        return []
    except Exception as e:
        print(f"❌ Errore nel caricamento degli IP: {e}")
        return []

def valida_ip(ip: str) -> bool:
    """Controlla se una stringa è un IP valido"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def filtra_ip_permettuti_e_sospetti(ips: List[str], whitelist: Set[str], blacklist: Set[str]) -> Tuple[List[str], List[str], List[str]]:
    """
    Filtra gli IP in 3 categorie:
    - IP permettiti (in whitelist)
    - IP sospetti (non in whitelist e non in blacklist)
    - IP bloccati (in blacklist)
    """
    ip_permettiti = []
    ip_sospetti = []
    ip_bloccati = []
    ip_invalidi = []
    
    for ip in ips:
        if not valida_ip(ip):
            ip_invalidi.append(ip)
            continue
        
        if ip in blacklist:
            ip_bloccati.append(ip)
        elif ip in whitelist:
            ip_permettiti.append(ip)
        else:
            ip_sospetti.append(ip)
    
    if ip_invalidi:
        print(f"⚠️  {len(ip_invalidi)} IP non validi ignorati: {', '.join(ip_invalidi[:5])}")
    
    print(f"\n📋 RISULTATI FILTRO WHITELIST/BLACKLIST:")
    print(f"  ✅ Permettiti (whitelist): {len(ip_permettiti)}")
    print(f"  ❌ Bloccati (blacklist): {len(ip_bloccati)}")
    print(f"  ❓ Sospetti (da verificare): {len(ip_sospetti)}")
    
    return ip_permettiti, ip_sospetti, ip_bloccati

def controlla_su_virustotal(ip: str, api_key: str) -> Optional[Dict]:
    """
    Controlla un IP su VirusTotal usando urllib (senza requests)
    Restituisce un dizionario con le statistiche o None se errore
    """
    if not api_key:
        return None
    
    import urllib.request
    import urllib.error
    import json
    
    headers = {"x-apikey": api_key}
    url = f"{VIRUSTOTAL_URL}{ip}"
    
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as response:
            if response.status == 200:
                data = json.loads(response.read().decode('utf-8'))
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                return stats
            else:
                return None
    except urllib.error.HTTPError as e:
        if e.code == 429:
            print(f"⚠ Rate limit raggiunto. Pausa...")
        elif e.code == 401:
            print(f"❌ Errore: API key non valida")
        return None
    except urllib.error.URLError as e:
        print(f"⚠ Errore di connessione per {ip}: {e.reason}")
        return None
    except Exception as e:
        print(f"❌ Errore durante il controllo di {ip}: {e}")
        return None

def aggiungi_a_blacklist(ip: str, file_path: str, motivo: str) -> None:
    """Aggiunge un IP alla blacklist"""
    try:
        with open(file_path, 'a', encoding='utf-8') as f:
            f.write(f"{ip}  # Bloccato: {motivo}\n")
        print(f"  🚫 Aggiunto a blacklist: {ip}")
    except Exception as e:
        print(f"  ❌ Errore nell'aggiunta a blacklist: {e}")

def stampa_report_dettagliato(ips_da_controllare: List[str], whitelist: Set[str], ip_report: Dict) -> None:
    """Stampa un report dettagliato di tutti gli IP controllati"""
    print("\n" + "="*80)
    print("📊 REPORT DETTAGLIATO DI TUTTI GLI IP CONTROLLATI")
    print("="*80)
    
    print(f"\n{'N°':<4} {'IP':<18} {'STATO':<30} {'DETTAGLI':<25}")
    print("-" * 80)
    
    for idx, ip in enumerate(ips_da_controllare, 1):
        if ip in ip_report:
            info = ip_report[ip]
            stato = info['stato']
            dettagli = info['dettagli']
            
            # Colore e emoji basati su stato
            if stato == "WHITELIST":
                simbolo = "✅"
            elif stato == "BLOCCATO":
                simbolo = "🚫"
            elif stato == "CONSENTITO":
                simbolo = "✓"
            else:
                simbolo = "❓"
            
            print(f"{idx:<4} {ip:<18} {simbolo} {stato:<27} {dettagli:<25}")
    
    print("-" * 80)
    
    # Statistiche
    whitelist_count = sum(1 for info in ip_report.values() if info['stato'] == "WHITELIST")
    bloccati_count = sum(1 for info in ip_report.values() if info['stato'] == "BLOCCATO")
    consentiti_count = sum(1 for info in ip_report.values() if info['stato'] == "CONSENTITO")
    sospetti_count = sum(1 for info in ip_report.values() if info['stato'] == "SOSPETTO")
    
    print(f"\n📈 STATISTICHE:")
    print(f"  ✅ In whitelist: {whitelist_count}")
    print(f"  🚫 Bloccati (malevoli): {bloccati_count}")
    print(f"  ✓ Consentiti (verificati sicuri): {consentiti_count}")
    print(f"  ❓ Sospetti (non verificati): {sospetti_count}")
    print(f"  📊 Totale controllati: {len(ips_da_controllare)}")
    print("\n" + "="*80)

def main():
    print("="*80)
    print("🛡️  IP MALICIOUS CHECKER - WHITELIST/BLACKLIST MANAGER")
    print("="*80)
    
    # Crea header log
    crea_header_log()
    
    # Template per i file di configurazione
    whitelist_template = """# Whitelist IP - indirizzi fidati
192.168.1.1
10.0.0.1
8.8.8.8
1.1.1.1
"""
    
    ips_template = """# IP da controllare
192.168.1.1
8.8.8.8
45.142.120.10
185.220.101.50
104.21.32.100
"""
    
    blacklist_template = """# Blacklist IP - indirizzi bloccati
# Aggiunto automaticamente quando rilevato malevolo
"""
    
    # Crea i file se non esistono
    crea_file_template("whitelist.txt", whitelist_template)
    crea_file_template("ips_to_check.txt", ips_template)
    crea_file_template("blacklist.txt", blacklist_template)
    
    # Chiedi API key all'utente
    api_key = chiedi_api_key()
    
    # 1. Carica whitelist e blacklist
    print("\n📂 CARICAMENTO FILE...")
    whitelist = carica_whitelist("whitelist.txt")
    blacklist = carica_blacklist("blacklist.txt")
    
    # 2. Carica gli IP da controllare
    ips_da_controllare = carica_ip_da_controllare("ips_to_check.txt")
    
    if not ips_da_controllare:
        print("\n⚠ Nessun IP da controllare!")
        return
    
    # 3. Filtra IP permettiti, sospetti e bloccati
    ip_permettiti, ip_sospetti, ip_bloccati = filtra_ip_permettuti_e_sospetti(
        ips_da_controllare, whitelist, blacklist
    )
    
    # Dictionary per il report finale
    ip_report = {}
    
    # Aggiungi IP della whitelist al report
    for ip in ip_permettiti:
        ip_report[ip] = {
            'stato': 'WHITELIST',
            'dettagli': 'In lista fidata'
        }
        scrivi_log(ip, "WHITELIST", "IP in lista fidata - CONSENTITO")
    
    # Aggiungi IP bloccati al report
    for ip in ip_bloccati:
        ip_report[ip] = {
            'stato': 'BLOCCATO',
            'dettagli': 'In blacklist'
        }
        scrivi_log(ip, "BLOCCATO", "IP in blacklist - NEGATO")
    
    # 4. Se non hai API key, non puoi controllare su VirusTotal
    if ip_sospetti:
        if not api_key:
            print(f"\n⚠️  {len(ip_sospetti)} IP sospetti trovati, ma API key non configurata")
            print("   Per verificarli su VirusTotal, riavvia lo script e fornisci una API key")
            for ip in ip_sospetti:
                ip_report[ip] = {
                    'stato': 'SOSPETTO',
                    'dettagli': 'Non verificato'
                }
                scrivi_log(ip, "SOSPETTO", "Non verificato (API key non fornita)")
        else:
            print(f"\n🔍 Controllo {len(ip_sospetti)} IP sospetti su VirusTotal...")
            
            for i, ip in enumerate(ip_sospetti, 1):
                print(f"\n[{i}/{len(ip_sospetti)}] Verifica {ip}...")
                stats = controlla_su_virustotal(ip, api_key)
                
                if stats:
                    malicious = stats.get('malicious', 0)
                    suspicious = stats.get('suspicious', 0)
                    total_detections = malicious + suspicious
                    
                    if total_detections >= MALICIOUS_THRESHOLD:
                        print(f"  ⚠️  MALEVOLO! Rilevamenti: {malicious} malevoli + {suspicious} sospetti")
                        ip_report[ip] = {
                            'stato': 'BLOCCATO',
                            'dettagli': f'{malicious} malevoli rilevati'
                        }
                        scrivi_log(ip, "BLOCCATO", f"Malevolo detected - {malicious} rilevamenti su VirusTotal - NEGATO")
                        aggiungi_a_blacklist(ip, "blacklist.txt", f"{malicious} rilevamenti malevoli")
                    else:
                        print(f"  ✓ Apparentemente sicuro (Rilevamenti: {total_detections})")
                        ip_report[ip] = {
                            'stato': 'CONSENTITO',
                            'dettagli': f'{total_detections} rilevamenti'
                        }
                        scrivi_log(ip, "CONSENTITO", f"Verificato sicuro su VirusTotal ({total_detections} rilevamenti) - CONSENTITO")
                else:
                    print(f"  ⚠️  Impossibile verificare")
                    ip_report[ip] = {
                        'stato': 'SOSPETTO',
                        'dettagli': 'Verifica fallita'
                    }
                    scrivi_log(ip, "SOSPETTO", "Verifica fallita su VirusTotal")
                
                # Rate limiting
                if i < len(ip_sospetti):
                    time.sleep(RATE_LIMIT_DELAY)
    
    # 5. Stampa report dettagliato
    stampa_report_dettagliato(ips_da_controllare, whitelist, ip_report)
    
    # 6. Salva sommario nel log
    scrivi_log("", "SUMMARY", f"--- CONTROLLO COMPLETATO: {len(ip_report)} IP controllati ---")
    print(f"\n📝 Log salvato in: {LOG_FILE}")
    print("\n✓ Controllo completato!")

if __name__ == "__main__":
    main()
