#!/usr/bin/env python3
"""
Script per filtrare indirizzi IP dalla whitelist e controllare quelli malevoli
"""

import ipaddress
import os
from typing import List, Set
import time

try:
    import requests
except ImportError:
    requests = None

# Configurazione
VIRUSTOTAL_API_KEY = "YOUR_API_KEY_HERE"  # Inserisci la tua chiave API di VirusTotal
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/ip_addresses/"

def crea_file_template(file_path: str, contenuto: str) -> None:
    """Crea un file template se non esiste"""
    if not os.path.exists(file_path):
        with open(file_path, 'w') as f:
            f.write(contenuto)
        print(f"✓ Creato file template: {file_path}")

def carica_whitelist(file_path: str) -> Set[str]:
    """Carica gli IP dalla whitelist"""
    try:
        with open(file_path, 'r') as f:
            whitelist = {line.strip() for line in f if line.strip() and not line.startswith('#')}
        print(f"✓ Caricati {len(whitelist)} IP dalla whitelist")
        return whitelist
    except FileNotFoundError:
        print(f"⚠ File whitelist non trovato: {file_path}")
        return set()

def carica_ip_da_controllare(file_path: str) -> List[str]:
    """Carica gli IP da controllare"""
    try:
        with open(file_path, 'r') as f:
            ips = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        print(f"✓ Caricati {len(ips)} IP da controllare")
        return ips
    except FileNotFoundError:
        print(f"⚠ File IP non trovato: {file_path}")
        return []

def valida_ip(ip: str) -> bool:
    """Controlla se una stringa è un IP valido"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def filtra_ip_non_whitelisted(ips: List[str], whitelist: Set[str]) -> List[str]:
    """Filtra gli IP che non sono nella whitelist"""
    ip_sospetti = []
    for ip in ips:
        if valida_ip(ip):
            if ip not in whitelist:
                ip_sospetti.append(ip)
    
    print(f"\n🔍 Trovati {len(ip_sospetti)} IP NON in whitelist (potenzialmente sospetti)")
    return ip_sospetti

def controlla_ip_malevolo_locale(ip: str) -> bool:
    """
    Controllo locale base per IP potenzialmente malevoli
    (puoi aggiungere logica più sofisticata qui)
    """
    # Esempio: controlla se è un IP privato (di solito non malevolo)
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private:
            return False
        # Puoi aggiungere altre logiche qui
        return True
    except:
        return False

def visualizza_ip_malevoli(ip_malevoli: List[str]):
    """Visualizza a video gli IP potenzialmente malevoli"""
    if not ip_malevoli:
        print("\n✓ Nessun IP malevolo trovato!")
        return
    
    print("\n" + "="*60)
    print("⚠️  IP POTENZIALMENTE MALEVOLI DA CONTROLLARE")
    print("="*60)
    for i, ip in enumerate(ip_malevoli, 1):
        print(f"{i}. {ip}")
    print("="*60)

def controlla_su_virustotal(ip: str, api_key: str) -> dict:
    """Controlla un IP su VirusTotal"""
    if api_key == "YOUR_API_KEY_HERE":
        print("⚠ Inserisci una chiave API valida per usare VirusTotal")
        return None
    
    headers = {
        "x-apikey": api_key
    }
    
    try:
        response = requests.get(f"{VIRUSTOTAL_URL}{ip}", headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            return stats
        else:
            print(f"⚠ Errore nella richiesta per {ip}: {response.status_code}")
            return None
    except Exception as e:
        print(f"⚠ Errore durante il controllo di {ip}: {e}")
        return None

def main():
    print("="*60)
    print("🛡️  IP MALICIOUS CHECKER")
    print("="*60)
    
    # Template per i file di configurazione
    whitelist_template = """# Whitelist di IP - Aggiungi un IP per riga
# Le righe che iniziano con # vengono ignorate
127.0.0.1
8.8.8.8
1.1.1.1
"""
    
    ips_template = """# IP da controllare - Aggiungi un IP per riga
# Le righe che iniziano con # vengono ignorate
192.168.1.1
10.0.0.1
"""
    
    # Crea i file se non esistono
    crea_file_template("whitelist.txt", whitelist_template)
    crea_file_template("ips_to_check.txt", ips_template)
    
    # 1. Carica la whitelist
    whitelist = carica_whitelist("whitelist.txt")
    
    # 2. Carica gli IP da controllare
    ips_da_controllare = carica_ip_da_controllare("ips_to_check.txt")
    
    if not ips_da_controllare:
        print("\n⚠ Nessun IP da controllare!")
        return
    
    # 3. Filtra gli IP non in whitelist
    ip_sospetti = filtra_ip_non_whitelisted(ips_da_controllare, whitelist)
    
    # 4. Controlla quali sembrano malevoli (controllo locale)
    ip_malevoli = [ip for ip in ip_sospetti if controlla_ip_malevolo_locale(ip)]
    
    # 5. Visualizza gli IP malevoli
    visualizza_ip_malevoli(ip_malevoli)
    
    # 6. Opzionale: Controlla su VirusTotal
    if ip_malevoli and VIRUSTOTAL_API_KEY != "YOUR_API_KEY_HERE":
        print("\n🔍 Controllo su VirusTotal...")
        try:
            scelta = input("\nVuoi controllare questi IP su VirusTotal? (s/n): ").lower()
            
            if scelta == 's':
                if requests is None:
                    print("⚠ Pacchetto 'requests' non installato. Installa con: pip install requests")
                    return
                
                for ip in ip_malevoli:
                    print(f"\nControllando {ip}...")
                    stats = controlla_su_virustotal(ip, VIRUSTOTAL_API_KEY)
                    if stats:
                        malicious = stats.get('malicious', 0)
                        suspicious = stats.get('suspicious', 0)
                        print(f"  → Malevoli: {malicious}, Sospetti: {suspicious}")
                    time.sleep(15)  # Rate limiting VirusTotal (free tier: 4 req/min)
        except KeyboardInterrupt:
            print("\n\n⚠ Controllo interrotto dall'utente")
    
    print("\n✓ Controllo completato!")

if __name__ == "__main__":
    main()
