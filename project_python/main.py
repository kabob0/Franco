#!/usr/bin/env python3
"""
Script per filtrare indirizzi IP dalla whitelist e controllare quelli malevoli
"""

import ipaddress
import os
import time
import json
import urllib.request
import urllib.error
from typing import Set, List, Dict, Optional
from datetime import datetime

# Configurazione
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/ip_addresses/"
RATE_LIMIT_DELAY = 15
MALICIOUS_THRESHOLD = 5
LOG_FILE = "ip_check.log"

def chiedi_api_key() -> Optional[str]:
    """Chiede API key all'utente"""
    print("\n🔐 API KEY VirusTotal (premi INVIO per saltare):")
    api_key = input(">>> ").strip()
    return api_key if len(api_key) >= 20 else None

def carica_file(file_path: str) -> Set[str]:
    """Carica IP da file"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return {line.strip() for line in f if line.strip() and not line.startswith('#')}
    except FileNotFoundError:
        print(f"❌ File non trovato: {file_path}")
        return set()

def valida_ip(ip: str) -> bool:
    """Valida IP"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def controlla_su_virustotal(ip: str, api_key: str) -> Optional[Dict]:
    """Controlla IP su VirusTotal"""
    if not api_key:
        return None
    
    headers = {"x-apikey": api_key}
    try:
        req = urllib.request.Request(f"{VIRUSTOTAL_URL}{ip}", headers=headers)
        with urllib.request.urlopen(req, timeout=10) as response:
            if response.status == 200:
                data = json.loads(response.read().decode('utf-8'))
                return data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
    except urllib.error.HTTPError as e:
        if e.code == 401:
            print("❌ API key non valida")
    except Exception:
        pass
    return None

def scrivi_log(ip: str, stato: str, dettagli: str) -> None:
    """Scrive log su file"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {ip:<18} | {stato:<15} | {dettagli}\n"
    with open(LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(log_entry)

def aggiungi_a_blacklist(ip: str, motivo: str) -> None:
    """Aggiunge IP a blacklist"""
    with open("blacklist.txt", 'a', encoding='utf-8') as f:
        f.write(f"{ip}  # {motivo}\n")

def main():
    print("="*70)
    print("🛡️  IP MALICIOUS CHECKER")
    print("="*70)
    
    # Crea header log
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'w', encoding='utf-8') as f:
            f.write(f"LOG IP CHECKER - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*70 + "\n\n")
    
    # Chiedi API key
    api_key = chiedi_api_key()
    
    # Carica file
    print("\n📂 Caricamento file...")
    whitelist = carica_file("whitelist.txt")
    blacklist = carica_file("blacklist.txt")
    ips_da_controllare = carica_file("ips_to_check.txt")
    
    if not ips_da_controllare:
        print("❌ Nessun IP da controllare!")
        return
    
    print(f"✓ Whitelist: {len(whitelist)} IP")
    print(f"✓ Blacklist: {len(blacklist)} IP")
    print(f"✓ Da controllare: {len(ips_da_controllare)} IP")
    
    # Processa IP
    print("\n" + "="*70)
    print("🔍 CONTROLLO IP")
    print("="*70)
    
    risultati = {"whitelist": [], "bloccato": [], "consentito": [], "sospetto": []}
    
    for ip in sorted(ips_da_controllare):
        if not valida_ip(ip):
            continue
        
        if ip in blacklist:
            print(f"🚫 {ip} - BLOCCATO (blacklist)")
            risultati["bloccato"].append(ip)
            scrivi_log(ip, "BLOCCATO", "In blacklist")
            continue
        
        if ip in whitelist:
            print(f"✅ {ip} - WHITELIST")
            risultati["whitelist"].append(ip)
            scrivi_log(ip, "WHITELIST", "In whitelist")
            continue
        
        # IP sospetto
        if api_key:
            print(f"🔍 {ip} - Verifica VirusTotal...", end=" ")
            stats = controlla_su_virustotal(ip, api_key)
            
            if stats:
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                total = malicious + suspicious
                
                if total >= MALICIOUS_THRESHOLD:
                    print(f"❌ MALEVOLO ({malicious} rilevamenti)")
                    risultati["bloccato"].append(ip)
                    scrivi_log(ip, "BLOCCATO", f"{malicious} rilevamenti su VirusTotal")
                    aggiungi_a_blacklist(ip, f"Malevolo - {malicious} rilevamenti")
                else:
                    print(f"✓ SICURO ({total} rilevamenti)")
                    risultati["consentito"].append(ip)
                    scrivi_log(ip, "CONSENTITO", f"{total} rilevamenti su VirusTotal")
            else:
                print("⚠ Verifica fallita")
                risultati["sospetto"].append(ip)
                scrivi_log(ip, "SOSPETTO", "Verifica fallita")
            
            time.sleep(RATE_LIMIT_DELAY)
        else:
            print(f"❓ {ip} - SOSPETTO (API key non fornita)")
            risultati["sospetto"].append(ip)
            scrivi_log(ip, "SOSPETTO", "API key non fornita")
    
    # Report finale
    print("\n" + "="*70)
    print("📊 REPORT FINALE")
    print("="*70)
    print(f"✅ Whitelist:    {len(risultati['whitelist'])}")
    print(f"✓ Consentiti:    {len(risultati['consentito'])}")
    print(f"❌ Bloccati:     {len(risultati['bloccato'])}")
    print(f"❓ Sospetti:     {len(risultati['sospetto'])}")
    print(f"📊 TOTALE:       {len(ips_da_controllare)}")
    print("="*70)
    print(f"\n📝 Log salvato: {LOG_FILE}")
    print("✓ Controllo completato!")

if __name__ == "__main__":
    main()
