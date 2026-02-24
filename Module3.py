#!/usr/bin/env python3
"""
Module d'audit d'obsolescence réseau
Permet de scanner un réseau, détecter les OS et vérifier leur statut EOL
"""

import sys
import subprocess
import importlib.util
import json
import re
import platform
import csv
import requests
from datetime import datetime
from typing import Dict, List, Optional
import os
import xml.etree.ElementTree as ET

# Fichier local pour les données EOL
EOL_DATA_FILE = "eol_data_local.json"

# ============================================================================
# AUTO-INSTALLATION DES DÉPENDANCES
# ============================================================================

def check_and_install_packages():
    """
    Vérifie et installe automatiquement les packages Python nécessaires.
    """
    required_packages = {
        'requests': 'requests'
    }

    missing_packages = []

    for package_name, pip_name in required_packages.items():
        spec = importlib.util.find_spec(package_name)
        if spec is None:
            missing_packages.append(pip_name)

    if missing_packages:
        print("Installation des dépendances manquantes...")
        print(f"   Packages à installer: {', '.join(missing_packages)}")

        try:
            print("\nMise à jour de pip...")
            subprocess.check_call([
                sys.executable, '-m', 'pip', 'install', '--upgrade', 'pip', '--quiet'
            ])

            print(f"Installation de {', '.join(missing_packages)}...")
            subprocess.check_call([
                sys.executable, '-m', 'pip', 'install', *missing_packages, '--quiet'
            ])

            print("Toutes les dépendances sont installées\n")
        except subprocess.CalledProcessError as e:
            print(f"\nErreur lors de l'installation des packages: {e}")
            print("Veuillez installer manuellement avec:")
            print(f"   pip install {' '.join(missing_packages)}")
            sys.exit(1)
    else:
        print("Toutes les dépendances Python sont déjà installées\n")

check_and_install_packages()

# ============================================================================
# VÉRIFICATION DE NMAP
# ============================================================================

def check_nmap():
    try:
        subprocess.run(['nmap', '--version'], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("AVERTISSEMENT: nmap n'est pas installé")
        print("\nInstructions d'installation:")
        if platform.system() == 'Linux':
            print("   Ubuntu/Debian: sudo apt install nmap")
            print("   CentOS/RHEL:   sudo yum install nmap")
            print("   Fedora:        sudo dnf install nmap")
        elif platform.system() == 'Windows':
            print("   Windows: Téléchargez depuis https://nmap.org/download.html")
            print("           Ou avec Chocolatey: choco install nmap")
        else:
            print("   macOS: brew install nmap")
        return False

# ============================================================================
# FONCTIONS GESTION FICHIER LOCAL EOL + API (AMÉLIORÉES)
# ============================================================================

def load_local_eol_data() -> Dict[str, List[Dict]]:
    """Charge les données EOL depuis le fichier local."""
    if not os.path.exists(EOL_DATA_FILE):
        return {}
    
    try:
        with open(EOL_DATA_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
            print(f"Fichier local chargé: {len(data)} OS disponibles")
            return data
    except Exception as e:
        print(f"Erreur lecture fichier local: {e}")
        return {}

def save_local_eol_data(data: Dict[str, List[Dict]]) -> bool:
    """Sauvegarde les données EOL dans le fichier local."""
    try:
        with open(EOL_DATA_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print(f"Données sauvegardées dans {EOL_DATA_FILE}")
        return True
    except Exception as e:
        print(f"Erreur sauvegarde fichier local: {e}")
        return False

def get_eol_data_api(os_name: str) -> Optional[List[Dict]]:
    """Récupère les données EOL depuis l'API."""
    try:
        response = requests.get(f"https://endoflife.date/api/{os_name}.json", timeout=10)
        if response.status_code == 200:
            return response.json()
        return None
    except Exception as e:
        print(f"Erreur API pour {os_name}: {e}")
        return None

def ensure_eol_data_local(os_name: str) -> bool:
    """Vérifie et télécharge si nécessaire les données EOL localement."""
    local_data = load_local_eol_data()
    
    # Si pas dans local et connexion possible, télécharger
    if os_name.lower() not in local_data:
        print(f"   {os_name} manquant localement - téléchargement...")
        data = get_eol_data_api(os_name.lower())
        if data:
            local_data[os_name.lower()] = data
            save_local_eol_data(local_data)
            return True
        else:
            print(f"   Impossible de télécharger {os_name}")
            return False
    return True

def get_eol_data(source: str, os_name: str) -> Optional[List[Dict]]:
    """
    Récupère les données EOL selon la source choisie.
    
    Args:
        source: 'local' ou 'api'
        os_name: Nom de l'OS
    """
    os_key = os_name.lower()
    
    if source == 'api':
        print(f"   Récupération {os_name} via API...")
        return get_eol_data_api(os_key)
    else:  # local
        # AUTO-MISE À JOUR si manquant
        if ensure_eol_data_local(os_key):
            local_data = load_local_eol_data()
            data = local_data.get(os_key, None)
            if data:
                print(f"   Lecture {os_name} depuis fichier local")
                return data
        print(f"   {os_name} non trouvé dans fichier local")
        return None

def update_eol_data_from_api():
    """Met à jour le fichier local depuis l'API."""
    print("\nMise à jour des données EOL depuis l'API endoflife.date...")
    
    popular_os = [
        'ubuntu', 'debian', 'windows-server', 'windows', 'centos', 'rhel', 'fedora',
        'alpine', 'rocky-linux', 'almalinux', 'oracle-linux',
        'freebsd', 'opensuse', 'sles', 'amazon-linux'
    ]
    
    local_data = {}
    
    for os_name in popular_os:
        print(f"   Récupération {os_name}...")
        data = get_eol_data_api(os_name)
        if data:
            local_data[os_name] = data
            print(f"     {len(data)} versions")
        else:
            print(f"     Non disponible")
    
    if save_local_eol_data(local_data):
        print(f"\nMise à jour terminée: {len(local_data)} OS")

# ============================================================================
# FONCTIONS EOL UNIQUES (source paramétrable)
# ============================================================================

def check_eol_status(eol_date: str) -> str:
    """Détermine le statut support/EOL."""
    if eol_date in ('N/A', None) or eol_date is False or eol_date is True:
        return "Inconnu"

    try:
        eol = datetime.strptime(str(eol_date), '%Y-%m-%d')
        today = datetime.now()
        days_diff = (eol - today).days

        if days_diff < 0:
            return "EOL dépassé"
        elif days_diff < 90:
            return f"EOL dans {days_diff} jours"
        elif days_diff < 365:
            return f"EOL dans {days_diff} jours"
        else:
            return "Supporté"
    except Exception:
        return "Format invalide"

def get_os_versions(source: str, os_name: str):
    """
    Affiche les versions d'un OS selon la source.
    
    Args:
        source: 'local' ou 'api'
        os_name: Nom de l'OS
    """
    print(f"\nVersions pour '{os_name}' ({source.upper()}):")
    
    data = get_eol_data(source, os_name)
    
    if not data:
        print(f"Aucune donnée trouvée pour '{os_name}' ({source})")
        if source == 'local':
            print("Mettez à jour via option 2→1")
        return
    
    print(f"\n{'Version':<15} {'Support':<12} {'EOL Date':<15} {'Statut'}")
    print("-" * 65)
    
    for version in data:
        cycle = version.get('cycle', 'N/A')
        eol_date = version.get('eol', 'N/A')
        support_date = version.get('support', 'N/A')
        
        status = check_eol_status(eol_date)
        
        print(f"{cycle:<15} {support_date:<12} {eol_date:<15} {status}")

# ============================================================================
# FONCTIONS DE SCAN RÉSEAU
# ============================================================================

def scan_network(network_range: str) -> List[Dict]:
    print(f"\nScan du réseau {network_range} en cours...")
    print("Ce scan peut prendre plusieurs minutes selon la taille du réseau...")

    xml_output_file = "nmap_scan.xml"

    cmd = [
        'nmap',
        '-O',
        '-sV',
        '-Pn',
        '--osscan-guess',
        '--script', 'ssl-cert',
        '-T4',
        '-oX', xml_output_file,
        network_range
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=6000)

        if result.returncode != 0:
            print("Erreur lors de l'exécution de nmap.")
            return []

        hosts = parse_nmap_xml(xml_output_file)
        print(f"Scan terminé: {len(hosts)} hôte(s) détecté(s)")
        return hosts

    except subprocess.TimeoutExpired:
        print("Timeout du scan.")
        return []
    except Exception as e:
        print(f"Erreur scan: {e}")
        return []

def parse_nmap_xml(xml_file: str) -> List[Dict]:
    hosts = []

    if not os.path.exists(xml_file):
        return hosts

    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()

        ns = ''
        if root.tag.startswith('{'):
            ns = root.tag.split('}')[0].strip('{')
        nsmap = {'nmap': ns} if ns else {}

        for host in root.findall('nmap:host', nsmap) if ns else root.findall('host'):
            host_data = {
                'ip': 'Unknown',
                'os': 'Unknown',
                'os_accuracy': '',
                'os_nmap_raw': '',
                'os_banner_hint': '',
                'services': [],
                'ssl_cert': []
            }

            addr_tag = host.find('nmap:address[@addrtype="ipv4"]', nsmap) if ns \
                else host.find('address[@addrtype="ipv4"]')
            if addr_tag is not None:
                host_data['ip'] = addr_tag.get('addr', 'Unknown')

            os_tag = host.find('nmap:os', nsmap) if ns else host.find('os')
            best_os = None
            best_accuracy = ''
            if os_tag is not None:
                osmatch = os_tag.find('nmap:osmatch', nsmap) if ns else os_tag.find('osmatch')
                if osmatch is not None:
                    best_os = osmatch.get('name', '')
                    best_accuracy = osmatch.get('accuracy', '')
                else:
                    osclass = os_tag.find('nmap:osclass', nsmap) if ns else os_tag.find('osclass')
                    if osclass is not None:
                        vendor = osclass.get('vendor') or ''
                        osfamily = osclass.get('osfamily') or ''
                        osgen = osclass.get('osgen') or ''
                        best_os = " ".join(x for x in [vendor, osfamily, osgen] if x)

            if best_os:
                host_data['os'] = best_os
                host_data['os_nmap_raw'] = best_os
            if best_accuracy:
                host_data['os_accuracy'] = best_accuracy

            ports_tag = host.find('nmap:ports', nsmap) if ns else host.find('ports')
            if ports_tag is not None:
                for port in ports_tag.findall('nmap:port', nsmap) if ns else ports_tag.findall('port'):
                    port_data = parse_port(port, ns, nsmap)
                    host_data['services'].append(port_data)
                    
                    banner_str = " ".join([
                        port_data['service'], port_data['product'], 
                        port_data['version'], port_data['extrainfo']
                    ]).lower()
                    
                    if 'ubuntu' in banner_str:
                        host_data['os_banner_hint'] = "Ubuntu Linux"
                    elif 'debian' in banner_str:
                        host_data['os_banner_hint'] = "Debian Linux"

            if host_data['os_banner_hint'] and (host_data['os'].lower().startswith('linux') or host_data['os'] == 'Unknown'):
                if host_data['os_nmap_raw']:
                    host_data['os'] = f"{host_data['os_banner_hint']} (nmap: {host_data['os_nmap_raw']})"
                else:
                    host_data['os'] = host_data['os_banner_hint']

            hosts.append(host_data)

    except Exception as e:
        print(f"Erreur parsing XML: {e}")

    return hosts

def parse_port(port, ns: str, nsmap: Dict):
    """Parse un port nmap."""
    port_id = port.get('portid', '')
    protocol = port.get('protocol', '')
    state_tag = port.find('nmap:state', nsmap) if ns else port.find('state')
    state = state_tag.get('state', '') if state_tag else ''
    service_tag = port.find('nmap:service', nsmap) if ns else port.find('service')

    service_name = service_tag.get('name', '') if service_tag else ''
    product = service_tag.get('product', '') if service_tag else ''
    version = service_tag.get('version', '') if service_tag else ''
    extrainfo = service_tag.get('extrainfo', '') if service_tag else ''

    port_data = {
        'port': port_id, 'protocol': protocol, 'state': state,
        'service': service_name, 'product': product,
        'version': version, 'extrainfo': extrainfo
    }

    # SSL cert
    scripts = port.findall('nmap:script', nsmap) if ns else port.findall('script')
    for script in scripts:
        if script.get('id') == 'ssl-cert':
            ssl_info = {'port': port_id, 'protocol': protocol}
            for table in script.findall('nmap:table', nsmap) if ns else script.findall('table'):
                for elem in table.findall('nmap:elem', nsmap) if ns else table.findall('elem'):
                    key = elem.get('key', '').lower()
                    value = (elem.text or '').strip()
                    if key and value:
                        ssl_info[key] = value
            port_data['ssl_cert'] = ssl_info

    return port_data

# ============================================================================
# SOUS-MENU VERSIONS OS
# ============================================================================

def get_os_versions_menu():
    """Sous-menu pour versions OS avec choix source."""
    while True:
        print("\n" + "=" * 50)
        print("VERSIONS OS EOL")
        print("=" * 50)
        print("1. Mettre à jour fichier local (API)")
        print("2. Local (fichier local - offline)")
        print("3. API directe (Internet)")
        print("0. Retour")
        print("-" * 50)
        
        choice = input("Choisissez (0-3): ").strip()
        
        if choice == '1':
            update_eol_data_from_api()
        elif choice == '2':
            os_name = input("\nOS (ex: ubuntu): ").strip()
            if os_name:
                get_os_versions('local', os_name)
        elif choice == '3':
            os_name = input("\nOS (ex: ubuntu): ").strip()
            if os_name:
                get_os_versions('api', os_name)
        elif choice == '0':
            break
        else:
            print("Option invalide")
        
        input("\nAppuyez sur Entrée...")

# ============================================================================
# MAPPINGS OS ET EXTRACTION VERSION (AMÉLIORÉS)
# ============================================================================

OS_MAPPING = {
    'microsoft windows server': 'windows-server',
    'windows server': 'windows-server',
    'microsoft windows': 'windows',
    'windows 10': 'windows',
    'windows 11': 'windows',
    'ubuntu': 'ubuntu',
    'debian': 'debian',
    'centos': 'centos',
    'red hat': 'rhel',
    'fedora': 'fedora',
    'freebsd': 'freebsd',
}

def extract_version_from_os(full_os: str) -> str:
    """Extrait la version Windows (1809, 21H2, etc.) ou Linux du nom d'OS."""
    full_os_lower = full_os.lower()
    
    # Patterns spécifiques Windows (priorité haute)
    windows_patterns = [
        r'\b(22h2|21h2|20h2|2004|1909|1903|1809|1803|1709|1703|1607|1511|1507)\b',  # Versions semi-annuelles
        r'\b(10\s*\d{4})\b',  # 10 2004
    ]
    for pattern in windows_patterns:
        match = re.search(pattern, full_os_lower)
        if match:
            version = match.group(1).replace(' ', '')  # Nettoie "10 1809" -> "101809" ou garde "1809"
            if version.startswith('10'):
                version = version[2:]  # "101809" -> "1809"
            return version.upper()
    
    # Fallback général (années, x.y)
    patterns = [
        r'\b(20\d{2}|19\d{2})\b',
        r'\b(\d+\.\d+)\b',
        r'\bv(\d+\.\d+)\b',
    ]
    for pattern in patterns:
        match = re.search(pattern, full_os_lower)
        if match:
            return match.group(1)
    return 'N/A'


def get_mapped_os_name(full_os: str) -> str:
    """Mappe le nom OS complet vers le nom API endoflife.date."""
    full_os_lower = full_os.lower()
    for long_name, short_name in OS_MAPPING.items():
        if long_name in full_os_lower:
            return short_name
    # Fallback amélioré
    words = full_os_lower.split()
    if words:
        first_word = words[0].replace('-', '')
        if first_word in ['linux', 'unknown', 'crestron']:
            return 'unknown'  # Skip les génériques
        return first_word
    return 'unknown'

# ============================================================================
# EXPORT CSV PROPRE ET OPTIMISÉ
# ============================================================================

def save_scan_results_clean(hosts: List[Dict], filename: str):
    """Sauvegarde les résultats de scan dans un CSV propre et lisible."""
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            fieldnames = ['ip', 'os', 'os_accuracy', 'open_ports']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for host in hosts:
                # Compter les ports ouverts et lister les principaux services
                services = host.get('services', [])
                open_ports = []
                for service in services:
                    if service['state'] == 'open':
                        port_info = f"{service['port']}/{service['protocol']}:{service['service']}"
                        if service['product']:
                            port_info += f"({service['product']})"
                        open_ports.append(port_info)
                
                open_ports_str = '; '.join(open_ports[:5])  # Limiter à 5 ports pour lisibilité
                if len(open_ports) > 5:
                    open_ports_str += f"; ... et {len(open_ports)-5} autres"
                
                writer.writerow({
                    'ip': host['ip'],
                    'os': host['os'][:100],  # Limiter longueur
                    'os_accuracy': host.get('os_accuracy', ''),
                    'open_ports': open_ports_str
                })
        
        print(f"CSV propre sauvé: {filename}")
        print(f"Format colonnes: IP | OS | Précision | Ports ouverts")
        
        # Aperçu
        print(f"\nAperçu {filename}:")
        with open(filename, 'r', encoding='utf-8') as f:
            for i, line in enumerate(f.readlines()[:4]):
                if i == 0:  # Header
                    print(f"   {line.strip()}")
                else:
                    print(f"   {line.strip()}")
            if len(hosts) > 3:
                print(f"   ... et {len(hosts)-3} lignes")
                
    except Exception as e:
        print(f"Erreur CSV: {e}")

# ============================================================================
# ANALYSE CSV (CORRIGÉE)
# ============================================================================

def analyze_csv_file(source: str, csv_file: str):
    """Analyse CSV avec source paramétrable et extraction intelligente."""
    if not os.path.exists(csv_file):
        print(f"Fichier {csv_file} introuvable")
        return

    print(f"\nAnalyse {csv_file} ({source.upper()})...")

    results = []

    try:
        with open(csv_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)

            for row in reader:
                ip = row.get('ip', 'N/A')
                full_os = row.get('os', 'N/A')
                
                # Skip si OS inconnu
                if 'unknown' in full_os.lower():
                    print(f"   {ip} (OS inconnu - ignoré)")
                    results.append({
                        'ip': ip, 'os': full_os, 'version': 'N/A',
                        'eol_date': 'N/A', 'status': 'OS inconnu'
                    })
                    continue
                
                csv_version = row.get('version', 'N/A')
                version = csv_version if csv_version not in ('N/A', '') else extract_version_from_os(full_os)
                
                # Mapping OS
                os_key = get_mapped_os_name(full_os)
                
                if os_key == 'unknown':
                    print(f"   {ip} ({full_os}) -> OS non mappé")
                    results.append({
                        'ip': ip, 'os': full_os, 'version': version,
                        'eol_date': 'N/A', 'status': 'Non mappé'
                    })
                    continue

                print(f"   {ip} ({full_os} v{version}) -> API: {os_key}")

                eol_info = get_eol_data(source, os_key)

                status = "Inconnu"
                eol_date = "N/A"

                if eol_info:
                    version_clean = version.lower().replace(' ', '')
                    for v in eol_info:
                        cycle_str = str(v.get('cycle', '')).lower()
                        # Matching amélioré: contient la version OU cycle commence par "10 version"
                        if (version.lower() in cycle_str or 
                            version_clean in cycle_str.replace(' ', '') or
                            f"10 {version_clean}" in cycle_str.replace(' ', '')):
                            eol_date = v.get('eol', 'N/A')
                            status = check_eol_status(eol_date)
                            break

                results.append({
                    'ip': ip, 'os': full_os, 'version': version,
                    'eol_date': eol_date, 'status': status
                })

        generate_report(results)

    except Exception as e:
        print(f"Erreur analyse: {e}")

def generate_report(data: List[Dict], output_file: str = "eol_audit_report.csv"):
    """Génère rapport CSV propre (CORRIGÉ)."""
    print(f"\nRapport: {output_file}")

    try:
        # CORRECTION: fieldnames sans 'source'
        fieldnames = ['ip', 'os', 'version', 'eol_date', 'status']
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(data)

        print(f"Rapport généré: {output_file}")

        print("\n" + "=" * 75)
        print(f"{'IP':<18} {'OS':<20} {'Version':<10} {'EOL':<12} {'Statut'}")
        print("=" * 75)

        critical_count = warning_count = 0
        for item in data:
            print(f"{item['ip']:<18} {item['os'][:19]:<20} {item['version']:<10} {item['eol_date']:<12} {item['status']}")

            if "EOL dépassé" in item['status']:
                critical_count += 1
            elif "EOL dans" in item['status']:
                warning_count += 1

        print("=" * 75)
        print(f"Résumé: {critical_count} EOL dépassé(s), {warning_count} bientôt EOL")

    except Exception as e:
        print(f"Erreur rapport: {e}")

# ============================================================================
# INTERFACE PRINCIPALE
# ============================================================================

def display_menu():
    print("\n" + "=" * 75)
    print("MODULE D'AUDIT D'OBSOLESCENCE RÉSEAU")
    print("=" * 75)
    print("\n1. Scanner réseau (nmap)")
    print("2. Versions OS (local/API - AUTO-MAJ)")
    print("3. Analyser CSV (local/API)")
    print("4. Quitter")
    print("\n" + "-" * 75)

def main():
    print("\n" + "=" * 75)
    print("MODULE D'AUDIT EOL v1.5 - AUTO-MAJ + CSV CORRIGÉ")
    print("=" * 75 + "\n")

    local_data = load_local_eol_data()
    if local_data:
        print(f"Local: {len(local_data)} OS disponibles")
    else:
        print("Local vide - utilisation option 2→1 pour mise à jour")

    nmap_ok = check_nmap()

    input("Entrée pour continuer...")

    while True:
        display_menu()
        choice = input("\nChoix (1-4): ").strip()

        if choice == '1':
            if nmap_ok:
                network = input("\nPlage (ex: 192.168.1.0/24): ").strip()
                if network:
                    hosts = scan_network(network)
                    if hosts:
                        print(f"\n{'IP':<20} {'OS':<40} {'Préc.':<8}")
                        print("-" * 70)
                        for h in hosts:
                            print(f"{h['ip']:<20} {h['os'][:39]:<40} {h.get('os_accuracy',''):<8}")

                        save = input("\nCSV? (o/n): ").lower()
                        if save == 'o':
                            filename = input("Nom (défaut: scan_results.csv): ").strip() or "scan_results.csv"
                            save_scan_results_clean(hosts, filename)

            input("\nEntrée...")

        elif choice == '2':
            get_os_versions_menu()
            input("\nEntrée...")

        elif choice == '3':
            csv_file = input("\nCSV: ").strip()
            if csv_file:
                print("\nSource EOL:")
                print("1. Local (offline - AUTO-MAJ si manquant)")
                print("2. API (Internet)")
                src_choice = input("Source (1-2): ").strip()
                source = 'local' if src_choice == '1' else 'api'
                analyze_csv_file(source, csv_file)
            input("\nEntrée...")

        elif choice == '4':
            print("\nAu revoir!")
            sys.exit(0)

        else:
            print("Option invalide (1-4)")
            input("\nEntrée...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterruption (Ctrl+C)")
        sys.exit(0)
    except Exception as e:
        print(f"Erreur: {e}")
        sys.exit(1)
