#!/usr/bin/env python3

import socket
import sys
import subprocess
import getpass

# Installation automatique de mysql-connector-python si absent
try:
    import mysql.connector
    from mysql.connector import Error
except ImportError:
    print("Module 'mysql-connector-python' manquant, installation en cours...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "mysql-connector-python"])
        import mysql.connector
        from mysql.connector import Error
        print("Module mysql-connector-python installe.\n")
    except Exception as e:
        print(f"Erreur lors de l'installation de mysql-connector-python : {e}")
        sys.exit(1)

# Parametres

# Controleurs de domaine (AD/DNS) - Windows Server
DOMAIN_CONTROLLERS = [
    {"name": "DC01", "ip": "10.5.20.94", "os": "Windows Server (AD/DNS)"},
]

# Ports a tester :
# 389 : LDAP (AD)
# 88 : Kerberos (AD)
# 53 : DNS
AD_PORTS = [389, 88]
DNS_PORTS = [53]

# Serveur MySQL WMS-DB (Ubuntu server)
MYSQL_STATIC = {
    "host": "10.5.20.113",  # IP de WMS-DB (Ubuntu)
    "port": 3306,
    "database": "wms",
}

MYSQL_SERVER_OS = "Ubuntu Server (serveur MySQL)"

# Variable globale pour éviter de redemander les identifiants à chaque fois
MYSQL_CREDENTIALS = None


def ask_mysql_credentials():
    """
    Demande a l'utilisateur l'utilisateur et le mot de passe MySQL
    (host, port, base restent fixes dans ce module).
    """
    global MYSQL_CREDENTIALS

    if MYSQL_CREDENTIALS is not None:
        return MYSQL_CREDENTIALS

    print("\nVeuillez saisir les identifiants MySQL (WMS-DB)")
    user = input("Utilisateur MySQL : ").strip()
    password = getpass.getpass("Mot de passe MySQL : ")

    MYSQL_CREDENTIALS = {
        "user": user,
        "password": password,
    }
    return MYSQL_CREDENTIALS


# Partie 1 : tests AD/DNS et MySQL

def check_tcp_port(host, port, timeout=3):
    """Retourne True si le port TCP est ouvert, False sinon."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def test_ad_dns():
    print("\nVerification AD / DNS sur les controleurs de domaine")
    for dc in DOMAIN_CONTROLLERS:
        name = dc["name"]
        ip = dc["ip"]
        print(f"\nControleur de domaine : {name} ({ip})")

        # AD : LDAP + Kerberos
        for port in AD_PORTS:
            ok_port = check_tcp_port(ip, port)
            etat = "OK" if ok_port else "KO"
            service = "LDAP" if port == 389 else "Kerberos"
            print(f" - Port AD ({service}) {port}/tcp : {etat}")

        # DNS
        for port in DNS_PORTS:
            ok_port = check_tcp_port(ip, port)
            etat = "OK" if ok_port else "KO"
            print(f" - Port DNS {port}/tcp : {etat}")


def test_mysql():
    print("\nVerification de la base MySQL (WMS-DB)")

    creds = ask_mysql_credentials()
    host = MYSQL_STATIC["host"]
    port = MYSQL_STATIC["port"]
    database = MYSQL_STATIC["database"]

    print(f"Connexion a MySQL sur {host}:{port} ...")

    try:
        conn = mysql.connector.connect(
            host=host,
            port=port,
            user=creds["user"],
            password=creds["password"],
            database=database
        )

        if conn.is_connected():
            print(" - Connexion MySQL : OK")
            cursor = conn.cursor()
            cursor.execute("SELECT 1;")
            result = cursor.fetchone()
            if result and result[0] == 1:
                print(" - Requete de test (SELECT 1) : OK")
            else:
                print(" - Requete de test (SELECT 1) : KO (resultat inattendu)")
            cursor.close()
        else:
            print(" - Connexion MySQL : KO (non connectee)")
    except Error as e:
        print(f" - Erreur MySQL : KO ({e})")
    finally:
        if 'conn' in locals() and conn.is_connected():
            conn.close()


# Partie 2 : diagnostic des OS des serveurs

def get_mysql_version():
    """Retourne la version du serveur MySQL ou 'Inconnue'."""
    creds = ask_mysql_credentials()
    host = MYSQL_STATIC["host"]
    port = MYSQL_STATIC["port"]
    database = MYSQL_STATIC["database"]

    try:
        conn = mysql.connector.connect(
            host=host,
            port=port,
            user=creds["user"],
            password=creds["password"],
            database=database
        )

        if conn.is_connected():
            cursor = conn.cursor()
            cursor.execute("SELECT VERSION();")
            row = cursor.fetchone()
            cursor.close()
            conn.close()
            if row and row[0]:
                return str(row[0])
    except Exception:
        pass

    return "Inconnue"


def diagnostic_os_serveurs():
    """
    Partie 2 : informations d'OS pour :
    - les serveurs AD/DNS (Windows Server)
    - le serveur WMS-DB (Ubuntu) et la version MySQL
    """
    print("\nDiagnostic des OS des serveurs AD/DNS et MySQL")

    # Controleurs de domaine
    print("\nServeurs AD/DNS")
    for dc in DOMAIN_CONTROLLERS:
        name = dc.get("name", "Inconnu")
        ip = dc.get("ip", "Inconnue")
        os_info = dc.get("os", "OS non precise")
        print(f" - {name} ({ip}) : {os_info}")

    # Serveur MySQL
    print("\nServeur MySQL WMS-DB")
    host = MYSQL_STATIC["host"]
    print(f" - Hote : {host}")
    print(f" - Systeme d'exploitation : {MYSQL_SERVER_OS}")
    version_mysql = get_mysql_version()
    print(f" - Version du serveur MySQL : {version_mysql}")


# Menu principal

def afficher_menu():
    print("\nMODULE 1 - Diagnostic NTL")
    print("1 - Verifier l'etat des services AD/DNS")
    print("2 - Tester la base MySQL WMS-DB")
    print("3 - Afficher les informations d'OS des serveurs AD/DNS et MySQL")
    print("0 - Quitter")


def main():
    while True:
        afficher_menu()
        choix = input("Votre choix : ").strip()

        if choix == "1":
            test_ad_dns()
            input("\nAppuyez sur Entree pour revenir au menu...")
        elif choix == "2":
            test_mysql()
            input("\nAppuyez sur Entree pour revenir au menu...")
        elif choix == "3":
            diagnostic_os_serveurs()
            input("\nAppuyez sur Entree pour revenir au menu...")
        elif choix == "0":
            print("Fin du module 1.")
            break
        else:
            print("Choix invalide, merci de recommencer.")
            input("\nAppuyez sur Entree pour revenir au menu...")


if __name__ == "__main__":
    main()
