import sys
import subprocess

# ==================================================
# Vérification / installation des dépendances
# ==================================================
def ensure_dependencies():
    try:
        import mysql.connector
    except ImportError:
        print("Dépendance manquante : mysql-connector-python")
        print("Installation automatique en cours...")
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "mysql-connector-python"]
        )
        print("Dépendance installée avec succès\n")

ensure_dependencies()

import mysql.connector
import datetime
import json
import os
import getpass
import csv

# ==================================================
# Configuration & utilitaires
# ==================================================
def ask_db_info():
    print("\n=== Connexion à la base WMS ===")
    return {
        "host": input("IP du serveur MariaDB : "),
        "database": input("Nom de la base : "),
        "user": input("Utilisateur : "),
        "password": getpass.getpass("Mot de passe : "),
        "backup_path": "backups",
        "export_path": "exports",
        "report_path": "reports"
    }


def ensure_directories(cfg):
    os.makedirs(cfg["backup_path"], exist_ok=True)
    os.makedirs(cfg["export_path"], exist_ok=True)
    os.makedirs(cfg["report_path"], exist_ok=True)


def connect_db(cfg):
    return mysql.connector.connect(
        host=cfg["host"],
        user=cfg["user"],
        password=cfg["password"],
        database=cfg["database"],
        connection_timeout=5
    )

# ==================================================
# Récupérer les tables
# ==================================================
def get_tables(cfg):
    conn = connect_db(cfg)
    cursor = conn.cursor()
    cursor.execute("SHOW TABLES")
    tables = [t[0] for t in cursor.fetchall()]
    conn.close()
    return tables

# ==================================================
# Sauvegarde SQL complète (backups/)
# ==================================================
def backup_database(cfg):
    ensure_directories(cfg)
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    sql_file = f"{cfg['backup_path']}/wms_{timestamp}.sql"
    report_file = f"{cfg['report_path']}/backup_{timestamp}.json"

    try:
        conn = connect_db(cfg)
        cursor = conn.cursor()

        with open(sql_file, "w", encoding="utf-8") as f:
            cursor.execute("SHOW TABLES")
            tables = cursor.fetchall()

            for (table,) in tables:
                cursor.execute(f"SHOW CREATE TABLE {table}")
                create_stmt = cursor.fetchone()[1]
                f.write(f"{create_stmt};\n\n")

                cursor.execute(f"SELECT * FROM {table}")
                rows = cursor.fetchall()
                cols = [desc[0] for desc in cursor.description]

                for row in rows:
                    values = []
                    for val in row:
                        if val is None:
                            values.append("NULL")
                        else:
                            values.append("'" + str(val).replace("'", "''") + "'")
                    f.write(
                        f"INSERT INTO {table} ({', '.join(cols)}) "
                        f"VALUES ({', '.join(values)});\n"
                    )
                f.write("\n")

        conn.close()

        report = {
            "module": "backup_wms",
            "operation": "full_backup",
            "status": "success",
            "timestamp": timestamp,
            "file": sql_file
        }

        with open(report_file, "w") as r:
            json.dump(report, r, indent=4)

        print(" Sauvegarde SQL réussie")

    except Exception as e:
        print(" ERREUR DÉTAILLÉE :", e)

# ==================================================
# Export CSV (exports/)
# ==================================================
def export_table_csv(cfg):
    tables = get_tables(cfg)

    if not tables:
        print("Aucune table trouvée")
        return

    print("\nTables disponibles :")
    for i, table in enumerate(tables, start=1):
        print(f"{i} - {table}")

    try:
        choice = int(input("Choisis le numéro de la table : "))
        table = tables[choice - 1]
    except (ValueError, IndexError):
        print("Choix invalide")
        return

    ensure_directories(cfg)
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    csv_file = f"{cfg['export_path']}/table_{table}_{timestamp}.csv"
    report_file = f"{cfg['report_path']}/export_{timestamp}.json"

    try:
        conn = connect_db(cfg)
        cursor = conn.cursor()
        cursor.execute(f"SELECT * FROM {table}")

        rows = cursor.fetchall()
        cols = [desc[0] for desc in cursor.description]

        with open(csv_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(cols)
            writer.writerows(rows)

        conn.close()

        report = {
            "module": "backup_wms",
            "operation": "table_export",
            "table": table,
            "status": "success",
            "timestamp": timestamp,
            "file": csv_file
        }

        with open(report_file, "w") as r:
            json.dump(report, r, indent=4)

        print(f" Export CSV réussi ({table})")

    except Exception as e:
        print(" ERREUR DÉTAILLÉE :", e)

# ==================================================
# Interface CLI
# ==================================================
def menu():
    print("\n=== Module Sauvegarde WMS ===")
    print("1 - Sauvegarde complète (SQL)")
    print("2 - Export d'une table (CSV)")
    print("0 - Quitter")


def main():
    cfg = ask_db_info()

    while True:
        menu()
        choice = input("Choix : ")

        if choice == "1":
            backup_database(cfg)

        elif choice == "2":
            export_table_csv(cfg)

        elif choice == "0":
            print("Fin du module sauvegarde WMS")
            break

        else:
            print("Choix invalide")


if __name__ == "__main__":
    main()
