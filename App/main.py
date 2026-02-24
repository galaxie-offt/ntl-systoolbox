#!/usr/bin/env python3

"""
Launcher NTL-SysToolbox

- Module1.py : Diagnostic AD/DNS + MySQL + OS serveurs
- Module2.py : Module 2 (sauvegarde WMS, etc.)
- Module3.py : Audit d'obsolescence reseau (EOL)
"""

import sys
import subprocess
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

MODULE1_PATH = os.path.join(BASE_DIR, "Module1.py")
MODULE2_PATH = os.path.join(BASE_DIR, "Module2.py")
MODULE3_PATH = os.path.join(BASE_DIR, "Module3.py")

def lancer_module(path, nom):
    if not os.path.exists(path):
        print(f"{nom} introuvable ({path})")
        return
    try:
        subprocess.run([sys.executable, path], check=False)
    except Exception as e:
        print(f"Erreur lors de l'execution de {nom} : {e}")

def afficher_menu():
    print("\nNTL-SysToolbox - Menu principal")
    print("1 - Module 1 : Diagnostic AD/DNS + MySQL + OS serveurs")
    print("2 - Module 2 : Sauvegarde de la base WMS")
    print("3 - Module 3 : Audit d'obsolescence reseau (EOL)")
    print("0 - Quitter")

def main():
    while True:
        afficher_menu()
        choix = input("Votre choix : ").strip()

        if choix == "1":
            lancer_module(MODULE1_PATH, "Module1.py")
        elif choix == "2":
            lancer_module(MODULE2_PATH, "Module2.py")
        elif choix == "3":
            lancer_module(MODULE3_PATH, "Module3.py")
        elif choix == "0":
            print("Fin de NTL-SysToolbox.")
            break
        else:
            print("Choix invalide, merci de recommencer.")
            input("\nAppuyez sur Entree pour revenir au menu...")

if __name__ == "__main__":
    main()
