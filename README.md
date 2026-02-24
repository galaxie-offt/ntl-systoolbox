# NTL-SysToolbox

Suite d’outils CLI (ligne de commande) développée en Python pour automatiser des opérations d’administration système critiques de **NordTransit Logistics**.

Projet académique réalisé dans le cadre de la **MSPR TPRE511** (B3 ASRBD – EPSI Auxerre, année 2025-2026).

---

## Sommaire

1. Présentation  
2. Fonctionnalités  
3. Architecture du projet  
4. Prérequis  
5. Installation  
6. Utilisation rapide  
7. Auteurs et contexte  

---

## 1. Présentation

**NTL-SysToolbox** regroupe trois modules principaux :

- Diagnostic des services AD/DNS et de la base MySQL WMS.  
- Sauvegarde complète et export CSV de la base WMS.  
- Audit d’obsolescence (EOL) des systèmes d’un réseau à partir d’un scan nmap.

L’objectif est de fournir des outils simples à exécuter, portables (Linux/Windows), et facilement intégrables dans un environnement d’administration système.

---

## 2. Fonctionnalités

- **Module 1 – Diagnostic AD/DNS + MySQL**  
  - Test des ports critiques AD/DNS (LDAP 389, Kerberos 88, DNS 53).  
  - Test de connexion MySQL avec requête de vérification `SELECT 1`.  
  - Affichage des informations OS des serveurs et version MySQL.

- **Module 2 – Sauvegarde WMS**  
  - Sauvegarde SQL complète de la base WMS (structure + données).  
  - Export CSV d’une table choisie (avec en-têtes, encodage UTF-8).  
  - Création automatique des répertoires `backups/`, `exports/`, `reports/`.

- **Module 3 – Audit EOL**  
  - Scan réseau via nmap (détection hôtes, services, OS).  
  - Récupération des dates de fin de support via l’API `endoflife.date` (avec cache local JSON).  
  - Génération de rapports CSV (`scan_results.csv`, `eol_audit_report.csv`) avec statut de support (supporté, bientôt EOL, EOL dépassé).

---

## 3. Architecture du projet

Arborescence principale :

```text
ntl-systoolbox/
├── main.py             # Menu principal (lance les 3 modules)
├── Module1.py          # Diagnostic AD/DNS + MySQL + OS
├── Module2.2.py        # Sauvegarde base MySQL WMS
├── Module3.py          # Audit d’obsolescence réseau (EOL)
├── backups/            # Sauvegardes SQL (Module 2)
├── exports/            # Exports CSV (Module 2)
├── reports/            # Rapports (Module 2)
├── audits/             # Rapports EOL / scans nmap (Module 3)
├── eol_data_local.json # Cache local EOL (Module 3)
├── guide-install.md    # Manuel d’installation et d’utilisation
└── doc-technique.md    # Documentation technique détaillée
```

---

## 4. Prérequis

### Systèmes supportés

- **Linux** : Debian, Ubuntu, CentOS, RHEL, Rocky Linux, etc.  
- **Windows** : Windows 10, 11, Server 2016/2019/2022.

### Logiciel

- **Python** 3.7 ou supérieur.  
- **nmap** (obligatoire uniquement pour le Module 3).  
- Accès Internet recommandé pour récupérer les données EOL (premier lancement du Module 3).

Les dépendances Python (`mysql-connector-python`, `requests`) sont installées automatiquement au lancement des modules concernés.

---

## 5. Installation

### 5.1 Clonage du dépôt

```bash
git clone https://github.com/ntl-it/ntl-systoolbox.git
cd ntl-systoolbox
```

### 5.2 Installation sur Linux (exemple Debian/Ubuntu)

```bash
# Vérifier Python
python3 --version

# Installer nmap (pour le Module 3)
sudo apt update
sudo apt install nmap -y
```

Les scripts Python installent automatiquement leurs dépendances à l’exécution (via `pip`).

### 5.3 Installation sur Windows

1. Installer Python 3.x depuis https://www.python.org (cocher « Add Python to PATH »).  
2. Installer nmap depuis https://nmap.org/download.html (optionnel, pour Module 3).  
3. Cloner ou copier le dossier `ntl-systoolbox` sur la machine.

---

## 6. Utilisation rapide

### 6.1 Lancer le menu principal

Linux :

```bash
cd ntl-systoolbox
python3 main.py
```

Windows (PowerShell ou CMD) :

```bash
cd C:
tl-systoolbox
python main.py
```

Menu attendu :

```text
NTL-SysToolbox - Menu principal
1 - Module 1 : Diagnostic AD/DNS + MySQL + OS serveurs
2 - Module 2 : Sauvegarde de la base WMS
3 - Module 3 : Audit d’obsolescence réseau (EOL)
0 - Quitter
```

### 6.2 Module 1 – Diagnostic

- Vérification des services AD/DNS.  
- Test de la base MySQL WMS (saisie des identifiants, requête `SELECT 1`).  
- Affichage des informations OS et de la version MySQL.

Exemple :

```text
Test de la base MySQL WMS
Connexion 10.5.20.113:3306...
Connexion MySQL OK
Base de données wms OK
Requête de test SELECT 1 OK
Base MySQL WMS opérationnelle
```

### 6.3 Module 2 – Sauvegarde WMS

- Demande interactive de la connexion MySQL (IP, base, utilisateur, mot de passe).  
- Création automatique des dossiers `backups/`, `exports/`, `reports/`.  

Fonctions principales :

- **Sauvegarde SQL complète**  
  - Fichier : `backups/wms_YYYY-MM-DD_HH-MM-SS.sql`.

- **Export CSV d’une table**  
  - Fichier : `exports/table_<nom>_YYYY-MM-DD_HH-MM-SS.csv`.

### 6.4 Module 3 – Audit EOL

- Scan réseau via nmap (plage d’IP à saisir, ex : `192.168.10.0/24`).  
- Mise à jour des données EOL locales depuis `endoflife.date` (mode offline ensuite possible).  
- Analyse d’un CSV de scan pour produire un rapport EOL (`eol_audit_report.csv`).

Résumé type en sortie :

```text
IP                 OS                         Version   EOL         Statut
192.168.10.10      Microsoft Windows Server   2016      2027-01-12  Supporté
192.168.10.100     Microsoft Windows 10       1809      2020-11-10  EOL dépassé
...
Résumé: 2 EOL dépassé(s), 0 bientôt EOL
```

---

## 7. Auteurs et contexte

Projet développé par **Groupe 2 – B3 ASRBD – EPSI Auxerre** dans le cadre de la **MSPR TPRE511 – Développement d’application NordTransit Logistics**, année scolaire **2025-2026**.

Pour plus de détails techniques et fonctionnels, se référer à :

- `guide-install.md` (manuel d’installation et d’utilisation).  
- `doc-technique.md` (documentation technique complète du code et de l’architecture).
