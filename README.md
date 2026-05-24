# Scanner de ports open source

## Prérequis

- Python 3.x installé
- Nmap installé et accessible dans le PATH

## Installation de Nmap

- **Windows** : [Télécharger Nmap](https://nmap.org/download.html) (cochez “Add Nmap to PATH” à l’installation)
- **Linux** : `sudo apt install nmap` (Debian/Ubuntu) ou `sudo dnf install nmap` (Fedora)
- **Mac** : `brew install nmap`


## Utilisation

**Important :** Pour un fonctionnement optimal (surtout la gestion automatique des ports), lancez le script en mode administrateur (clic droit > "Exécuter en tant qu'administrateur" sous Windows, ou avec `sudo` sous Linux).

```bash
python scan-ports.py
## Nouveautés

- **Score de sécurité** : À la fin du scan, un score sur 100 évalue la sécurité de votre réseau selon les ports ouverts.
- **Conseils personnalisés** : Des recommandations sont affichées selon les risques détectés.
- **Gestion des ports** : Un menu interactif permet de fermer ou ouvrir des ports automatiquement (nécessite les droits administrateur/sudo).
- **Détection des services sur ports non-standards** : Le scanner identifie les services s'exécutant sur des ports inhabituels (ex : HTTP sur 8080 au lieu de 80) pour repérer les configurations suspectes.
- **Export dual format** : Exportez le rapport en fichier texte (`.txt`) ou Markdown (`.md`) selon vos besoins.

## Export du rapport

Après chaque scan, vous pouvez exporter le rapport dans deux formats :

### Format Texte (.txt)
Rapport simple et lisible, parfait pour :
-  Archivage
-  Envoi par email
-  Impression

**Contenu:**
```
============================================================
RAPPORT DE SCAN DE SÉCURITÉ RÉSEAU
============================================================

Date du scan : 2026-05-24 14:32:45
Adresse IP scannée : 8.8.8.8

PORTS OUVERTS DÉTECTÉS
  53/tcp : domain
  443/tcp : https

SCORE DE SÉCURITÉ : 80/100
```

### Format Markdown (.md)
Rapport formaté avec tableaux  idéal pour :
-  GitHub/GitLab
-  Documentation web
-  Édition dans VS Code
- Rendu HTML élégant

**Contenu:**
```markdown
# Rapport de Scan de Sécurité Réseau

**Date du scan:** 2026-05-24 14:32:45
**Adresse IP scannée:** `8.8.8.8`

##  Ports Ouverts Détectés

| Port | Service | Risque |
|------|---------|--------|
| 53/tcp | domain | faible |
| 443/tcp | https | faible |

##  Score de Sécurité

### **80/100**

 **Bien** : Votre sécurité est bonne, mais vous pouvez encore améliorer certains points.
```

### Comment exporter ?

À la fin du scan, le programme demande :
```
Voulez-vous exporter le rapport ? (oui/non) : oui
Format d'export :
1. Fichier texte (.txt)
2. Fichier Markdown (.md)
Votre choix (1 ou 2) : 
```

Les rapports sont sauvegardés dans le **même dossier** que le script avec des noms uniques :
- `rapport_scan_8.8.8.8_20260524_143245.txt`
- `rapport_scan_8.8.8.8_20260524_143250.md`


## Services analysés

Le scanner détecte et analyse notamment les ports/services suivants :

| Port   | Service      | Description rapide                                 |
|--------|--------------|---------------------------------------------------|
| 21     | ftp          | Transfert de fichiers non chiffré                 |
| 22     | ssh          | Accès distant sécurisé                            |
| 23     | telnet       | Accès distant non chiffré (dangereux)             |
| 25     | smtp         | Envoi d’e-mails                                   |
| 53     | dns/domain   | Résolution de noms                                |
| 80     | http         | Web non chiffré                                   |
| 110    | pop3         | Récupération d’e-mails non chiffrée               |
| 143    | imap         | Récupération d’e-mails non chiffrée               |
| 443    | https        | Web sécurisé                                      |
| 445    | smb          | Partage de fichiers Windows                       |
| 3389   | rdp          | Bureau à distance Windows                         |
| 3306   | mysql        | Base de données MySQL                             |
| 5432   | postgresql   | Base de données PostgreSQL                        |
| 5900   | vnc          | Bureau à distance VNC                             |
| 389    | ldap         | Annuaire réseau                                   |
| 161    | snmp         | Supervision réseau                                |


Exemple

Adresse IP à scanner : 8.8.8.8
Ports ouverts et services associés :
53/tcp : domain
443/tcp : https