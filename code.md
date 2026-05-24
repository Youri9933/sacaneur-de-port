# Scanner de Ports - Guide d'utilisation sur Claude/Copilot

Bienvenue ! Ce guide te montre comment utiliser le **Scanner de Ports** sur Claude ou GitHub Copilot.

## Qu'est-ce que c'est ?

Un **scanner de sécurité réseau** qui :
- Scanne une adresse IP pour trouver les ports ouverts
- Détecte les services et évalue le risque
- Calcule un score de sécurité (0-100)
- Détecte les services sur ports non-standards (suspecte)
- Exporte un rapport complet en fichier `.txt`
- Permet de fermer/ouvrir des ports automatiquement

## Installation

### Prérequis
- **Python 3.x** (télécharger sur https://www.python.org)
- **Nmap** (télécharger sur https://nmap.org/download.html)

### Étapes
1. Télécharge les fichiers du projet
2. Installe Nmap et ajoute-le au PATH
3. Ouvre une terminal/PowerShell dans le dossier du projet
4. Lance : `python scan-ports.py`

## Comment ça marche ?

### 1. Demande l'IP
```
Adresse IP à scanner : 8.8.8.8
```

### 2. Détecte les ports ouverts
```
Ports ouverts et services associés :
53/tcp : domain | Risque : faible
443/tcp : https | Risque : faible
```

### 3. Alerte sur les ports non-standards
```
[!] Services détectés sur des ports non standards :
  - http sur 8080/tcp
  ⚠️  Vérifiez si ces services sont légitimes sur ces ports !
```

### 4. Calcule un score de sécurité
```
Score de sécurité : 80/100
Bien : Votre sécurité est bonne, mais vous pouvez encore améliorer certains points.
```

### 5. Donne des conseils
```
Conseils personnalisés :
- Le port 53 (domain) est généralement sûr, mais vérifiez s'il est utile.
```

### 6. Menu de gestion des ports
```
Que veux-tu faire ?
1. Fermer un port
2. Ouvrir un port
3. Quitter
```

## Niveaux de risque

| Risque | Signification |
|--------|---------------|
| **Critique** | 🔴 Fermez ce port si possible |
| **Moyen** | 🟡 Vérifiez si c'est nécessaire |
| **Faible** | 🟢 Généralement sûr |

## Ports analysés

- **21** - FTP (transfert fichiers)
- **22** - SSH (accès sécurisé)
- **23** - Telnet (accès non chiffré) ⚠️
- **25** - SMTP (e-mail)
- **53** - DNS (résolution noms)
- **80** - HTTP (web)
- **110** - POP3 (e-mail) ⚠️
- **143** - IMAP (e-mail) ⚠️
- **443** - HTTPS (web sécurisé)
- **445** - SMB (partage fichiers Windows) ⚠️
- **3389** - RDP (bureau à distance) ⚠️
- **3306** - MySQL (base données)
- **5432** - PostgreSQL (base données)
- **5900** - VNC (bureau à distance) ⚠️

## Export du rapport

À la fin du scan, le rapport est **automatiquement sauvegardé** dans un fichier `.txt` :
```
rapport_scan_8.8.8.8_20260524_143245.txt
```

Le fichier contient :
- Date et heure du scan
- IP scannée
- Liste complète des ports
- Services non-standards
- Score de sécurité
- Recommandations personnalisées

## Exemples d'utilisation

### Scanner Google DNS
```
Adresse IP à scanner : 8.8.8.8
```

### Scanner ton réseau local
```
Adresse IP à scanner : 192.168.1.1
```

### Scanner une machine spécifique
```
Adresse IP à scanner : 10.0.0.5
```

## Points importants

⚠️ **Lancer en admin/sudo** : Pour la gestion automatique des ports, lance en mode administrateur :
- Windows : Clic droit > "Exécuter en tant qu'administrateur"
- Linux : `sudo python scan-ports.py`

⚠️ **Respect de la légalité** : Ne scanne que des serveurs que tu as la permission de tester !

🛡️ **Ne ferme pas les ports critiques** : Fermer SSH (22) sans accès peut te bloquer.

## Questions fréquentes

**Q: Pourquoi le scan prend du temps ?**
A: Nmap scanne 1000 ports par défaut. C'est normal.

**Q: Je peux scanner depuis Internet ?**
A: Oui, mais les pare-feu peuvent bloquer Nmap.

**Q: Le rapport ne se crée pas ?**
A: Vérifie que tu as les droits d'écriture dans le dossier.

**Q: Comment je saurai si un port est légitime ?**
A: Demande-toi : "J'ai besoin d'accéder à ce service depuis Internet ?"
- Si NON → Ferme-le
- Si OUI → Sécurise-le au maximum

## Améliorations futures

- 📊 Export en HTML (rapport visuel)
- 📈 Historique des scans
- 🔔 Alertes email en cas de risque critique
- 🖥️ Interface graphique (GUI)
- 🗄️ Base de données CVE (failles connues)

---

**Besoin d'aide ?** Pose tes questions sur le code, les résultats, ou la sécurité ! 😊
