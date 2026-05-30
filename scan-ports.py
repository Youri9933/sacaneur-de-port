import platform
import subprocess
import datetime

# Table des ports/services standards
services_standard = {
    ("21", "ftp"),
    ("22", "ssh"),
    ("23", "telnet"),
    ("25", "smtp"),
    ("53", "domain"),
    ("80", "http"),
    ("110", "pop3"),
    ("143", "imap"),
    ("443", "https"),
    ("445", "smb"),
    ("3389", "rdp"),
    ("3306", "mysql"),
    ("5432", "postgresql"),
    ("5900", "vnc"),
    ("389", "ldap"),
    ("161", "snmp"),
}

# Fonction pour extraire les ports ouverts
def extraire_ports_ouverts(nmap_output):
    ports = []
    lines = nmap_output.splitlines()
    for line in lines:
        if "/tcp" in line or "/udp" in line:
            parts = line.split()
            if len(parts) >= 3 and parts[1] == "open":
                port = parts[0]
                service = parts[2]
                ports.append((port, service))
    return ports

# Fonction pour détecter les services sur ports non standards
def detecter_services_non_standards(list_ports):
    non_standards = []
    for port, service in list_ports:
        port_num = port.split("/")[0]
        if (port_num, service) not in services_standard:
            non_standards.append((port, service))
    return non_standards

risques_services = {
    "ftp":      ("critique", "FTP (21) : Protocole non chiffré, vulnérable aux interceptions."),
    "ssh":      ("faible",   "SSH (22) : Protocole sécurisé pour l'accès distant."),
    "telnet":   ("critique", "Telnet (23) : Protocole non chiffré, très risqué."),
    "smtp":     ("moyen",    "SMTP (25) : Envoi d'e-mails, peut être utilisé pour le spam."),
    "dns":      ("faible",   "DNS (53) : Service de résolution de noms."),
    "http":     ("moyen",    "HTTP (80) : Protocole web non chiffré."),
    "pop3":     ("critique", "POP3 (110) : Récupération d'e-mails non chiffrée."),
    "imap":     ("critique", "IMAP (143) : Récupération d'e-mails non chiffrée."),
    "https":    ("faible",   "HTTPS (443) : Protocole web sécurisé."),
    "smb":      ("critique", "SMB (445) : Partage de fichiers Windows, cible fréquente des attaques."),
    "rdp":      ("critique", "RDP (3389) : Accès bureau à distance, cible fréquente des attaques."),
    "mysql":    ("moyen",    "MySQL (3306) : Base de données, attention à la configuration."),
    "postgresql": ("moyen",  "PostgreSQL (5432) : Base de données, attention à la configuration."),
    "vnc":      ("critique", "VNC (5900) : Accès bureau à distance, souvent non chiffré."),
    "domain":   ("faible",   "DNS (53) : Service de résolution de noms."),
    "ldap":     ("moyen",    "LDAP (389) : Annuaire réseau, attention à la configuration."),
    "snmp":     ("moyen",    "SNMP (161) : Supervision réseau, attention aux versions non sécurisées."),
}

# === FONCTIONS D'EXPORT ===

def exporter_rapport(ip, list_ports, non_standards, score, conseils):
    """Exporte le rapport en fichier texte"""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    nom_fichier = f"rapport_scan_{ip}_{timestamp}.txt"
    
    with open(nom_fichier, "w", encoding="utf-8") as f:
        f.write("=" * 60 + "\n")
        f.write("RAPPORT DE SCAN DE SÉCURITÉ RÉSEAU\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Date du scan : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Adresse IP scannée : {ip}\n\n")
        f.write("-" * 60 + "\n")
        f.write("PORTS OUVERTS DÉTECTÉS\n")
        f.write("-" * 60 + "\n")
        if list_ports:
            for port, service in list_ports:
                f.write(f"  {port} : {service}\n")
        else:
            f.write("  Aucun port ouvert détecté.\n")
        f.write("\n" + "-" * 60 + "\n")
        f.write("SERVICES SUR PORTS NON-STANDARDS\n")
        f.write("-" * 60 + "\n")
        if non_standards:
            for port, service in non_standards:
                f.write(f"    {service} sur {port} (inhabituel)\n")
        else:
            f.write("  Aucun service sur port non-standard.\n")
        f.write("\n" + "-" * 60 + "\n")
        f.write(f"SCORE DE SÉCURITÉ : {score}/100\n")
        f.write("-" * 60 + "\n")
        f.write("\n" + "-" * 60 + "\n")
        f.write("RECOMMANDATIONS\n")
        f.write("-" * 60 + "\n")
        if conseils:
            for c in conseils:
                f.write(f"  • {c}\n")
        else:
            f.write("  Aucune recommandation, votre réseau semble sécurisé !\n")
        f.write("\n" + "=" * 60 + "\n")
    print(f"\n Rapport texte sauvegardé : {nom_fichier}")

def exporter_rapport_md(ip, list_ports, non_standards, score, conseils):
    """Exporte le rapport en fichier Markdown"""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    nom_fichier = f"rapport_scan_{ip}_{timestamp}.md"
    
    with open(nom_fichier, "w", encoding="utf-8") as f:
        f.write("# Rapport de Scan de Sécurité Réseau\n\n")
        f.write(f"**Date du scan:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"**Adresse IP scannée:** `{ip}`\n\n")
        f.write("##  Ports Ouverts Détectés\n\n")
        if list_ports:
            f.write("| Port | Service | Risque |\n")
            f.write("|------|---------|--------|\n")
            for port, service in list_ports:
                risque, _ = risques_services.get(service, ("inconnu", ""))
                f.write(f"| {port} | {service} | {risque} |\n")
        else:
            f.write(" Aucun port ouvert détecté.\n\n")
        f.write("\n##  Services sur Ports Non-Standards\n\n")
        if non_standards:
            for port, service in non_standards:
                f.write(f"- **{service}** sur **{port}** (inhabituel)\n")
        else:
            f.write(" Aucun service sur port non-standard.\n\n")
        f.write(f"\n##  Score de Sécurité\n\n")
        f.write(f"### **{score}/100**\n\n")
        if score >= 90:
            f.write(" **Excellent** : Votre réseau est très bien sécurisé !\n\n")
        elif score >= 80:
            f.write(" **Bien** : Votre sécurité est bonne, mais vous pouvez encore améliorer certains points.\n\n")
        elif score >= 70:
            f.write(" **Correct** : Attention à certains ports ouverts, vérifiez leur utilité.\n\n")
        elif score >= 60:
            f.write(" **Moyen** : Plusieurs ports ouverts présentent des risques.\n\n")
        elif score >= 50:
            f.write(" **Faible** : Votre réseau est exposé, sécurisez davantage.\n\n")
        elif score >= 40:
            f.write(" **Alerte** : Beaucoup de ports à risque ouverts !\n\n")
        elif score >= 30:
            f.write(" **Danger** : Votre réseau est très vulnérable !\n\n")
        elif score >= 20:
            f.write(" **Critique** : La plupart des ports ouverts sont dangereux !\n\n")
        else:
            f.write(" **Catastrophique** : Aucune sécurité, fermez tout immédiatement !\n\n")
        f.write("\n##  Recommandations\n\n")
        if conseils:
            for c in conseils:
                f.write(f"- {c}\n")
        else:
            f.write(" Aucune recommandation, votre réseau semble sécurisé !\n\n")
        f.write("\n---\n")
        f.write("*Généré par Scanner de Ports - Scanner de Sécurité Réseau*\n")
    print(f"\n Rapport Markdown sauvegardé : {nom_fichier}")

def fermer_port(port, protocole):
    """Ferme un port spécifique"""
    if os_name == "Windows":
        cmd = ["netsh", "advfirewall", "firewall", "add", "rule",
               f"name=Bloquer port {port}", "dir=in", "action=block",
               f"protocol={protocole}", f"localport={port}"]
    elif os_name == "Linux":
        cmd = ["sudo", "ufw", "deny", f"{port}/{protocole.lower()}"]
    elif os_name == "Darwin":
        print("Sur macOS, la gestion des ports se fait avec pfctl. (Non implémenté ici)")
        return
    else:
        print("OS non supporté.")
        return
    subprocess.run(cmd)

def ouvrir_port(port, protocole):
    """Ouvre un port spécifique"""
    if os_name == "Windows":
        cmd = ["netsh", "advfirewall", "firewall", "add", "rule",
               f"name=Ouvrir port {port}", "dir=in", "action=allow",
               f"protocol={protocole}", f"localport={port}"]
    elif os_name == "Linux":
        cmd = ["sudo", "ufw", "allow", f"{port}/{protocole.lower()}"]
    elif os_name == "Darwin":
        print("Sur Mac, la gestion des ports se fait avec pfctl. (Non implémenté ici)")
        return
    else:
        print("OS non supporté.")
        return
    subprocess.run(cmd)

# === PROGRAMME PRINCIPAL ===

# Afficher l'en-tête ASCII art
def afficher_banner():
    banner = """
    ╔════════════════════════════════════════════════════════════╗
    ║                  SCANNER DE PORTS                          ║
    ║            Outil de Sécurité Réseau Professionnel          ║
    ╚════════════════════════════════════════════════════════════╝
    """
    print(banner)

afficher_banner()

# Demander l'IP et scanner
ip = input("\nAdresse IP a scanner : ")
os_name = platform.system()
print(f"Systeme detecte : {os_name}")
print("Scan en cours...\n")

result = subprocess.run(["nmap", ip], capture_output=True, text=True)

# Extraire et afficher les ports ouverts
list_ports = extraire_ports_ouverts(result.stdout)
print(f"\n========== PORTS OUVERTS DETECTES ==========")
if list_ports:
    for port, service in list_ports:
        print(f"[OUVERT] {port:15} {service:25}")
else:
    print(f"[OK] Aucun port ouvert detecte !")
print(f"==========================================")

# Detecter et afficher les services sur ports non-standards
non_standards = detecter_services_non_standards(list_ports)
if non_standards:
    print("\n[!] SERVICES SUR PORTS NON-STANDARDS :")
    for port, service in non_standards:
        print(f"    [ALERTE] {service} detecte sur {port} (inhabituel !)")
    print("    Verifiez si ces services sont legitimes !\n")


# Calculer le score de sécurité
score = 100
conseils = []

for port, service in list_ports:
    risque, explication = risques_services.get(service, ("inconnu", "Risque non défini."))
    score -= 10
    if risque == "critique":
        conseils.append(f"Fermez le port {port} ({service}) si possible : {explication}")
    elif risque == "moyen":
        conseils.append(f"Vérifiez si le port {port} ({service}) est nécessaire : {explication}")
    elif risque == "faible":
        conseils.append(f"Le port {port} ({service}) est généralement sûr, mais vérifiez s'il est utile.")
    else:
        conseils.append(f"Port {port} ({service}) : risque inconnu, renseignez-vous sur ce service.")

if score < 0:
    score = 0

print(f"\n========== SCORE DE SECURITE ==========")
status = "[CRITIQUE]" if score < 30 else "[ALERTE]" if score < 60 else "[BON]" if score < 80 else "[EXCELLENT]"
print(f"{status} {score}/100")
print(f"==========================================")

if score >= 90:
    print("\n[EXCELLENT] Votre reseau est tres bien securise !")
elif score >= 80:
    print("\n[BON] Votre securite est bonne, mais vous pouvez ameliorer.")
elif score >= 70:
    print("\n[CORRECT] Attention a certains ports, verifiez leur utilite.")
elif score >= 60:
    print("\n[MOYEN] Plusieurs ports a risque, pensez a les fermer.")
elif score >= 50:
    print("\n[FAIBLE] Votre reseau est expose, securisez davantage.")
elif score >= 40:
    print("\n[ALERTE] Beaucoup de ports a risque, securite insuffisante !")
elif score >= 30:
    print("\n[DANGER] Votre reseau est tres vulnerable, agissez !")
elif score >= 20:
    print("\n[CRITIQUE] Presque tous les ports dangereux, fermez-les !")
elif score >= 10:
    print("\n[EXTREME] Quasiment ouvert, risque majeur !")
else:
    print("\n[CATASTROPHIQUE] AUCUNE SECURITE, FERMEZ TOUT !")

if conseils:
    print("\n===== RECOMMANDATIONS PERSONNALISEES =====")
    for i, c in enumerate(conseils, 1):
        print(f"{i}. {c}")
    print("==========================================")
else:
    print("\n[OK] Bravo, aucun port a risque detecte !")

# === Menu d'export du rapport ===
print("\n" + "=" * 60)
choix_rapport = input("Voulez-vous exporter le rapport ? (oui/non) : ").lower()
if choix_rapport == "oui" or choix_rapport == "o":
    print("\n===== FORMAT D'EXPORT =====")
    print("[ 1 > Fichier texte (.txt) ]")
    print("[ 2 > Fichier Markdown (.md) ]")
    print("[ 0 > Annuler ]")
    print("==========================")
    format_choix = input("\nVotre choix (0/1/2) : ")
    if format_choix == "1":
        exporter_rapport(ip, list_ports, non_standards, score, conseils)
    elif format_choix == "2":
        exporter_rapport_md(ip, list_ports, non_standards, score, conseils)
    elif format_choix == "0":
        print("[OK] Export annule.")
    else:
        print("[ERREUR] Choix invalide.")
else:
    print("\n[OK] Rapport non exporte.")

# === Menu gestion ports ===
print("\n" + "=" * 60)
gerer_ports = input("\nVoulez-vous gerer les ports ? (oui/non) : ").lower()
if gerer_ports == "oui" or gerer_ports == "o":
    while True:
        print("\n===== GESTION DES PORTS =====")
        print("[ 1 > Fermer un port ]")
        print("[ 2 > Ouvrir un port ]")
        print("[ 0 > Quitter ]")
        print("============================")
        choix = input("\nTon choix (0/1/2) : ")
        if choix == "1":
            port = input("\nNumero du port a fermer : ")
            protocole = input("Protocole (tcp/udp) : ").upper()
            print("[EN COURS] Fermeture en cours...")
            fermer_port(port, protocole)
        elif choix == "2":
            port = input("\nNumero du port a ouvrir : ")
            protocole = input("Protocole (tcp/udp) : ").upper()
            print("[EN COURS] Ouverture en cours...")
            ouvrir_port(port, protocole)
        elif choix == "0":
            print("\n[OK] Gestion des ports terminee.")
            break
        else:
            print("\n[ERREUR] Choix invalide. Reessaye.")
else:
    print("\n[OK] Gestion des ports non utilisee.")

print("\n" + "=" * 60)
print("[OK] Scanner termine. Au revoir !")

