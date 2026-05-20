import platform
import subprocess

ip = input("Adresse IP à scanner : ")
os_name = platform.system()
print("Système détecté :", os_name)


result = subprocess.run(["nmap", ip], capture_output=True, text=True)

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

risques_services = {
    "ftp":      ("critique", "FTP (21) : Protocole non chiffré, vulnérable aux interceptions."),
    "ssh":      ("faible",   "SSH (22) : Protocole sécurisé pour l’accès distant."),
    "telnet":   ("critique", "Telnet (23) : Protocole non chiffré, très risqué."),
    "smtp":     ("moyen",    "SMTP (25) : Envoi d’e-mails, peut être utilisé pour le spam."),
    "dns":      ("faible",   "DNS (53) : Service de résolution de noms."),
    "http":     ("moyen",    "HTTP (80) : Protocole web non chiffré."),
    "pop3":     ("critique", "POP3 (110) : Récupération d’e-mails non chiffrée."),
    "imap":     ("critique", "IMAP (143) : Récupération d’e-mails non chiffrée."),
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

list_ports = extraire_ports_ouverts(result.stdout)
print("Ports ouverts et services associés :")

score = 100
conseils = []

for port, service in list_ports:
    risque, explication = risques_services.get(service, ("inconnu", "Risque non défini."))
    print(f"{port} : {service} | Risque : {risque} | {explication}")
    score -= 10
    if risque == "critique":
        conseils.append(f" Fermez le port {port} ({service}) si possible : {explication}")
    elif risque == "moyen":
        conseils.append(f" Vérifiez si le port {port} ({service}) est nécessaire : {explication}")
    elif risque == "faible":
        conseils.append(f" Le port {port} ({service}) est généralement sûr, mais vérifiez s'il est utile.")
    else:
        conseils.append(f" Port {port} ({service}) : risque inconnu, renseignez-vous sur ce service.")

if score < 0:
    score = 0

print(f"\nScore de sécurité : {score}/100\n")


if score >= 90:
    print(" Excellent : Votre réseau est très bien sécurisé !")
elif score >= 80:
    print(" Bien : Votre sécurité est bonne, mais vous pouvez encore améliorer certains points.")
elif score >= 70:
    print(" Correct : Attention à certains ports ouverts, vérifiez leur utilité.")
elif score >= 60:
    print(" Moyen : Plusieurs ports ouverts présentent des risques, pensez à les fermer si possible.")
elif score >= 50:
    print(" Faible : Votre réseau est exposé, il est conseillé de sécuriser davantage.")
elif score >= 40:
    print(" Alerte : Beaucoup de ports à risque ouverts, votre sécurité est insuffisante !")
elif score >= 30:
    print(" Danger : Votre réseau est très vulnérable, agissez rapidement !")
elif score >= 20:
    print(" Critique : La plupart des ports ouverts sont dangereux, fermez-les au plus vite !")
elif score >= 10:
    print(" Extrême : Votre réseau est quasiment ouvert à tous, il y a un risque majeur !")
else:
    print(" Catastrophique : Aucune sécurité, tous vos ports sont ouverts ! Fermez tout immédiatement !")

if conseils:
    print("\nConseils personnalisés :")
    for c in conseils:
        print("-", c)
else:
    print("Bravo, aucun port à risque détecté !")

# ==== commandes pour fermer et ouvrir les ports ====

def fermer_port(port, protocole):
    if os_name == "Windows":
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name=Bloquer port {port}", "dir=in", "action=block",
            f"protocol={protocole}", f"localport={port}"
        ]
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
    if os_name == "Windows":
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name=Ouvrir port {port}", "dir=in", "action=allow",
            f"protocol={protocole}", f"localport={port}"
        ]
    elif os_name == "Linux":
        cmd = ["sudo", "ufw", "allow", f"{port}/{protocole.lower()}"]
    elif os_name == "Darwin":
        print("Sur Mac, la gestion des ports se fait avec pfctl. (Non implémenté ici)")
        return
    else:
        print("OS non supporté.")
        return
    subprocess.run(cmd)

# === Menu gestion ports ===
while True:
    print("\nQue veux-tu faire ?")
    print("1. Fermer un port")
    print("2. Ouvrir un port")
    print("3. Quitter")
    choix = input("Ton choix : ")
    if choix == "1":
        port = input("Numéro du port à fermer : ")
        protocole = input("Protocole (tcp/udp) : ").upper()
        fermer_port(port, protocole)
    elif choix == "2":
        port = input("Numéro du port à ouvrir : ")
        protocole = input("Protocole (tcp/udp) : ").upper()
        ouvrir_port(port, protocole)
    elif choix == "3":
        print("Au revoir !")
        break
    else:
        print("Choix invalide.")