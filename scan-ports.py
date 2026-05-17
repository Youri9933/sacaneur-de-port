
import subprocess

ip = input("Adresse IP à scanner : ")
nmap_path = r"C:\Users\amson\Documents\nmap\nmap.exe"
# Scan rapide (1000 ports principaux)
result = subprocess.run([nmap_path, ip], capture_output=True, text=True)

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
    # vous pouvez en ajouter d'autres selon vos besoins
}

list_ports_ouverts = extraire_ports_ouverts(result.stdout)
print("Ports ouverts et services associés :")
for port, service in list_ports_ouverts:
    risque, explication = risques_services.get(service, ("inconnu", "Risque non défini."))
    print(f"{port} : {service} | Risque : {risque} | {explication}")

input("Appuie sur Entrée pour quitter...")