# DC-2

    echo "192.168.249.194 dc-2" >> /etc/hosts

    sudo nmap -A -p1-10000 192.168.249.194
    sudo masscan -p1-65535,U:1-65535 --rate=1000 192.168.249.194 --tun0
    sudo /home/timothe/.local/bin/autorecon 192.168.249.194
    wpscan --url http://dc-2 --enumerate

Scans classiques. Bien penser à l'option "--enumerate" pour le scan WordPress sous peine de louper pas mal d'éléments importants, comme par exemple des noms d'utilisateurs. Dans notre cas on trouve justement trois utilisateurs : "tom", "jerry" et "admin". 

J'ai fouillé un peu toutes les vulnérabilités qui correspondaient à la version 4.7.10 et qui ne nécessitaient pas d'authentification grâce au site https://wpscan.com/wordpresses mais il n'y avait rien d'exceptionnel. Les deux vulnérabilités qui m'ont tout de suite sauté aux yeux étaient les suivantes : 
- https://wpscan.com/vulnerability/2999613a-b8c8-4ec0-9164-5dfe63adf6e6
- https://wpscan.com/vulnerability/3413b879-785f-4c9f-aa8a-5a4a1d5e0ba2

Seule la seconde fonctionnait mais elle m'a simplement donné le post par défaut de WordPress et l'indice suivant :

> If you can’t exploit WordPress and take a shortcut, there is another way.

En revanche en allant sur l'onglet "Flag" depuis le menu j'ai trouvé un indice bien plus pertinent : 

> Your usual wordlists probably won’t work, so instead, maybe you just need to be cewl. 
> More passwords is always better, but sometimes you just can’t win them all. 
> Log in as one to see the next flag. 
> If you can’t find it, log in as another.

C'est évidemment une référence à l'outil CeWL qui sert à générer des wordlists, je l'ai donc utilisé sur tout le site pour tenter un bruteforcing avec les trois utilisateurs récupérés plus hauts. Je suis d'abord passé par WordPress mais on aurait directement pu sauter à la phase SSH, en tout cas au moins pour Tom.

    cewl http://dc-2/ -w  liste_DC-2.txt

Pour attaquer le formulaire WordPress, je suis passé par Burp. Il suffit d'intercepter une requête à destination de http://dc-2/wp-login.php et de la transmettre à l'Intruder. Il faut ensuite isoler le paramètre à bruteforcer, ici "pwd", et charger la liste obtenue plus haut avec CeWL. Voici ci-dessous les URL utilisées pour l'attaque : 

> log=tom&pwd=§bbb§&wp-submit=Log+In&redirect_to=http%3A%2F%2Fdc-2%2Fwp-admin%2F&testcookie=1
> log=jerry&pwd=§bbb§&wp-submit=Log+In&redirect_to=http%3A%2F%2Fdc-2%2Fwp-admin%2F&testcookie=1
> log=admin&pwd=§bbb§&wp-submit=Log+In&redirect_to=http%3A%2F%2Fdc-2%2Fwp-admin%2F&testcookie=1

Pour Tom et Jerry on voit un résultat dont la page web a une taille différente de toutes les autres, j'ai testé les mots de passe sur le formulaire de login et ils fonctionnent. Pas de résultats pour Admin en revanche.

Une fois entré sur le dashboard, j'ai tout de suite remarqué le formulaire d'upload mais je n'ai pas réussi à l'exploiter. J'ai ouvert un deuxième onglet en navigation privée pour pouvoir tester avec les deux utilisateurs en même temps mais je n'ai rien obtenu de cette partie WordPress. En revanche, en fouillant les pages, je suis retombé sur le deuxième indice mentionnant un autre point d'entrée. J'ai tout de suite pensé au SSH, qui était ouvert sur le port 7744 d'après les scans initiaux. J'ai lancé trois autres tentatives de bruteforcing, mais cette fois-ci sur le port 7744 : 

    hydra -vV -l tom -P ~/liste_DC-2.txt 192.168.249.194 -s 7744 ssh
    hydra -vV -l jerry -P ~/liste_DC-2.txt 192.168.249.194 -s 7744 ssh
    hydra -vV -l admin -P ~/liste_DC-2.txt 192.168.249.194 -s 7744 ssh

Cela fonctionne pour Tom mais pas pour les deux autres.

    ssh 192.168.249.194 -l tom -p 7744

On arrive sur un shell restreint et avec un $PATH spécial mais ces deux points ne sont pas durs à contourner :

    PATH=$PATH:/bin:/usr/bin
    BASH_CMDS[a]=/bin/sh ; a
    cat local.txt
    cat flag3.txt
    
Le fichier "flag3.txt" était le troisième indice et il contenait un jeu de mots qui m'a tout de suite fait comprendre qu'il fallait changer d'utilisateur. Attention à cet angle mort, ce n'est pas parce que Jerry n'a pas le droit au SSH que l'on ne doit pas prendre son compte et vérifier si il n'y a pas un vecteur d'élévation de privilèges dessus.
Et Jerry était bien la clé pour cette dernière étape, une fois arrivé sur le compte de Jerry on voit qu'il a le droit de lancer la commande "git" en tant que root.

Voir : https://gtfobins.github.io/gtfobins/git/#sudo

    su jerry - 
    sudo git -p help config
    !/bin/sh
    ls /root
    cat /root/proof.txt






