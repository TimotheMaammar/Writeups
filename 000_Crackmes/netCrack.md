# netCrack (Crackmes.one)

## Writeup

Programme Linux en CLI qui demande un mot de passe.

En le désassemblant on voit quelques fonctions liées aux sockets ainsi que quelques strings HTTP : 

```
.data:000000000040311A	0000002B	C	hat's not correct ;(\nGET / HTTP/1.0\r\nHost: 
.data:0000000000403145	00000021	C	\r\nUser-Agent: AssemblyClient\r\n\r\n
```

Il y a une string qui a le mot "Platon" après la fin de la phrase mais ce mot de passe ne marche pas : 

	.data:0000000000403167	0000005F	C	omething went wrong, maybe check your internet connection, or try to read the code again.Platon

Dans la fonction getRequest on remarque qu'en fait le programme n'attend pas le mot de passe mais une adresse IP qui va servir d'argument à la connexion observée avant : 

```
[...]
mov     word ptr ds:sockaddr.sa_data, ax
mov     rdi, offset __bss_start ; cp
call    _inet_addr
mov     dword ptr ds:(sockaddr.sa_data+2), eax
mov     rdi, ds:sock_fd ; fd
[...]
```

BSS = Section mémoire pour les données non initialisées (donc tapées au clavier par l'utilisateur par exemple).

inet_addr = Fonction qui convertit une chaîne ASCII en un entier 32 bits pour le socket.

En entrant une adresse IP dans le programme on voit qu'il n'y a pas d'erreur mais pas de message non plus.

On a également le port 3125 qui est passé en hexadécimal : 

	mov     edi, 0C35h      ; hostshort

En mettant un listener sur notre machine et en testant avec 127.0.0.1 en entrée on reçoit bien une requête : 

```
┌──(timothe㉿APPLEDORE)-[~]
└─$ nc -nvlp 3125
listening on [any] 3125 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 58076
GET / HTTP/1.0
Host: 127.0.0.1
User-Agent: AssemblyClient
```

En entrant quelque chose après cette requête on reçoit cette fois un "That's not correct ;(" dans la fenêtre du programme. Il faut donc bien entrer le mot de passe directement du côté de la requête web.

En faisant un printf() pour éviter les problèmes d'encodage on valide bien l'épreuve avec le "Platon" trouvé avant : 

	printf "Platon" | nc -nvlp 3125
