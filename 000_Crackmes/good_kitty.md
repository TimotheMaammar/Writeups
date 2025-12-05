# good kitty (Crackmes.one)

## Writeup

Une inversion de saut basique permet d'arriver à la bonne branche : 

	.text:00000000000014F2                 jz      short loc_1562

Mais le message de réussite est générique et ne révèle pas le mot de passe.

	ltrace ./crack

Pas de "strcmp" dans le binaire et quasiment que des "read" et des "write" donc la comparaison semble être faite à la main.

Regarder les strings dans IDA et chercher les références croisées pour "bad kitty!".

On arrive à deux blocs "bad kitty!" et "good kitty!" avec un saut conditionnel avant, mais la comparaison semble juste être faite sur la longueur du mot de passe : 

```
loc_14D9:
movzx   edx, [rsp+0C8h+var_BD]
cmp     rax, 8
setz    al
and     eax, edx
mov     [rsp+0C8h+var_BD], al
movzx   eax, [rsp+0C8h+var_BD]
test    al, al
jz      short loc_1562
```

En remontant un peu on a un autre bloc qui ressemble un peu plus à de la comparaison octet par octet : 

```
loc_1522:
mov     edx, [rsp+0C8h+var_BC]
add     edx, 1
mov     [rsp+0C8h+var_BC], edx
mov     edx, [rsp+0C8h+var_BC]
movsxd  rdx, edx
cmp     rdx, rax
jge     short loc_14D9
```

On retrouve un bloc à peu près équivalent dans GDB : 

	gdb ./crack
	(gdb) disass main

Copie du bloc avec des commentaires ajoutés : 

```
0x1522 <+630>: mov  0xc(%rsp), %edx      ; Charge le compteur dans EDX
0x1526 <+634>: add  $0x1, %edx           ; Incrémente EDX
0x1529 <+637>: mov  %edx, 0xc(%rsp)      ; Stocke le nouveau compteur
0x152d <+641>: mov  0xc(%rsp), %edx      ; Recharge le compteur dans EDX
0x1531 <+645>: movslq %edx, %rdx         ; Étend EDX en 64 bits (RDX)
0x1534 <+648>: cmp  %rax, %rdx           ; Compare RDX avec RAX
0x1537 <+651>: jge  0x14d9 <main+557>    ; Si compteur >= 8 on sort
```

Quelques lignes dessous on voit la ligne qui fait le contrôle du caractère : 

	0x0000000000001555 <+681>:   cmp    %bl,0x60(%rsp,%rcx,1)

%bl = Registre d'un seul octet qui contient un caractère de mot de passe chargé avant par `movzbl 0x10(%rsp,%rdx,1),%ebx`

0x60(%rsp,%rcx,1) = Adresse mémoire de notre entrée (RSP + 0x60 + RCX)

Mise en place d'un breakpoint pour lire pendant l'exécution : 

```
(gdb) b *main+681
Breakpoint 1 at 0x1555
(gdb) r
Starting program: /mnt/c/Users/timothe/Downloads/Crackmes.one/68c44e20224c0ec5dcedbf4b/crack
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
enter the right password
AAAAAA

Breakpoint 1, 0x0000555555555555 in main ()
(gdb) x/s $rsp+0x10
0x7fffffffd8c0: "00sGo4M0passwordenter the right password"
```

On a bien le mot de passe de 8 caractères.
