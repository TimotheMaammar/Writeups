# pixy (Crackmes.one)

## Writeup

Le programme renvoie simplement un "umm....try again" à l'ouverture quelques soient les arguments.

Pas mal d'embranchements conditionnels et quelques strings qui font penser à du traitement de fichier, plus particulièrement du traitement d'image : 

```
.rdata:00007FF628D06938	00000013	C	unknown image type
...
.rdata:00007FF628D06DA8	0000000C	C	unknown BMP
...
.rdata:00007FF628D06960	0000000C	C	can't fopen
...
```

On observe aussi le canary habituel de Microsoft : 

```
mov rax, cs:__security_cookie
xor rax, rsp
mov [rbp+250h+var_50], rax
```

En regardant le code plus précisément on trouve quelques conditions explicites : 

1) Trois caractères + extension JPEG :

```
.text:00007FF628D01DF5                 lea     rcx, FileName   ; "???.jpeg"
```

2) Dans le dossier courant (à cause de FindFirstFileA()) :

```
.text:00007FF628D01DFC                 call    cs:FindFirstFileA
```


En essayant de relancer avec une image "abc.jpeg" dans le dossier courant on a toujours la même erreur "umm....try again" mais dans le debugging avec IDA on voit que le programme prend l'autre embranchement (breakpoint dans le bloc initial puis spamming de F8). 

Juste avant le "umm....try again" de l'embranchement de gauche (il y en a trois atteignables différemment) il y a un bloc de comparaison intéressant : 

```
.text:00007FF78CA3228C call    memcmp
.text:00007FF78CA32291 test    eax, eax
.text:00007FF78CA32293 jnz     short loc_7FF78CA3229E
```

La fonction memcmp() permet de comparer le contenu de deux blocs de mémoire spécifiés par les deux premiers paramètres de la fonction, souvent des registres. En pausant l'exécution à cet endroit on voit que RDX contient une adresse qui pointe vers mon "abc" (survoler le registre dans l'interface graphique donne le contenu en clair) : 

	Stack[00000198]:0000008C79D0F900

RCX juste au-dessus contient quant à lui une adresse qui pointe vers trois caractères '~' : 

	Stack[00000198]:0000008C79D0F900

En testant simplement de mettre un fichier `~~~.jpeg` dans le répertoire de l'exécutable on a bien le message de succès au démarrage.


