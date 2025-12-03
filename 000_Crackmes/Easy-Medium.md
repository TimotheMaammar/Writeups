# Easy - Medium (Crackmes.one)

## Writeup 

En désassemblant le programme avec IDA on voit qu'il répond négativement par défaut et saute vers le "Nice! ;)" seulement si EAX et dword_A3437C sont égaux : 

```
.text:00A3104E cmp     dword_A3437C, eax
.text:00A31054 jnz     short loc_A3105B
```

Quelques modifications sont faites sur le registre juste avant : 

```
[...]
.text:00A31033 mov     eax, ds:dword_A33188
[...]
.text:00A3103D sub     eax, ds:dword_A3318C
[...]
.text:00A31049 add     eax, 19F97Fh
```

En somme on voit que le registre prend la valeur de dword_A33188, puis se fait retirer la valeur de dword_A3318C, puis se fait ajouter 19F97Fh (soit 1702271 en base 10).

Le mot de passe semble donc être juste un nombre, et en faisant une recherche sur l'une des deux variables on tombe très vite sur les deux lignes qui les déclarent : 

```
.rdata:00A33188 dword_A33188    dd 0F15EAh              ; DATA XREF: _main+33↑r
.rdata:00A3318C dword_A3318C    dd 498F0h               ; DATA XREF: _main+3D↑r
```

En faisant les conversions puis le calcul (988650 - 301296 + 1702271) on obtient le mot de passe.

## Remédiation 

Meilleur mot de passe et algorithme de hachage.
