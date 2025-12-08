# beginner friendly (Crackmes.one)

## Writeup

Programme qui demande simplement un mot de passe.

Petit bloc anti-debugging au début mais facile à contourner avec une inversion de saut : 

```
mov     rax, cs:__imp_IsDebuggerPresent
call    rax ; __imp_IsDebuggerPresent
mov     [rbp+10h+Debugger], eax
cmp     [rbp+10h+Debugger], 0
jz      short loc_14000151F
```

En regardant le pseudocode on voit directement les opérations faites sur le mot de passe et elles sont principalement à base de XOR, il est donc facile de retrouver le clair : 

```
    [...]
    strcpy(str, "bSAAE]@V");
    strcpy(str1, "X]BS");
    strcpy(sj76f, "eW^Q]_W");
    strcpy(sfdwe, "f@K PWFFW@");
    key = 50;
    access_granted = 1;
    v1 = strlen(str);
    xor_encrypt(str, 50, v1);
    [...]
```

- `X` (0x58) XOR 0x32 = 0x6A → j
- `]` (0x5D) XOR 0x32 = 0x6F → o
- `B` (0x42) XOR 0x32 = 0x70 → p
- `S` (0x53) XOR 0x32 = 0x61 → a

Le mot de passe "jopa" fonctionne bien :

```
Password: jopa
Welcome
```
