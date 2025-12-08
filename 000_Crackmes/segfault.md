# segfault (Crackmes.one)

## Writeup

Programme qui demande un nom (entre 8 et 12 caractères) puis un numéro de série.

En désassemblant et en générant le pseudocode avec IDA, on voit qu'après la demande du numéro seules quelques modifications assez simples sont effectuées, dont un atoi() : 

```
puts("serial number:");
  fflush(_bss_start);
  __isoc99_scanf("%lf", &v11);
  v10 = strlen(s);
  v7 = 0;
  for ( i = 0; i < v10; ++i )
  {
    if ( (i & 1) != 0 )
      v3 = toupper(s[i]);
    else
      v3 = tolower(s[i]);
    v4 = v7++;
    src[v4] = v3;
  }
  src[v7] = 0;
  strncpy(dest, src, 8uLL);
  dest[8] = 0;
  v5 = (double)atoi(dest);
  if ( v5 == v11 )
    puts("s/n OK!");
  else
    puts("s/n WRONG!");
  return 0;
```

On sait que la fonction atoi() est assez obsolète, et qu'elle s'arrête dès qu'autre chose qu'un chiffre est rencontré. N'importe quel nombre suivi de lettres peut donc passer comme nom puis comme numéro :

```
username:
1AAAAAAA
serial number:
1
s/n OK!
```

Voir le thread suivant : 
- https://stackoverflow.com/questions/46090706/atoi-ignores-a-letter-in-the-string-to-convert

