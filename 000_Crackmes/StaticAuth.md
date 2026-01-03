# StaticAuth (Crackmes.one)

## Writeup

Simple programme CLI qui demande un code d'authentification.

Après le getch() responsable de la saisie au clavier, on voit une fonction sub_1400015B0 qui est appelée : 

	call    sub_1400015B0

Cette fonction semble responsable de la génération du mot de passe juste avant la comparaison qui va décider de l'embranchement à suivre.

Elle appelle une autre fonction sub_1400012A0 qui, quand on la décompose en pseudo-code, semble initialiser une chaîne "goo" avant de faire d'autres opérations : 

```
[...]
qmemcpy(Src, "goo", 3);
[...]
```

Dans le corps de sub_1400015B0 elle-même on voit ensuite une concaténation de "djob" : 

```
[...]
strcpy((char *)Block, "djob");
[...]
```
Ce qui donne "goodjob", mais cette chaîne ne fonctionne pas comme code. 

En continuant un peu dans le code, on observe une troisième fonction appelée sub_140001490 et qui semble ajouter du texte aussi : 

```
[...]
  *(_DWORD *)&Str[4] = HIDWORD(a1);
  *(_OWORD *)a1 = 0LL;
  strcpy(Str, "123");
[...]
```

Et "goodjob123" fonctionne comme code d'authentification.
