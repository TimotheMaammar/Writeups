# Notepad Launcher (Crackmes.one)

## Writeup 

Programme qui demande un nom ainsi qu'une clé et qui est censé lancer un Notepad d'après la consigne.

Dans les strings on voit les quelques chaînes intéressantes ainsi qu'un "ShellExecuteA" qui se trouve également facilement dans la vue graphique, juste après les lignes suivantes :

```
lea     r8, File        ; "C:\\Windows\\System32\\notepad.exe"
lea     rdx, Operation  ; "open"
xor     ecx, ecx        ; hwnd
```

Tout le bloc contenant ces lignes est précédé par un saut conditionnel : 

```
cmp     eax, 2D27B1A9h
jnz     loc_14000186A
```

Mais il y en a aussi plusieurs avant, et en faisant du "Step over" ligne par ligne on voit que plusieurs embranchements conditionnels sont pris.

Le saut qui semble faire la différence est le suivant : 

	.text:00007FF684CD17E2 jnz      loc_7FF684CD186A

En le passant en "jz" on a bien un Notepad qui s'exécute à la fin.

Il semble aussi possible de récupérer le nom demandé directement en inspectant EAX au bon moment mais pour l'obtention de la clé ça a l'air plus compliqué et très chiant.
