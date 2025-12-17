# Visuel et basique (NewbieContest)

## Writeup

Petite interface graphique qui demande un mot de passe.

En fouillant les fonctions dans IDA on voit que sub_4020D8 semble être la principale. 

À l'intérieur on trouve directement la comparaison avec ce qui ressemble à un mot de passe en clair : 

```
push    offset aTheresa ; "theresa"
call    ds:__imp___vbaStrCmp
```

Ce mot de passe fonctionne.
