# Are you a good boy ?(NewbieContest)

## Writeup

Programme CLI qui renvoie une erreur liée à l'humeur au démarrage mais qui semble devoir renvoyer le mot de passe.

Dans les strings on voit l'autre cas de figure mais sans le code en clair :

	.text:00401300	00000026	C	\nJe suis de bonne... Voici le code : 

On trouve ce cas dans la vue graphique avec un embranchement conditionnel juste avant. En patchant simplement le saut au runtime on arrive à faire afficher le code :

```
.text:00401370 cmp     [ebp+var_10], 0
.text:00401374 jz      short loc_4013A0
```
