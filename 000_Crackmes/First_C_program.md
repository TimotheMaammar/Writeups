# First C program

## Writeup

Pas de strings utiles mais on peut suivre l'appel à scanf() pour retracer le chemin depuis l'entrée au clavier : 

	.text:004014E6                 call    scanf

Trois lignes intéressantes un peu après :

	.text:00401543 cmp     [esp+0DCh+var_14], 6
	...
	.text:00401572 mov     [esp+0DCh+Character], eax       ; Character
	...
	.text:00401582 cmp     [esp+0DCh+var_10], 20h

On serait donc encore dans un cas de comparaison octet par octet avec probablement un mot de passe à 6 caractères.

Passage dans WinDbg :

	lm 
	x msvcrt!scanf
	bp msvcrt!scanf

En relançant et en avançant progressivement en Step Over avec 'p' après le scanf() on peut trouver chaque caractère du mot de passe dans les comparaisons entre ECX et EAX :

	00401525 39c1                   cmp     ecx, eax

Ajout d'un breakpoint sur cette instruction pour aller plus vite :

	bp 0x00401525
	g
	.formats eax
	g
	.formats eax
	g
	.formats eax
	...

On répète jusqu'à ce que le programme sorte de la boucle, on voit que le mot de passe est "banana" et qu'il fonctionne bien dans l'application.
