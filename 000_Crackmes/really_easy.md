# really easy (Crackmes.one)

## Writeup

Mot de passe trouvable directement dans le code après désassemblage.

Si on oublie cette première voie, on observe que le programme continue naturellement vers la bonne branche mais qu'un "jnz" fait sauter vers le "Wrong try again." en cas de mauvais mot de passe.

Un simple remplacement en "jz" permet de contourner la condition :

	.text:000000000000122B                 jnz      short loc_123E

Edit => Patch program => Assemble   
Edit => Patch program => Apply patches to input file
