# Are you the number one ? (NewbieContest)

## Writeup

Programme en CLI qui demande un nombre entre 0 et 70 000 000.

Dans IDA on a l'embranchement conditionnel avec une comparaison avant : 

```
cmp     ds:_cacacafe, 163B37h
jnz     short loc_40151D
```

Simple conversion vers le format décimal ensuite : 
- 163B37h => 1456951
