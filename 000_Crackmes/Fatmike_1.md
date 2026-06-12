# Fatmike's Crackme #1 (Crackmes.one)

## Writeup

### UPX

On voit directement que le binaire est packé par UPX dans IDA avec le segment "UPX1" ainsi qu'avec son entry point qui est le stub classique pour UPX en x86 : 

```
pusha                              ; Sauvegarde tous les registres
mov  esi, offset loc_433000        ; ESI = source (données compressées)
lea  edi, [esi-32000h]             ; EDI = destination (où le code décompressé va être écrit)
push edi                           ; sauvegarde la base de destination
or   ebp, 0FFFFFFFFh               ; EBP = -1 (init pour l'algo de décompression)
jmp  short loc_439F22              ; saute dans la boucle de décompression
```

Pour dépacker manuellement, il vaut mieux utiliser x64dbg parce qu'il intègre directement Scylla (outil de reconstruction pour les imports et les headers) et que ce serait plus laborieux avec IDA pour reconstruire le dump proprement.

Procédure pour dépacker manuellement et trouver l'OEP sur x64dbg : 

- F9 une fois pour passer le breakpoint système et arriver sur le pushad (entry point)
- F8 une fois pour exécuter seulement le pushad
- Clic droit sur ESP (panneau registres) → Follow in Dump
- Dans la vue Dump, sélectionner les 4 premiers octets
- Clic droit → Breakpoint → Hardware, Access → Dword
- F9 → le breakpoint s'arrête juste après le popad
- F8 pour suivre le jmp → on arrive à l'OEP
- Vérifier que le code ressemble à un vrai début de programme
- Ouvrir Plugins → Scylla (ou Ctrl+I)
- Vérifier que le champ OEP est rempli avec l'adresse courante
- Cliquer IAT Autosearch
- Cliquer Get Imports → contrôler l'absence de lignes rouges
- Cliquer Dump → enregistrement en "dump.exe"
- Cliquer Fix Dump → sélectionner dump.exe → génération de "dump_SCY.exe"
- Ouvrir dump_SCY.exe dans IDA pour lire le vrai code

Équivalent avec l'outil upx : 

```
upx.exe -d .\Crackme#1.exe
```
### Phase finale

TO DO
